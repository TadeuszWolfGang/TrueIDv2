#!/usr/bin/env python3
"""Run every unchanged auth/RBAC libtest case against a fresh private native web.

Import is passive. This program checks root-owned build capture records; their
independent producer and runtime admission remain an external trust boundary.
No endpoint, credential, test-subset or TLS-bypass option is provided.
"""
from __future__ import annotations

import argparse
import ctypes
import errno
import fcntl
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import resource
import select
import signal
import socket
import sqlite3
import ssl
import stat
import subprocess
import sys
import tempfile
import time

SUITES = ('auth_integration', 'rbac_matrix')
HELPER = 'scripts/live_auth_fixture.py'
RUNNER = 'scripts/run-live-auth-acceptance.py'
ID_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*')
HASH_RE = re.compile(r'[0-9a-f]{64}')
PHASES = frozenset(('startup','inputs','discovery','fixture','bootstrap','case','witness','cleanup','report','complete'))
CATEGORIES = frozenset(('ok','invalid_argument','environment_rejected','identity_mismatch','input_invalid','build_evidence_invalid','runtime_unavailable','discovery_failed','inventory_failed','fixture_failed','bootstrap_failed','case_failed','witness_failed','timeout','interrupted','log_overflow','cleanup_failed','unknown_drain','report_failed','not_run','internal_error'))
IDENTITIES = ('source_sha256','helper_sha256','runner_sha256','build_manifest_sha256','web_sha256','auth_sha256','rbac_sha256','runtime_sha256','build_capture_sha256')
EXPORTS = ('FixtureError','prepare_case','bootstrap','test_environment','read_witnesses','public_summary','remove_case')
MAX_JSON = 1048576
MAX_LOG = 1048576
HARD_FILE_LIMIT = 64 * 1048576  # Applies to DB/WAL too; not the per-stream limit.
CANCELLED = False
TIMED_OUT = False


class Stop(Exception):
    def __init__(self, code):
        self.code = code if type(code) is str and code in CATEGORIES else 'internal_error'
        super().__init__(self.code)


def need(condition, code='input_invalid'):
    if not condition:
        raise Stop(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


def strict_json(raw, cap=MAX_JSON):
    need(type(raw) is bytes and 0 < len(raw) <= cap)
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result)
            result[key] = value
        return result
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                           parse_constant=lambda _v: (_ for _ in ()).throw(Stop('input_invalid')))
        def check(item, depth=0):
            need(depth <= 16)
            if type(item) is str:
                need(len(item) <= 65536 and '\0' not in item and not any(0xD800 <= ord(c) <= 0xDFFF for c in item))
            elif type(item) is dict:
                need(len(item) <= 4096)
                for key, child in item.items(): check(key, depth+1); check(child, depth+1)
            elif type(item) is list:
                need(len(item) <= 8192)
                for child in item: check(child, depth+1)
            elif type(item) in (int, float):
                need(math.isfinite(item) and abs(item) <= 2**63-1)
            else:
                need(item is None or type(item) is bool)
        check(value)
        return value
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        raise Stop('input_invalid') from None


def closed(value, keys):
    need(type(value) is dict and set(value) == set(keys))


def digest(value):
    need(type(value) is str and HASH_RE.fullmatch(value) is not None)
    return value


def number(value, low=0, high=1200):
    need(type(value) in (int,float) and math.isfinite(value) and low <= value <= high, 'invalid_argument')
    return float(value)


def safe_id(value):
    return type(value) is str and len(value) <= 256 and ID_RE.fullmatch(value) is not None


def no_dotenv(path):
    for current in (path, *path.parents):
        need(not os.path.lexists(current / '.env'), 'environment_rejected')


def ancestry(path, root_owned=False):
    need(path.is_absolute() and path == Path(os.path.abspath(path)))
    for parent in (*reversed(path.parents), path):
        info = parent.lstat()
        need(not stat.S_ISLNK(info.st_mode))
        if parent != path:
            need(stat.S_ISDIR(info.st_mode))
        if root_owned:
            need(info.st_uid == 0 and not info.st_mode & 0o022)


def read_file(path, cap, *, executable=False, runtime=False):
    """Read a stable no-follow root-owned snapshot, never execute a reopened helper."""
    path = Path(path)
    ancestry(path, True)
    need(stat.S_ISREG(path.lstat().st_mode))
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1 and
             0 <= before.st_size <= cap and not before.st_mode & 0o022)
        need(runtime or not before.st_mode & 0o222)
        need(not executable or before.st_mode & 0o111)
        chunks = bytearray()
        while len(chunks) <= cap:
            part = os.read(fd, min(65536, cap + 1 - len(chunks)))
            if not part: break
            chunks.extend(part)
        after = os.fstat(fd)
        fields = ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_mode','st_uid','st_gid','st_nlink')
        need(all(getattr(before,k) == getattr(after,k) for k in fields) and len(chunks) == before.st_size)
        need((path.lstat().st_dev,path.lstat().st_ino) == (before.st_dev,before.st_ino))
        return bytes(chunks)
    finally:
        os.close(fd)


def descriptor(value, cap, *, executable=False, runtime=False):
    closed(value, ('path','sha256','bytes'))
    digest(value['sha256'])
    need(type(value['bytes']) is int and 0 < value['bytes'] <= cap)
    raw = read_file(value['path'], cap, executable=executable, runtime=runtime)
    need(len(raw) == value['bytes'] and sha(raw) == value['sha256'], 'identity_mismatch')
    return raw


def elf(raw):
    need(len(raw) >= 64 and raw[:6] == b'\x7fELF\x02\x01' and raw[18:20] == b'\x3e\x00', 'runtime_unavailable')


def source_view(root, wanted):
    need(type(wanted) is dict and 0 < len(wanted) <= 4096)
    ancestry(root, True)
    actual = set()
    total = 0
    for parent, dirs, files in os.walk(root, followlinks=False):
        for name in dirs:
            p = Path(parent)/name; ancestry(p, True); need(p.is_dir())
        for name in files:
            rel = (Path(parent)/name).relative_to(root).as_posix()
            need(rel in wanted, 'identity_mismatch')
            actual.add(rel)
    need(actual == set(wanted), 'identity_mismatch')
    for rel, info in sorted(wanted.items()):
        pure = PurePosixPath(rel)
        need(type(rel) is str and not pure.is_absolute() and '..' not in pure.parts and str(pure) == rel)
        closed(info, ('sha256','bytes')); digest(info['sha256'])
        raw = read_file(root/rel, 16*1048576)
        need(type(info['bytes']) is int and len(raw) == info['bytes'] and sha(raw) == info['sha256'], 'identity_mismatch')
        total += len(raw); need(total <= 128*1048576)
    for rel in (HELPER,RUNNER,'Cargo.toml','Cargo.lock','tests/Cargo.toml','tests/auth_integration.rs','tests/rbac_matrix.rs','tests/support/mod.rs','apps/web/Cargo.toml'):
        need(rel in wanted)
    need(any(p.startswith('crates/common/migrations/') for p in wanted) and any(p.startswith('apps/web/assets/') for p in wanted))
    return sha(canonical(wanted))


def build_record(desc, role, manifest, source_sha):
    """Join root-owned capture metadata, the complete Cargo JSON stream and exports.

    UID0 producer provenance is a trust boundary, not a self-issued runtime GO.
    S4 must independently observe actual commands/exits and publish these bytes.
    """
    record = strict_json(descriptor(desc, MAX_JSON))
    closed(record, ('schemaVersion','kind','argv','source_root','target_dir','source_before_sha256','source_after_sha256','exit','timed_out','owned_drain','target_empty_at_start','cargo_json','exports'))
    need(type(record['schemaVersion']) is int and record['schemaVersion'] == 1 and record['kind'] == 'CARGO_BUILD_CAPTURE')
    need(record['source_before_sha256'] == record['source_after_sha256'] == source_sha)
    need(type(record['exit']) is int and record['exit'] == 0 and record['timed_out'] is False and record['owned_drain'] is True and record['target_empty_at_start'] is True, 'build_evidence_invalid')
    for key in ('source_root','target_dir'):
        need(type(record[key]) is str and Path(record[key]).is_absolute())
    cargo = manifest['runtime']['cargo']['path']
    tail = (['test','--release','--locked','--offline','--no-run','--tests','--message-format=json','-p','trueid-integration-tests','-p','trueid-web'] if role == 'tests' else
            ['build','--release','--locked','--offline','--message-format=json','-p','trueid-web','--bin','trueid-web'])
    need(record['argv'] == [cargo,*tail], 'build_evidence_invalid')
    raw = descriptor(record['cargo_json'], 16*1048576)
    need(raw.endswith(b'\n') and len(raw.splitlines()) <= 100000)
    messages = [strict_json(line, MAX_JSON) for line in raw.splitlines()]
    need(messages and all(type(x) is dict and type(x.get('reason')) is str for x in messages))
    finished = [x for x in messages if x['reason'] == 'build-finished']
    need(len(finished) == 1 and messages[-1] is finished[0] and finished[0].get('success') is True, 'build_evidence_invalid')
    wanted = SUITES if role == 'tests' else ('web',)
    closed(record['exports'], wanted)
    package_ids = set()
    for name in wanted:
        info = record['exports'][name]
        closed(info, ('package_id','cargo_executable','sha256','bytes'))
        need(type(info['package_id']) is str and 0<len(info['package_id'])<=512 and
             type(info['cargo_executable']) is str and 0<len(info['cargo_executable'])<=4096 and
             type(info['bytes']) is int and 0<info['bytes']<=256*1048576, 'build_evidence_invalid')
        digest(info['sha256'])
        target_name = 'trueid-web' if name == 'web' else name
        target_src = 'apps/web/src/main.rs' if name == 'web' else 'tests/'+name+'.rs'
        artifacts = [x for x in messages if x['reason'] == 'compiler-artifact' and
                     type(x.get('target')) is dict and x['target'].get('name') == target_name and
                     x['target'].get('kind') == (['bin'] if name == 'web' else ['test']) and
                     type(x.get('profile')) is dict and x['profile'].get('test') is (name != 'web') and
                     x['target'].get('src_path') == str(Path(record['source_root'])/target_src)]
        need(len(artifacts) == 1, 'build_evidence_invalid')
        item = artifacts[0]
        need(type(item.get('executable')) is str and item['executable'] == info['cargo_executable'] and
             type(item.get('package_id')) is str and item['package_id'] == info['package_id'])
        need(Path(item['executable']).is_relative_to(Path(record['target_dir'])) and
             '..' not in Path(item['executable']).parts)
        key = name
        need(info['sha256'] == manifest['binaries'][key]['sha256'] and info['bytes'] == manifest['binaries'][key]['bytes'])
        package_ids.add(info['package_id'])
    need(len(package_ids) == 1)
    if role == 'tests':
        features = [x.get('features') for x in messages if x['reason'] == 'compiler-artifact' and
                    type(x.get('target')) is dict and x['target'].get('name') == 'reqwest']
        need(features and any(type(x) is list and 'rustls' in x and 'cookies' in x for x in features), 'build_evidence_invalid')
    return record


def verify_inputs(args):
    need(sys.platform == 'linux' and sys.version_info[:2] == (3,11) and os.geteuid() != 0, 'runtime_unavailable')
    root = Path(args.source_root)
    no_dotenv(root)
    raw = read_file(Path(args.build_manifest), MAX_JSON)
    manifest = strict_json(raw)
    closed(manifest, ('schemaVersion','source_files','binaries','runtime','builds'))
    need(type(manifest['schemaVersion']) is int and manifest['schemaVersion'] == 1)
    source_sha = source_view(root, manifest['source_files'])
    closed(manifest['binaries'], ('web',*SUITES))
    cli = {'web':args.web_binary,'auth_integration':args.auth_binary,'rbac_matrix':args.rbac_binary}
    for name, desc in manifest['binaries'].items():
        need(desc.get('path') == cli[name], 'identity_mismatch')
        elf(descriptor(desc, 256*1048576, executable=True))
    closed(manifest['runtime'], ('python','openssl','ssl_extension','sqlite_extension','cargo','rustc'))
    import _ssl
    import _sqlite3
    actual = {'python':str(Path('/proc/self/exe').resolve(strict=True)),
              'ssl_extension':str(Path(_ssl.__file__).resolve(strict=True)),
              'sqlite_extension':str(Path(_sqlite3.__file__).resolve(strict=True))}
    for name, desc in manifest['runtime'].items():
        need(name not in actual or desc.get('path') == actual[name], 'identity_mismatch')
        descriptor(desc, 128*1048576, executable=name in ('python','openssl','cargo','rustc'), runtime=True)
    need(manifest['runtime']['openssl']['path'] == str(Path('/usr/bin/openssl').resolve(strict=True)))
    need(type(ssl.OPENSSL_VERSION) is str and sqlite3.sqlite_version_info >= (3,0,0))
    closed(manifest['builds'], ('tests','web'))
    tests = build_record(manifest['builds']['tests'], 'tests', manifest, source_sha)
    web = build_record(manifest['builds']['web'], 'web', manifest, source_sha)
    need(tests['target_dir'] != web['target_dir'], 'build_evidence_invalid')
    helper_source = read_file(root/HELPER, MAX_JSON)
    need(sha(read_file(Path(__file__), MAX_JSON)) == manifest['source_files'][RUNNER]['sha256'], 'identity_mismatch')
    identities = dict(zip(IDENTITIES, (source_sha,sha(helper_source),manifest['source_files'][RUNNER]['sha256'],sha(raw),
        manifest['binaries']['web']['sha256'],manifest['binaries']['auth_integration']['sha256'],manifest['binaries']['rbac_matrix']['sha256'],
        sha(canonical(manifest['runtime'])),sha(canonical(manifest['builds'])))))
    return manifest,identities,helper_source


def load_helper(raw, path):
    need(type(raw) is bytes)
    module = type(sys)('_trueid_live_auth_fixture')
    module.__file__ = str(path)
    # Future annotations/dataclasses must see the same registered module.
    sys.modules[module.__name__] = module
    try:
        exec(compile(raw, str(path), 'exec'), module.__dict__)
        need(tuple(module.__all__) == EXPORTS and all(hasattr(module,name) for name in EXPORTS))
        return module
    except BaseException:
        sys.modules.pop(module.__name__,None)
        raise


def cancelled(_signum, _frame):
    global CANCELLED
    CANCELLED = True


def alarm(_signum, _frame):
    global TIMED_OUT
    TIMED_OUT = True
    raise Stop('timeout')


def check_time(deadline, *, cleanup=False):
    if not cleanup:
        need(not CANCELLED, 'interrupted')
    need(time.monotonic() < deadline, 'timeout')


def arm_deadline(deadline):
    # SIGALRM interrupts ordinary blocking filesystem work as well as poll loops.
    check_time(deadline,cleanup=True)
    signal.setitimer(signal.ITIMER_REAL,max(0.000001,deadline-time.monotonic()))


class OwnedTree:
    """Single-thread scoped subreaper; immutable pidfds, never numeric signaling.

    Direct anchors stay unreaped until the other causal descendants have drained.
    No background subprocess may be launched outside this lease.
    """
    def __init__(self, logdir):
        need(len(os.listdir('/proc/self/task')) == 1 and signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL, 'unknown_drain')
        need(self.no_children(), 'unknown_drain')
        self.logdir = Path(logdir)
        self.refs = {}; self.anchors = {}; self.terminals = {}; self.pending = {}; self.completed = {}; self.sequence = 0
        self.uncertain = False; self.log_overflow = False; self.closed = False
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.libc.prctl.restype = ctypes.c_int
        current = ctypes.c_int(-1)
        need(self.libc.prctl(37,ctypes.byref(current),0,0,0) == 0 and current.value in (0,1), 'unknown_drain')
        self.previous = current.value
        need(self.libc.prctl(36,1,0,0,0) == 0, 'unknown_drain')
        try:
            need(self.libc.prctl(37,ctypes.byref(current),0,0,0) == 0 and current.value == 1, 'unknown_drain')
            self.self_ref = self.pin(os.getpid())
        except BaseException:
            need(self.libc.prctl(36,self.previous,0,0,0) == 0 and
                 self.libc.prctl(37,ctypes.byref(current),0,0,0) == 0 and current.value == self.previous, 'unknown_drain')
            raise

    @staticmethod
    def no_children():
        try: os.waitid(os.P_ALL,0,os.WEXITED|os.WNOHANG|os.WNOWAIT)
        except ChildProcessError: return True
        return False

    @staticmethod
    def row(dfd):
        fd = os.open('stat',os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=dfd)
        try: raw = os.read(fd,8193)
        finally: os.close(fd)
        need(len(raw) <= 8192 and b')' in raw,'unknown_drain')
        fields = raw[raw.rfind(b')')+2:].split()
        need(len(fields) >= 20,'unknown_drain')
        return int(raw[:raw.index(b' ')]),int(fields[1]),int(fields[19])

    def read(self, ref):
        try: row = self.row(ref['proc'])
        except OSError as exc:
            if exc.errno in (errno.ENOENT,errno.ESRCH): return None
            raise
        need((row[0],row[2]) == ref['identity'],'unknown_drain')
        return row

    def pin(self,pid,parent=None):
        before = self.read(parent) if parent is not None else None
        need(parent is None or before is not None,'unknown_drain')
        dfd = os.open('/proc/'+str(pid),os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW)
        pfd = None
        try:
            first = self.row(dfd); pfd = os.pidfd_open(pid,0); last = self.row(dfd)
            need(first[0] == last[0] == pid and first[2] == last[2],'unknown_drain')
            if parent is not None:
                after = self.read(parent)
                need(after is not None and first[1] == last[1] == before[0] == after[0],'unknown_drain')
            return {'identity':(pid,last[2]),'proc':dfd,'pidfd':pfd}
        except BaseException:
            if pfd is not None: os.close(pfd)
            os.close(dfd); raise

    @staticmethod
    def close_ref(ref):
        for key in ('proc','pidfd'):
            if ref[key] is not None: os.close(ref[key]); ref[key] = None

    @staticmethod
    def exited(ref):
        return bool(select.select([ref['pidfd']],[],[],0)[0])

    def discover(self):
        ids = sorted(int(p) for p in os.listdir('/proc') if p.isdecimal())
        need(len(ids) <= 8192,'unknown_drain')
        parents = {os.getpid():self.self_ref}
        for ref in self.refs.values():
            if self.read(ref) is not None: parents[ref['identity'][0]] = ref
        known = {r['identity'][0] for r in self.refs.values()}
        for pid in ids:
            if pid == os.getpid() or pid in known: continue
            dfd = None
            try:
                dfd = os.open('/proc/'+str(pid),os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW)
                row = self.row(dfd); parent = parents.get(row[1])
                if parent is None: continue
                ref = self.pin(pid,parent)
            except OSError as exc:
                if exc.errno in (errno.ENOENT,errno.ESRCH): continue
                raise
            finally:
                if dfd is not None: os.close(dfd)
            need(len(self.refs) < 256,'unknown_drain')
            self.refs[ref['identity']] = ref; parents[pid] = ref; known.add(pid)
            if pid in self.pending:
                pending=self.pending.pop(pid)
                self.anchors[ref['identity']]={'ref':ref,'process':pending['process'],'logs':pending['logs'],'code':None}

    def observe(self):
        for identity,ref in list(self.refs.items()):
            if not self.exited(ref): continue
            if identity in self.anchors:
                if identity not in self.terminals:
                    result = os.waitid(os.P_PIDFD,ref['pidfd'],os.WEXITED|os.WNOHANG|os.WNOWAIT)
                    if result is not None:
                        need(result.si_pid == identity[0] and result.si_code in (os.CLD_EXITED,os.CLD_KILLED,os.CLD_DUMPED),'unknown_drain')
                        self.terminals[identity] = result
            else:
                try:
                    result = os.waitid(os.P_PIDFD,ref['pidfd'],os.WEXITED|os.WNOHANG)
                    need(result is None or result.si_pid == identity[0],'unknown_drain')
                except ChildProcessError:
                    pass  # An owned parent reaped it or it is not adopted yet.
                self.close_ref(ref); del self.refs[identity]

    def logs(self):
        for entry in self.logdir.iterdir():
            match = re.fullmatch(r'[0-9]{3}-([0-9]+)-(out|err)',entry.name)
            need(match is not None,'unknown_drain')
            cap = int(match[1]); info = entry.lstat()
            need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600,'unknown_drain')
            if info.st_size > cap:
                self.log_overflow = True
        need(not self.log_overflow,'log_overflow')

    def tick(self):
        self.discover(); self.observe(); self.logs()

    def adopt_anchor(self,pid,process=None):
        ref = self.pin(pid,self.self_ref)
        need(len(self.refs) < 256,'unknown_drain')
        self.refs[ref['identity']] = ref
        self.anchors[ref['identity']] = {'ref':ref,'process':process,'logs':None,'code':None}
        return ref['identity']

    def spawn(self,argv,*,cwd,env,out_cap=MAX_LOG,err_cap=MAX_LOG):
        need(type(argv) is list and argv and all(type(x) is str for x in argv))
        need(type(out_cap) is type(err_cap) is int and 0 < out_cap <= MAX_LOG and 0 < err_cap <= MAX_LOG)
        no_dotenv(Path(cwd)); self.sequence += 1; need(self.sequence <= 128,'log_overflow')
        fds=[]; paths=[]
        for label,cap in (('out',out_cap),('err',err_cap)):
            path = self.logdir/f'{self.sequence:03d}-{cap}-{label}'
            fds.append(os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)); paths.append(path)
        mask = signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT,signal.SIGTERM,signal.SIGHUP,signal.SIGALRM})
        try:
            def before_exec():
                resource.setrlimit(resource.RLIMIT_CORE,(0,0))
                resource.setrlimit(resource.RLIMIT_FSIZE,(HARD_FILE_LIMIT,HARD_FILE_LIMIT))
                signal.pthread_sigmask(signal.SIG_SETMASK,set())
            process = subprocess.Popen(argv,cwd=cwd,env=env,stdin=subprocess.DEVNULL,
                stdout=fds[0],stderr=fds[1],close_fds=True,start_new_session=True,preexec_fn=before_exec)
            self.pending[process.pid]={'process':process,'logs':paths}
            identity = self.adopt_anchor(process.pid,process)
            self.anchors[identity]['logs'] = paths
            del self.pending[process.pid]
        finally:
            for fd in fds: os.close(fd)
            signal.pthread_sigmask(signal.SIG_SETMASK,mask)
        return identity

    def finish(self,identity):
        if identity not in self.terminals: return None
        if any(key not in self.anchors for key in self.refs): return None
        fd=os.open('/proc/self/task/'+str(os.getpid())+'/children',os.O_RDONLY|os.O_CLOEXEC)
        try: raw=os.read(fd,65537)
        finally: os.close(fd)
        need(len(raw)<=65536,'unknown_drain')
        if {int(x) for x in raw.split()} != {k[0] for k in self.anchors}: return None
        anchor=self.anchors[identity]; terminal=self.terminals[identity]
        expected=terminal.si_status if terminal.si_code==os.CLD_EXITED else -terminal.si_status
        if anchor['process'] is not None:
            actual=anchor['process'].wait(timeout=0)
        else:
            actual_status=os.waitid(os.P_PIDFD,anchor['ref']['pidfd'],os.WEXITED)
            need(actual_status.si_pid==identity[0],'unknown_drain')
            actual=actual_status.si_status if actual_status.si_code==os.CLD_EXITED else -actual_status.si_status
        need(actual==expected,'unknown_drain')
        anchor['code']=actual;self.completed[identity]=actual
        self.close_ref(anchor['ref']); del self.refs[identity]; del self.anchors[identity]; del self.terminals[identity]
        return actual

    def wait(self,identity,deadline,*,monitor=None,cleanup=False):
        while True:
            check_time(deadline,cleanup=cleanup)
            self.tick()
            if monitor is not None: monitor()
            code=self.finish(identity)
            if code is not None:return code
            time.sleep(0.01)

    def captured(self,identity,deadline):
        paths=self.anchors[identity]['logs']
        code=self.wait(identity,deadline)
        data=[]
        for path in paths:
            cap=int(path.name.split('-')[1]); need(path.stat().st_size<=cap,'log_overflow')
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
            try:raw=os.read(fd,cap+1)
            finally:os.close(fd)
            need(len(raw)<=cap,'log_overflow');data.append(raw)
        return code,*data

    def send(self,ref,signum):
        if not self.exited(ref):signal.pidfd_send_signal(ref['pidfd'],signum,None,0)

    def drain(self,deadline,web=None):
        """Every best-effort operation is isolated, including damaged known refs."""
        started=time.monotonic(); errors=False; sent=set()
        duration=max(0,deadline-started)
        grace=min(10,max(0,duration-6)) if web is not None else 0
        term_end=grace+min(2,max(0,duration-grace-2))
        while time.monotonic()<deadline:
            try:self.discover()
            except BaseException:errors=True
            try:self.observe()
            except BaseException:errors=True
            elapsed=time.monotonic()-started
            signum=signal.SIGINT if elapsed<grace else (signal.SIGTERM if elapsed<term_end else signal.SIGKILL)
            for identity,ref in list(self.refs.items()):
                try:
                    chosen=signum if identity==web or signum!=signal.SIGINT else signal.SIGTERM
                    if (identity,chosen) not in sent:
                        self.send(ref,chosen);sent.add((identity,chosen))
                except ProcessLookupError:pass
                except BaseException:errors=True
            for identity in list(self.anchors):
                try:self.finish(identity)
                except BaseException:errors=True
            try:self.logs()
            except Stop as exc:
                if exc.code!='log_overflow':errors=True
            except BaseException:errors=True
            if not self.refs and not self.anchors and not self.pending and self.no_children():
                self.uncertain |= errors
                return not errors
            time.sleep(0.01)
        self.uncertain=True
        return False

    def release(self):
        need(not self.refs and not self.anchors and not self.pending and self.no_children(),'unknown_drain')
        value=ctypes.c_int(-1)
        need(self.libc.prctl(36,self.previous,0,0,0)==0 and self.libc.prctl(37,ctypes.byref(value),0,0,0)==0 and value.value==self.previous,'unknown_drain')
        self.close_ref(self.self_ref); self.closed=True


def parse_inventory(raw, *, empty=False):
    need(type(raw) is bytes and len(raw)<MAX_LOG,'discovery_failed')
    try:text=raw.decode('utf-8')
    except UnicodeError:raise Stop('discovery_failed') from None
    need(not text or text.endswith('\n'),'discovery_failed')
    ids=[]; summary=None
    for line in text.splitlines():
        if not line:continue
        match=re.fullmatch(r'(.+): test',line)
        if match:
            need(summary is None and safe_id(match[1]) and match[1] not in ids,'discovery_failed')
            ids.append(match[1]); need(len(ids)<=256,'inventory_failed')
        else:
            match=re.fullmatch(r'([0-9]+) tests?, 0 benchmarks?',line)
            need(match is not None and summary is None,'discovery_failed')
            summary=int(match[1])
    need((ids or empty) and (summary is None or summary==len(ids)),'discovery_failed')
    return sorted(ids)


def parse_libtest(raw,selected,total):
    need(type(raw) is bytes and 0<len(raw)<MAX_LOG,'case_failed')
    try:text=raw.decode('utf-8')
    except UnicodeError:raise Stop('case_failed') from None
    need(text.endswith('\n'),'case_failed')
    lines=[line for line in text.splitlines() if line]
    need(len(lines)==3 and lines[0]=='running 1 test' and lines[1]=='test '+selected+' ... ok','case_failed')
    match=re.fullmatch(r'test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; ([0-9]+) filtered out; finished in ([0-9]+(?:\.[0-9]+)?)s',lines[2])
    need(match is not None and int(match[1])==total-1 and number(float(match[2]))>=0,'case_failed')
    return {'id':selected,'passed':1,'failed':0,'ignored':0,'measured':0,'filtered_out':int(match[1])}


def fixture_summary(helper,fixture):
    value=helper.public_summary(fixture)
    closed(value,('case_prepared','bootstrap_complete','verified_tls_ready','untrusted_ca_rejected','wrapper_sessions_revoked','leaf_sha256','ca_sha256','removed'))
    need(value['case_prepared'] is True and all(type(value[k]) is bool for k in ('bootstrap_complete','verified_tls_ready','untrusted_ca_rejected','wrapper_sessions_revoked','removed')),'fixture_failed')
    digest(value['leaf_sha256']);digest(value['ca_sha256'])
    need(value['leaf_sha256']!=value['ca_sha256'],'fixture_failed')
    return value


def blank_case(suite,tid):
    return {'suite':suite,'id':tid,'status':'NOT_RUN','phase':'case','category':'not_run',
        'presence':{'fixture':False,'libtest':False,'witness':False},'exit':None,'timed_out':False,'elapsed_s':0,
        'result':None,'auth':None,'fixture':None,'witness':None,'openssl_commands':0,'owned_drain':None,'private_data_removed':None}


def remove_private(path,identity,deadline):
    """Descriptor-relative removal of this fresh private tree only, after drain."""
    check_time(deadline,cleanup=True)
    info=path.lstat()
    need((info.st_dev,info.st_ino)==identity,'cleanup_failed')
    parent=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    root=os.open(path.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
    nodes=[0]
    def walk(fd,delete=False):
        for entry in os.scandir(fd):
            check_time(deadline,cleanup=True)
            nodes[0]+=1;need(nodes[0]<=10000,'cleanup_failed')
            st=entry.stat(follow_symlinks=False);directory=stat.S_ISDIR(st.st_mode)
            need(st.st_uid==os.geteuid() and st.st_gid==os.getegid() and stat.S_IMODE(st.st_mode)==(0o700 if directory else 0o600),'cleanup_failed')
            need(directory or (stat.S_ISREG(st.st_mode) and st.st_nlink==1),'cleanup_failed')
            if directory:
                child=os.open(entry.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
                try:
                    current=os.fstat(child);need((current.st_dev,current.st_ino)==(st.st_dev,st.st_ino),'cleanup_failed')
                    walk(child,delete)
                finally:os.close(child)
                current=os.stat(entry.name,dir_fd=fd,follow_symlinks=False)
                need((current.st_dev,current.st_ino)==(st.st_dev,st.st_ino),'cleanup_failed')
                if delete:
                    check_time(deadline,cleanup=True);os.rmdir(entry.name,dir_fd=fd)
            elif delete:
                check_time(deadline,cleanup=True);os.unlink(entry.name,dir_fd=fd)
    try:
        st=os.fstat(root);need((st.st_dev,st.st_ino)==identity,'cleanup_failed')
        walk(root);nodes[0]=0;walk(root,True)
        now=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
        need((now.st_dev,now.st_ino)==identity,'cleanup_failed')
        check_time(deadline,cleanup=True);os.rmdir(path.name,dir_fd=parent)
        check_time(deadline,cleanup=True)
    finally:os.close(root);os.close(parent)


def private_dir(path):
    path.mkdir(mode=0o700)
    info=path.lstat()
    need(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode)==0o700 and info.st_uid==os.geteuid() and info.st_gid==os.getegid(),'environment_rejected')
    no_dotenv(path)
    return info.st_dev,info.st_ino


def log_monitor(path):
    count=0
    for item in path.iterdir():
        count+=1;need(count<=256,'log_overflow')
        match=re.fullmatch(r'[0-9]{3}-([0-9]+)-(out|err)',item.name)
        need(match is not None,'unknown_drain')
        info=item.lstat();need(stat.S_ISREG(info.st_mode) and info.st_uid==os.geteuid() and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o600,'unknown_drain')
        need(info.st_size<=int(match[1]),'log_overflow')


def run_case(helper,manifest,args,suite,tid,total,work,started,deadline):
    """This complete synchronous fixture scope runs inside the owned case child."""
    global CANCELLED,TIMED_OUT
    CANCELLED=False;TIMED_OUT=False
    for signum in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP):signal.signal(signum,cancelled)
    signal.signal(signal.SIGALRM,alarm)
    row=blank_case(suite,tid);row.update(status='FAIL',phase='fixture',category='fixture_failed',owned_drain=False,private_data_removed=False)
    tree=fixture=web=None
    work_end=deadline-22  # 16s inner drain + 5s parent reserve + 1s projection.
    cleanup_end=deadline-6
    try:
        need(time.monotonic()<work_end,'timeout')
        tree=OwnedTree(work/'logs')
        signal.setitimer(signal.ITIMER_REAL,max(0.001,work_end-time.monotonic()))
        def run_owned(argv,*,cwd,env,deadline,output_limit):
            check_time(min(deadline,work_end))
            need(type(argv) is list and argv and argv[0]=='openssl','fixture_failed')
            # S1 has an explicit tiny environment; replace only executable identity.
            command=[manifest['runtime']['openssl']['path'],*argv[1:]]
            identity=tree.spawn(command,cwd=cwd,env=env,out_cap=output_limit,err_cap=65536)
            code,out,_err=tree.captured(identity,min(deadline,work_end))
            need(code==0,'fixture_failed')
            row['openssl_commands']+=1
            return out
        port_socket=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        try:
            port_socket.bind(('127.0.0.1',0));port=port_socket.getsockname()[1]
        finally:port_socket.close()
        # Release-bind race is not proof of reservation: bootstrap must verify
        # this fresh private CA. Another listener cannot satisfy that identity.
        fixture=helper.prepare_case(work/'case',Path(args.source_root),port,run_owned=run_owned,deadline=work_end)
        row['fixture']=fixture_summary(helper,fixture);row['presence']['fixture']=True
        web=tree.spawn([args.web_binary],cwd=str(fixture.case_root),env=fixture.server_env)
        row['phase']='bootstrap';row['category']='bootstrap_failed'
        helper.bootstrap(fixture,work_end)
        row['fixture']=fixture_summary(helper,fixture)
        need(all(row['fixture'][k] is True for k in ('bootstrap_complete','verified_tls_ready','untrusted_ca_rejected','wrapper_sessions_revoked')),'bootstrap_failed')
        row['auth']={key:True for key in ('verified_tls','untrusted_ca_rejected','initial_force_change','three_cookie_rotation','changed_password_new_login','both_sessions_revoked')}
        tree.tick();need(web not in tree.terminals,'bootstrap_failed')
        row['phase']='case';row['category']='case_failed'
        environment=helper.test_environment(fixture)
        need(set(environment)=={'PATH','HOME','TMPDIR','TRUEID_TEST_URL','TRUEID_TEST_ADMIN_PASS','SSL_CERT_FILE','SSL_CERT_DIR','TOKIO_WORKER_THREADS','RUST_LOG'},'environment_rejected')
        binary=args.auth_binary if suite=='auth_integration' else args.rbac_binary
        identity=tree.spawn([binary,'--include-ignored','--exact',tid,'--test-threads=1'],cwd=str(fixture.case_root),env=environment)
        row['exit'],out,_err=tree.captured(identity,work_end)
        need(row['exit']==0,'case_failed')
        row['result']=parse_libtest(out,tid,total);row['presence']['libtest']=True
        check_time(work_end);tree.tick();need(web not in tree.terminals,'case_failed')
        row['phase']='witness';row['category']='witness_failed'
        row['witness']=helper.read_witnesses(fixture,suite,tid,work_end)
        row['presence']['witness']=True
        row.update(status='PASS',phase='complete',category='ok')
    except BaseException as exc:
        row['status']='FAIL'
        if isinstance(exc,Stop):row['category']=exc.code
        elif isinstance(exc,helper.FixtureError):
            if exc.code=='invalid_deadline':row['category']='timeout'
            elif row['phase']=='witness':row['category']='witness_failed'
            elif row['phase']=='bootstrap':row['category']='bootstrap_failed'
            else:row['category']='fixture_failed'
        else:row['category']='internal_error'
        row['timed_out']=TIMED_OUT or row['category']=='timeout'
    finally:
        signal.setitimer(signal.ITIMER_REAL,0)
        if tree is not None:
            try:
                tree.tick()
                if web is not None and web in tree.terminals:
                    row.update(status='FAIL',phase='cleanup',category='case_failed')
            except BaseException as exc:
                row.update(status='FAIL',phase='cleanup',category=exc.code if isinstance(exc,Stop) else 'internal_error')
            try:
                row['owned_drain']=tree.drain(cleanup_end,web)
                if row['owned_drain']:tree.release()
                need(row['owned_drain'] and not tree.uncertain,'unknown_drain')
                if tree.log_overflow:row.update(status='FAIL',phase='cleanup',category='log_overflow')
                if web is not None and tree.completed.get(web)!=0:
                    row.update(status='FAIL',phase='cleanup',category='cleanup_failed')
            except BaseException:
                row.update(status='FAIL',phase='cleanup',category='unknown_drain',owned_drain=False)
        else:row['owned_drain']=OwnedTree.no_children()
        if fixture is not None:
            try:
                if row['owned_drain'] is True:
                    need(helper.remove_case(fixture,drain_confirmed=True) is True,'cleanup_failed')
                row['fixture']=fixture_summary(helper,fixture)
                row['presence']['fixture']=True
            except BaseException:
                row.update(status='FAIL',phase='cleanup',category='cleanup_failed')
        if CANCELLED:
            row.update(status='FAIL',phase='cleanup',category='interrupted')
        if TIMED_OUT:row['timed_out']=True
        if row['status']=='FAIL' and row['phase']=='complete':row['phase']='cleanup'
        if row['timed_out'] and row['category'] not in ('timeout','cleanup_failed','unknown_drain'):
            row.update(status='FAIL',phase='cleanup',category='timeout')
        row['elapsed_s']=round(time.monotonic()-started,6)
    return row


def supervised_case(tree,helper,manifest,args,suite,tid,total,work,deadline):
    """Parent owns the complete Python fixture scope, including blocking I/O."""
    started=time.monotonic();identity=None
    ipc=os.memfd_create('trueid-case-result',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
    try:
        oldmask=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT,signal.SIGTERM,signal.SIGHUP,signal.SIGALRM})
        try:
            pid=os.fork()
            if pid==0:
                try:
                    signal.setitimer(signal.ITIMER_REAL,0)
                    # A child must not retain the parent's proc/pidfd ownership lease.
                    for ref in list(tree.refs.values())+[tree.self_ref]:
                        for key in ('proc','pidfd'):
                            if ref[key] is not None:os.close(ref[key])
                    signal.pthread_sigmask(signal.SIG_SETMASK,set())
                    os.environ.clear()
                    os.environ.update({'PATH':'/usr/bin:/bin','HOME':str(work),'TMPDIR':str(work),'LC_ALL':'C','LANG':'C'})
                    value=run_case(helper,manifest,args,suite,tid,total,work,started,deadline)
                    payload=canonical(value);need(len(payload)<=MAX_JSON,'report_failed')
                    view=memoryview(payload)
                    while view:
                        written=os.write(ipc,view);need(written>0,'report_failed');view=view[written:]
                    os._exit(0 if value['status']=='PASS' else 2)
                except BaseException:
                    os._exit(2)
            identity=tree.adopt_anchor(pid)
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK,oldmask)
        problem=None;code=None;drained=False
        try:
            code=tree.wait(identity,deadline-5,monitor=lambda:log_monitor(work/'logs'))
            drained=True
        except BaseException as exc:
            problem=exc
            # Same whole-case deadline, genuine reserved TERM/KILL/reap time.
            drained=tree.drain(deadline-1)
            code=tree.completed.get(identity)
        try:
            fcntl.fcntl(ipc,fcntl.F_ADD_SEALS,fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL)
            info=os.fstat(ipc);need(0<info.st_size<=MAX_JSON,'report_failed')
            payload=os.pread(ipc,MAX_JSON+1,0);need(len(payload)==info.st_size,'report_failed')
            row=strict_json(payload)
            need(type(row) is dict and row.get('suite')==suite and row.get('id')==tid,'report_failed')
            need(code==(0 if row.get('status')=='PASS' else 2),'report_failed')
        except BaseException:
            row=blank_case(suite,tid);row.update(status='FAIL',phase='case',category='report_failed',owned_drain=False,private_data_removed=False)
        finally:pass
        if problem is not None:
            category=problem.code if isinstance(problem,Stop) else 'internal_error'
            row.update(status='FAIL',phase='case',category=category,timed_out=category=='timeout' or row['timed_out'])
        row['owned_drain']=drained and row['owned_drain'] is True
        if not drained:
            row.update(status='FAIL',phase='cleanup',category='unknown_drain')
        if CANCELLED:row.update(status='FAIL',phase='cleanup',category='interrupted')
        if row['timed_out'] and row['category'] not in ('timeout','cleanup_failed','unknown_drain'):
            row.update(status='FAIL',phase='cleanup',category='timeout')
        row['elapsed_s']=round(time.monotonic()-started,6)
        return row
    finally:
        os.close(ipc)


def empty_report():
    return {'schemaVersion':1,'status':'FAIL','phase':'startup','category':'input_invalid',
        'presence':{'identities':False,'discovery':False,'cases':False},'identities':None,'build_evidence':None,
        'discovery':None,'ignored_inventory':None,'selected':[],'per_case':[],
        'counts':{'discovered':0,'selected':0,'attempted':0,'passed':0,'failed':0,'not_run':0},
        'elapsed_s':0,'owned_drain':False,'private_data_removed':False}


def counts(report):
    rows=report['per_case']; passed=sum(x['status']=='PASS' for x in rows); failed=sum(x['status']=='FAIL' for x in rows)
    report['counts']={'discovered':len(report['selected']),'selected':len(report['selected']),
        'attempted':passed+failed,'passed':passed,'failed':failed,'not_run':len(rows)-passed-failed}
    report['presence']['cases']=bool(rows)


class ReportWriter:
    def __init__(self,path):
        self.path=Path(path);need(self.path.is_absolute(),'invalid_argument')
        self.parent=self.path.parent;ancestry(self.parent)
        info=self.parent.lstat();need(info.st_uid==os.geteuid() and info.st_gid==os.getegid() and stat.S_IMODE(info.st_mode)==0o700,'environment_rejected')
        need(not os.path.lexists(self.path),'report_failed')
        self.parent_identity=(info.st_dev,info.st_ino);self.previous=None
        self.previous_alarm_handler=signal.getsignal(signal.SIGALRM)
        self.committed=False

    def write(self,value,deadline):
        check_time(deadline,cleanup=True)
        payload=canonical(value)+b'\n';need(len(payload)<=MAX_JSON,'report_failed')
        check_time(deadline,cleanup=True)
        info=self.parent.lstat();need((info.st_dev,info.st_ino)==self.parent_identity,'report_failed')
        if self.previous is None:need(not os.path.lexists(self.path),'report_failed')
        else:
            st=self.path.lstat();need((st.st_dev,st.st_ino)==self.previous and stat.S_ISREG(st.st_mode) and st.st_nlink==1,'report_failed')
        fd,name=tempfile.mkstemp(prefix='.report-',dir=self.parent)
        try:
            os.fchmod(fd,0o600);view=memoryview(payload)
            while view:
                check_time(deadline,cleanup=True)
                n=os.write(fd,view);need(n>0,'report_failed');view=view[n:]
            check_time(deadline,cleanup=True);os.fsync(fd)
            check_time(deadline,cleanup=True);os.close(fd);fd=None
            check_time(deadline,cleanup=True)
            if self.previous is None:
                os.link(name,self.path,follow_symlinks=False);os.unlink(name)
            else:os.replace(name,self.path)
            st=self.path.lstat();self.previous=(st.st_dev,st.st_ino)
            dfd=os.open(self.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            try:
                check_time(deadline,cleanup=True);os.fsync(dfd)
                check_time(deadline,cleanup=True)
            finally:os.close(dfd)
        finally:
            if fd is not None:os.close(fd)
            if os.path.lexists(name):os.unlink(name)
        # All potentially blocking I/O, including fsync and descriptor closes,
        # remained alarm-supervised. Successful return itself owns the cutoff.
        previous_mask=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGALRM})
        try:
            check_time(deadline,cleanup=True)
            signal.setitimer(signal.ITIMER_REAL,0)
            # One owned one-shot timer has at most one coalesced pending signal.
            signal.sigtimedwait({signal.SIGALRM},0)
            signal.signal(signal.SIGALRM,self.previous_alarm_handler)
            self.committed=True
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK,previous_mask)


class Parser(argparse.ArgumentParser):
    def error(self,_message):raise Stop('invalid_argument')


def main(argv=None):
    global CANCELLED,TIMED_OUT
    started=time.monotonic();report=empty_report();writer=tree=work=manifest=identities=None
    oldhandlers={};oldtimer=None;oldumask=None;work_identity=None;args=None;expected=None;budgets_valid=False
    overall_end=None;final_exit=2
    CANCELLED=False;TIMED_OUT=False
    try:
        parser=Parser(description=__doc__,add_help=False)
        for name in ('source-root','web-binary','auth-binary','rbac-binary','build-manifest','report'):parser.add_argument('--'+name,required=True)
        parser.add_argument('--timeout',required=True,type=float)
        parser.add_argument('--case-timeout',type=float,default=45)
        args=parser.parse_args(argv)
        writer=ReportWriter(args.report)
        oldumask=os.umask(0o077)
        number(args.timeout,1,1200);number(args.case_timeout,30,45)
        need(args.case_timeout>30,'invalid_argument');budgets_valid=True
        overall_end=started+args.timeout;work_end=overall_end-10
        need(work_end>time.monotonic(),'timeout')
        need(signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0),'environment_rejected')
        for signum in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP,signal.SIGALRM):
            oldhandlers[signum]=signal.getsignal(signum)
            signal.signal(signum,alarm if signum==signal.SIGALRM else cancelled)
        oldtimer=signal.getitimer(signal.ITIMER_REAL);need(oldtimer==(0.0,0.0),'environment_rejected')
        signal.setitimer(signal.ITIMER_REAL,max(0.001,work_end-time.monotonic()))
        report['phase']='inputs'
        manifest,identities,helper_source=verify_inputs(args)
        report['identities']=identities;report['presence']['identities']=True
        report['build_evidence']={'root_owned_inputs':True,'cargo_records_validated':True,'producer_scope':'ROOT_OWNED_CAPTURE_NOT_CRYPTOGRAPHIC_ATTESTATION'}
        helper=load_helper(helper_source,Path(args.source_root)/HELPER)
        work=Path(tempfile.mkdtemp(prefix='trueid-auth-',dir=writer.parent));os.chmod(work,0o700)
        st=work.lstat();work_identity=(st.st_dev,st.st_ino);no_dotenv(work)
        private_dir(work/'logs');private_dir(work/'home');private_dir(work/'tmp')
        environment={'PATH':'/usr/bin:/bin','HOME':str(work/'home'),'TMPDIR':str(work/'tmp'),'LC_ALL':'C','LANG':'C'}
        tree=OwnedTree(work/'logs')
        # Actual CLI execution establishes OpenSSL capability; hashes alone do not.
        identity=tree.spawn([manifest['runtime']['openssl']['path'],'version'],cwd=str(work),env=environment,out_cap=8192,err_cap=8192)
        code,out,_err=tree.captured(identity,min(work_end,time.monotonic()+5))
        need(code==0 and out.startswith(b'OpenSSL '),'runtime_unavailable')
        report['phase']='discovery';inventory={};ignored={}
        for suite,binary in (('auth_integration',args.auth_binary),('rbac_matrix',args.rbac_binary)):
            identity=tree.spawn([binary,'--list','--format','terse'],cwd=str(work),env=environment)
            code,out,_err=tree.captured(identity,min(work_end,time.monotonic()+10));need(code==0,'discovery_failed')
            inventory[suite]=parse_inventory(out)
            identity=tree.spawn([binary,'--list','--ignored','--format','terse'],cwd=str(work),env=environment)
            code,out,_err=tree.captured(identity,min(work_end,time.monotonic()+10));need(code==0,'discovery_failed')
            ignored[suite]=parse_inventory(out,empty=True)
            need(set(ignored[suite])<=set(inventory[suite]),'inventory_failed')
        need(sum(len(v) for v in inventory.values())<=256,'inventory_failed')
        report['discovery']=inventory;report['ignored_inventory']=ignored;report['presence']['discovery']=True
        report['selected']=[{'suite':suite,'id':tid} for suite in SUITES for tid in inventory[suite]]
        report['per_case']=[blank_case(item['suite'],item['id']) for item in report['selected']];counts(report)
        need(time.monotonic()+len(report['selected'])*args.case_timeout<=work_end,'timeout')
        report['phase']='case'
        for index,item in enumerate(report['selected']):
            check_time(work_end)
            case_started=time.monotonic()
            case_end=min(work_end,case_started+args.case_timeout)
            arm_deadline(case_end)
            casework=work/f'case-{index:03d}';case_identity=private_dir(casework);private_dir(casework/'logs')
            row=supervised_case(tree,helper,manifest,args,item['suite'],item['id'],len(inventory[item['suite']]),casework,case_end)
            report['per_case'][index]=row
            if row['owned_drain'] is True and row['fixture'] is not None and row['fixture']['removed'] is True:
                try:
                    remove_private(casework,case_identity,case_end);row['private_data_removed']=True
                except BaseException as exc:
                    row.update(status='FAIL',phase='cleanup',category='timeout' if isinstance(exc,Stop) and exc.code=='timeout' else 'cleanup_failed',private_data_removed=False)
                    row['timed_out'] |= isinstance(exc,Stop) and exc.code=='timeout'
            else:row['private_data_removed']=False
            if row['status']=='PASS' and row['private_data_removed'] is not True:row.update(status='FAIL',phase='cleanup',category='cleanup_failed')
            row['elapsed_s']=round(time.monotonic()-case_started,6)
            if time.monotonic()>=case_end:
                row.update(status='FAIL',phase='cleanup',category='timeout',timed_out=True)
            counts(report)
            arm_deadline(work_end)
            if row['owned_drain'] is not True or CANCELLED:raise Stop('unknown_drain' if not CANCELLED else 'interrupted')
            # Ordinary case failure is sticky but does not skip other discovered IDs.
        report['phase']='inputs'
        source_view(Path(args.source_root),manifest['source_files'])
        verify_inputs(args)
        report['phase']='case'
        need(all(row['status']=='PASS' for row in report['per_case']),'case_failed')
        report.update(status='PASS',phase='complete',category='ok')
    except BaseException as exc:
        report['status']='FAIL';report['category']=exc.code if isinstance(exc,Stop) else 'internal_error'
        if report['phase']=='complete':report['phase']='cleanup'
    finally:
        try:
            cleanup_end=(overall_end-2) if overall_end is not None else started+1
            report_end=overall_end if overall_end is not None else started+1
            # Keep absolute supervision through filesystem cleanup and durable report.
            if oldtimer is not None:
                try:arm_deadline(cleanup_end)
                except Stop:
                    TIMED_OUT=True
                    report.update(status='FAIL',phase='cleanup',category='timeout')
            if tree is not None:
                try:
                    report['owned_drain']=tree.drain(cleanup_end)
                    if report['owned_drain']:tree.release()
                    need(report['owned_drain'] and not tree.uncertain,'unknown_drain')
                except BaseException:report.update(status='FAIL',phase='cleanup',category='unknown_drain',owned_drain=False)
            else:
                try:report['owned_drain']=OwnedTree.no_children()
                except BaseException:report['owned_drain']=False
            if work is not None and report['owned_drain'] and all(row['private_data_removed'] is True for row in report['per_case']):
                try:
                    remove_private(work,work_identity,cleanup_end);report['private_data_removed']=True
                except BaseException as exc:
                    category='timeout' if isinstance(exc,Stop) and exc.code=='timeout' else 'cleanup_failed'
                    report.update(status='FAIL',phase='cleanup',category=category)
            elif work is None:report['private_data_removed']=report['owned_drain']
            # Cancellation cutoff: restore runner cancellation handlers BEFORE the
            # final sticky-state projection. Later prior-handler signals are external
            # aborts, not a newly handled normal exit2 paired with a PASS report.
            for signum in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP):
                if signum in oldhandlers:
                    signal.signal(signum,oldhandlers.pop(signum))
            if CANCELLED:report.update(status='FAIL',phase='cleanup',category='interrupted')
            if TIMED_OUT and report['status']=='PASS':report.update(status='FAIL',phase='cleanup',category='timeout')
            counts(report);report['elapsed_s']=round(time.monotonic()-started,6)
            if budgets_valid and report['elapsed_s']>args.timeout:
                report.update(status='FAIL',phase='cleanup',category='timeout')
            expected={'identities':identities,'inventory':report['discovery'],
                'ignored_inventory':report['ignored_inventory'],
                'timeout':args.timeout if budgets_valid else 1200,
                'case_timeout':args.case_timeout if budgets_valid else 45}
            try:
                need(report['status']!='PASS' or (report['owned_drain'] and report['private_data_removed']),'cleanup_failed')
                if writer is not None:
                    if oldtimer is None:
                        need(signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0),'environment_rejected')
                        oldhandlers[signal.SIGALRM]=signal.getsignal(signal.SIGALRM)
                        signal.signal(signal.SIGALRM,alarm);oldtimer=(0.0,0.0)
                    arm_deadline(report_end)
                    verdict=validate_report(canonical(report),expected=expected,actual_exit=0 if report['status']=='PASS' else 2)
                    need(verdict['valid'],'report_failed')
                    writer.write(report,report_end)
                    # write returns only after the owned alarm cutoff; no later
                    # owned ALRM can turn this committed status into normal exit2.
                    final_exit=0 if report['status']=='PASS' else 2
            except BaseException as exc:
                category='timeout' if isinstance(exc,Stop) and exc.code=='timeout' else ('interrupted' if isinstance(exc,KeyboardInterrupt) else 'report_failed')
                report.update(status='FAIL',phase='report',category=category)
                report['elapsed_s']=round(time.monotonic()-started,6)
                final_exit=2
                if writer is not None and oldtimer is not None and not writer.committed:
                    try:
                        arm_deadline(report_end)
                        verdict=validate_report(canonical(report),expected=expected,actual_exit=2)
                        need(verdict['valid'],'report_failed')
                        writer.write(report,report_end)
                    except BaseException:
                        pass  # UNSAFE_ABORT/incomplete: actual exit rejects any stale artifact.
        except BaseException as exc:
            final_exit=2
            category='timeout' if isinstance(exc,Stop) and exc.code=='timeout' else ('interrupted' if isinstance(exc,KeyboardInterrupt) else 'cleanup_failed')
            report.update(status='FAIL',phase='cleanup',category=category)
            report['elapsed_s']=round(time.monotonic()-started,6);counts(report)
            expected={'identities':identities,'inventory':report['discovery'],
                'ignored_inventory':report['ignored_inventory'],
                'timeout':args.timeout if budgets_valid else 1200,
                'case_timeout':args.case_timeout if budgets_valid else 45}
            if writer is not None and oldtimer is not None and not writer.committed:
                try:
                    # The two-second report reserve remains independently armed.
                    arm_deadline(report_end)
                    verdict=validate_report(canonical(report),expected=expected,actual_exit=2)
                    need(verdict['valid'],'report_failed')
                    writer.write(report,report_end)
                except BaseException:
                    pass
        finally:
            if oldtimer is not None:signal.setitimer(signal.ITIMER_REAL,0)
            for signum,handler in oldhandlers.items():signal.signal(signum,handler)
            if oldtimer is not None:signal.setitimer(signal.ITIMER_REAL,*oldtimer)
            if oldumask is not None:os.umask(oldumask)
    if writer is not None and not writer.committed:
        return 2  # UNSAFE_ABORT: no complete committed-report claim.
    return final_exit


"""Pure closed S2 report policy. Source fragment; no runtime qualification claimed."""
import json
import math
import re

pv_RAW_CAP = 1048576
pv_TERMINAL_ELAPSED_CAP = 86400  # Representation only; never an execution budget.
pv_DEPTH_CAP = 16
pv_NODE_CAP = 200000
pv_ARRAY_CAP = 512
pv_ID_CAP = 256
pv_SUITES = ("auth_integration", "rbac_matrix")
pv_ID_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(::[A-Za-z_][A-Za-z0-9_]*)*")
pv_SHA_RE = re.compile(r"[0-9a-f]{64}")
pv_PHASES = frozenset(("startup", "inputs", "discovery", "fixture", "bootstrap",
    "case", "witness", "cleanup", "report", "complete"))
pv_CATEGORIES = frozenset(("ok", "invalid_argument", "environment_rejected",
    "identity_mismatch", "input_invalid", "build_evidence_invalid", "runtime_unavailable",
    "discovery_failed", "inventory_failed", "fixture_failed", "bootstrap_failed",
    "case_failed", "witness_failed", "timeout", "interrupted", "log_overflow",
    "cleanup_failed", "unknown_drain", "report_failed", "not_run", "internal_error"))
pv_TOP = frozenset(("schemaVersion", "status", "phase", "category", "presence",
    "identities", "build_evidence", "discovery", "ignored_inventory", "selected",
    "per_case", "counts", "elapsed_s", "owned_drain", "private_data_removed"))
pv_EXPECTED = frozenset(("identities", "inventory", "ignored_inventory", "timeout", "case_timeout"))
pv_IDENTITIES = frozenset(("source_sha256", "helper_sha256", "runner_sha256",
    "build_manifest_sha256", "web_sha256", "auth_sha256", "rbac_sha256",
    "runtime_sha256", "build_capture_sha256"))
pv_ROW = frozenset(("suite", "id", "status", "phase", "category", "presence", "exit",
    "timed_out", "elapsed_s", "result", "auth", "fixture", "witness", "openssl_commands",
    "owned_drain", "private_data_removed"))
pv_FIXTURE = frozenset(("case_prepared", "bootstrap_complete", "verified_tls_ready",
    "untrusted_ca_rejected", "wrapper_sessions_revoked", "leaf_sha256", "ca_sha256", "removed"))
pv_FIXTURE_FLAGS = pv_FIXTURE - {"leaf_sha256", "ca_sha256"}
pv_AUTH = frozenset(("verified_tls", "untrusted_ca_rejected", "initial_force_change",
    "three_cookie_rotation", "changed_password_new_login", "both_sessions_revoked"))
pv_COUNTS = frozenset(("discovered", "selected", "attempted", "passed", "failed", "not_run"))
pv_REASONS = frozenset(("ok", "raw", "json", "bounds", "expected", "exit", "schema",
    "phase", "category", "presence", "identities", "build_evidence", "inventory",
    "selection", "counts", "elapsed", "cleanup", "case", "result", "auth", "fixture",
    "witness", "not_run", "pass", "fail", "invalid"))


class pv_Error(ValueError):
    def __init__(self, reason):
        self.reason = reason if type(reason) is str and reason in pv_REASONS else "invalid"


def pv_need(condition, reason):
    if not condition:
        raise pv_Error(reason)


def pv_keys(value, keys, reason):
    pv_need(type(value) is dict and all(type(k) is str for k in value) and set(value) == set(keys), reason)


def pv_int(value, low, high):
    return type(value) is int and low <= value <= high


def pv_number(value, low, high):
    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(value) and low <= value <= high
    except (OverflowError, ValueError):
        return False


def pv_walk(value, depth=0, counter=None):
    if counter is None:
        counter = [0]
    counter[0] += 1
    pv_need(depth <= pv_DEPTH_CAP and counter[0] <= pv_NODE_CAP, "bounds")
    kind = type(value)
    if kind is dict:
        pv_need(len(value) <= 32, "bounds")
        for key, item in value.items():
            pv_need(type(key) is str, "bounds")
            pv_walk(key, depth + 1, counter)
            pv_walk(item, depth + 1, counter)
    elif kind is list:
        pv_need(len(value) <= pv_ARRAY_CAP, "bounds")
        for item in value:
            pv_walk(item, depth + 1, counter)
    elif kind is str:
        pv_need(len(value) <= 512 and "\0" not in value and
                not any(0xD800 <= ord(ch) <= 0xDFFF for ch in value), "bounds")
    elif kind is int:
        pv_need(abs(value) <= 1000000000000, "bounds")
    elif kind is float:
        pv_need(math.isfinite(value), "bounds")
    else:
        pv_need(value is None or kind is bool, "bounds")


def pv_pairs(items):
    result = {}
    for key, value in items:
        pv_need(key not in result, "json")
        result[key] = value
    return result


def pv_json_int(text):
    pv_need(len(text) <= 14, "json")
    return int(text)


def pv_constant(_text):
    raise pv_Error("json")


def pv_sha(value):
    return type(value) is str and pv_SHA_RE.fullmatch(value) is not None


def pv_id(value):
    return type(value) is str and len(value) <= 256 and pv_ID_RE.fullmatch(value) is not None


def pv_inventory(value, ignored=False):
    pv_keys(value, pv_SUITES, "inventory")
    total = 0
    for suite in pv_SUITES:
        ids = value[suite]
        pv_need(type(ids) is list and len(ids) <= pv_ID_CAP and
                (ignored or len(ids) > 0) and all(pv_id(item) for item in ids), "inventory")
        pv_need(len(ids) == len(set(ids)) and ids == sorted(ids), "inventory")
        total += len(ids)
    pv_need(total <= pv_ID_CAP, "inventory")


def pv_subset(full, ignored):
    for suite in pv_SUITES:
        pv_need(set(ignored[suite]) <= set(full[suite]), "inventory")


def pv_identity_block(value):
    pv_keys(value, pv_IDENTITIES, "identities")
    pv_need(all(pv_sha(item) for item in value.values()), "identities")


def pv_na(value):
    pv_keys(value, {"applicable"}, "witness")
    pv_need(value["applicable"] is False, "witness")


def pv_witness(value, suite, case_id):
    pv_keys(value, {"migrations_successful", "csrf_witness", "rbac_witness"}, "witness")
    pv_need(pv_int(value["migrations_successful"], 1, 10000), "witness")
    csrf, rbac = value["csrf_witness"], value["rbac_witness"]
    if suite == "rbac_matrix" and case_id == "test_csrf_protection":
        pv_keys(csrf, {"applicable", "api_keys_csrf_test_key", "api_keys_nested_key"}, "witness")
        pv_need(csrf["applicable"] is True and
                all(pv_int(csrf[k], 1, 1) for k in ("api_keys_csrf_test_key", "api_keys_nested_key")), "witness")
    else:
        pv_na(csrf)
    if suite == "rbac_matrix" and case_id == "test_rbac_matrix":
        pv_keys(rbac, {"applicable", "users_rbac_operator", "users_rbac_viewer", "wrong_roles"}, "witness")
        pv_need(rbac["applicable"] is True and
                all(pv_int(rbac[k], 1, 1) for k in ("users_rbac_operator", "users_rbac_viewer")) and
                pv_int(rbac["wrong_roles"], 0, 0), "witness")
    else:
        pv_na(rbac)


def pv_case(row, selected, case_timeout, certificates, filtered_out):
    pv_keys(row, pv_ROW, "case")
    pv_need(row["suite"] == selected["suite"] and row["id"] == selected["id"], "selection")
    pv_need(type(row["status"]) is str and row["status"] in ("PASS", "FAIL", "NOT_RUN"), "case")
    pv_need(type(row["phase"]) is str and row["phase"] in pv_PHASES, "phase")
    pv_need(type(row["category"]) is str and row["category"] in pv_CATEGORIES, "category")
    pv_keys(row["presence"], {"fixture", "libtest", "witness"}, "presence")
    pv_need(all(type(flag) is bool for flag in row["presence"].values()) and
            row["presence"] == {"fixture": row["fixture"] is not None,
                                "libtest": row["result"] is not None,
                                "witness": row["witness"] is not None}, "presence")
    pv_need(row["exit"] is None or pv_int(row["exit"], -255, 255), "exit")
    pv_need(type(row["timed_out"]) is bool and pv_number(row["elapsed_s"], 0, case_timeout if row["status"] == "PASS" else pv_TERMINAL_ELAPSED_CAP) and
            pv_int(row["openssl_commands"], 0, 128), "case")
    pv_need(all(row[k] is None or type(row[k]) is bool for k in
                ("owned_drain", "private_data_removed")), "cleanup")
    pv_need(row["private_data_removed"] is not True or row["owned_drain"] is True, "cleanup")
    if row["status"] == "NOT_RUN":
        pv_need(row["phase"] == "case" and row["category"] == "not_run" and
                not any(row["presence"].values()) and row["exit"] is None and
                row["timed_out"] is False and row["elapsed_s"] == 0 and
                row["openssl_commands"] == 0 and all(row[k] is None for k in
                ("result", "auth", "fixture", "witness", "owned_drain", "private_data_removed")), "not_run")
        return
    pv_need(type(row["owned_drain"]) is bool and type(row["private_data_removed"]) is bool, "cleanup")
    fixture, auth, result, witness = (row[k] for k in ("fixture", "auth", "result", "witness"))
    if fixture is not None:
        pv_keys(fixture, pv_FIXTURE, "fixture")
        pv_need(all(type(fixture[k]) is bool for k in pv_FIXTURE_FLAGS) and
                fixture["case_prepared"] is True and pv_sha(fixture["ca_sha256"]) and
                pv_sha(fixture["leaf_sha256"]) and fixture["ca_sha256"] != fixture["leaf_sha256"], "fixture")
        for key in ("ca_sha256", "leaf_sha256"):
            pv_need(fixture[key] not in certificates, "fixture")
            certificates.add(fixture[key])
        if row["status"] == "PASS":
            pv_need(fixture["bootstrap_complete"] is (auth is not None), "auth")
        # Fixture removal alone does not prove successful removal of parent work.
        pv_need(row["private_data_removed"] is not True or fixture["removed"] is True, "cleanup")
    else:
        pv_need(auth is None, "auth")
    if auth is not None:
        pv_keys(auth, pv_AUTH, "auth")
        pv_need(all(flag is True for flag in auth.values()) and fixture is not None and
                all(fixture[k] is True for k in ("bootstrap_complete", "verified_tls_ready",
                    "untrusted_ca_rejected", "wrapper_sessions_revoked")), "auth")
    if result is not None:
        pv_keys(result, {"id", "passed", "failed", "ignored", "measured", "filtered_out"}, "result")
        pv_need(type(result["id"]) is str and result["id"] == row["id"] and
                pv_int(result["passed"], 1, 1) and all(pv_int(result[k], 0, 0) for k in
                    ("failed", "ignored", "measured")) and
                pv_int(result["filtered_out"], 0, 256) and result["filtered_out"] == filtered_out and
                pv_int(row["exit"], 0, 0), "result")
        # An observed exit0/result remains valid after a later cleanup timeout.
    if witness is not None:
        pv_need(result is not None and auth is not None and pv_int(row["exit"], 0, 0), "witness")
        pv_witness(witness, row["suite"], row["id"])
    if row["status"] == "PASS":
        pv_need(row["phase"] == "complete" and row["category"] == "ok" and
                pv_int(row["exit"], 0, 0) and row["timed_out"] is False and
                all(row["presence"].values()) and auth is not None and
                all(fixture[k] is True for k in pv_FIXTURE_FLAGS) and row["openssl_commands"] > 0 and
                row["owned_drain"] is True and row["private_data_removed"] is True, "pass")
    else:
        pv_need(row["phase"] != "complete" and row["category"] not in ("ok", "not_run"), "fail")
        pv_need(row["category"] != "timeout" or row["timed_out"] is True, "fail")
        pv_need(not row["timed_out"] or row["category"] in
                ("timeout", "cleanup_failed", "unknown_drain"), "fail")


def pv_policy(report, expected, actual_exit):
    pv_keys(expected, pv_EXPECTED, "expected")
    pv_need(pv_number(expected["timeout"], 0, 1200) and expected["timeout"] > 0 and
            pv_number(expected["case_timeout"], 30, 45) and expected["case_timeout"] > 30, "expected")
    for key in ("inventory", "ignored_inventory"):
        if expected[key] is not None:
            pv_inventory(expected[key], ignored=key == "ignored_inventory")
    if expected["inventory"] is not None and expected["ignored_inventory"] is not None:
        pv_subset(expected["inventory"], expected["ignored_inventory"])
    if expected["identities"] is not None:
        pv_identity_block(expected["identities"])
    pv_need(pv_int(actual_exit, -255, 255), "exit")
    pv_keys(report, pv_TOP, "schema")
    pv_need(pv_int(report["schemaVersion"], 1, 1) and type(report["status"]) is str and
            report["status"] in ("PASS", "FAIL"), "schema")
    pv_need(type(report["phase"]) is str and report["phase"] in pv_PHASES, "phase")
    pv_need(type(report["category"]) is str and report["category"] in pv_CATEGORIES, "category")
    pv_keys(report["presence"], {"identities", "discovery", "cases"}, "presence")
    pv_need(all(type(flag) is bool for flag in report["presence"].values()), "presence")
    ids, full, ignored = (report[k] for k in ("identities", "discovery", "ignored_inventory"))
    pv_need((full is None) is (ignored is None), "inventory")
    if ids is not None:
        pv_identity_block(ids)
        pv_need(expected["identities"] is not None and ids == expected["identities"], "identities")
        pv_keys(report["build_evidence"], {"root_owned_inputs", "cargo_records_validated", "producer_scope"}, "build_evidence")
        evidence = report["build_evidence"]
        pv_need(evidence["root_owned_inputs"] is True and evidence["cargo_records_validated"] is True and
                evidence["producer_scope"] == "ROOT_OWNED_CAPTURE_NOT_CRYPTOGRAPHIC_ATTESTATION", "build_evidence")
    else:
        pv_need(report["build_evidence"] is None, "build_evidence")
    selected_expected = []
    if full is not None:
        pv_inventory(full)
        pv_inventory(ignored, ignored=True)
        pv_subset(full, ignored)
        pv_need(expected["inventory"] is not None and expected["ignored_inventory"] is not None and
                full == expected["inventory"] and ignored == expected["ignored_inventory"], "inventory")
        selected_expected = [{"suite": suite, "id": test_id}
                             for suite in pv_SUITES for test_id in full[suite]]
    selected, rows = report["selected"], report["per_case"]
    pv_need(type(selected) is list and type(rows) is list and
            len(selected) == len(rows) == len(selected_expected), "selection")
    for item in selected:
        pv_keys(item, {"suite", "id"}, "selection")
        pv_need(type(item["suite"]) is str and item["suite"] in pv_SUITES and pv_id(item["id"]), "selection")
    pv_need(selected == selected_expected, "selection")
    pv_need(report["presence"] == {"identities": ids is not None,
                "discovery": full is not None and ignored is not None, "cases": len(rows) > 0}, "presence")
    certificates = set()
    not_run_seen = False
    counts = {"discovered": len(selected), "selected": len(selected),
              "attempted": 0, "passed": 0, "failed": 0, "not_run": 0}
    for row, choice in zip(rows, selected):
        pv_case(row, choice, expected["case_timeout"], certificates,
                len(full[choice["suite"]]) - 1)
        if row["status"] == "NOT_RUN":
            not_run_seen = True
            counts["not_run"] += 1
        else:
            pv_need(not not_run_seen, "not_run")
            counts["attempted"] += 1
            counts["passed" if row["status"] == "PASS" else "failed"] += 1
    pv_keys(report["counts"], pv_COUNTS, "counts")
    pv_need(all(pv_int(value, 0, pv_ID_CAP) for value in report["counts"].values()) and
            report["counts"] == counts, "counts")
    pv_need(pv_number(report["elapsed_s"], 0, expected["timeout"] if report["status"] == "PASS" else pv_TERMINAL_ELAPSED_CAP), "elapsed")
    pv_need(type(report["owned_drain"]) is bool and type(report["private_data_removed"]) is bool and
            (not report["private_data_removed"] or report["owned_drain"]), "cleanup")
    if report["status"] == "PASS":
        pv_need(report["phase"] == "complete" and report["category"] == "ok" and actual_exit == 0 and
                all(report["presence"].values()) and ids is not None and full is not None and
                counts["attempted"] == counts["passed"] == len(selected) and counts["failed"] == 0 and
                counts["not_run"] == 0 and report["owned_drain"] and report["private_data_removed"], "pass")
    else:
        pv_need(report["phase"] != "complete" and report["category"] != "ok" and actual_exit != 0, "fail")
    return report


def validate_report(raw: bytes, *, expected: dict, actual_exit: int) -> dict:
    """Validate data only. Caller must independently supply expected identities/inventories."""
    try:
        pv_need(type(raw) is bytes and 0 < len(raw) <= pv_RAW_CAP, "raw")
        pv_walk(expected)
        report = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=pv_pairs,
                            parse_constant=pv_constant, parse_int=pv_json_int)
        pv_walk(report)
        accepted = pv_policy(report, expected, actual_exit)
        return {"valid": True, "reason": "ok", "report": accepted}
    except pv_Error as error:
        return {"valid": False, "reason": error.reason, "report": None}
    except (UnicodeError, ValueError, TypeError, RecursionError, OverflowError, KeyError, IndexError):
        return {"valid": False, "reason": "invalid", "report": None}
    except Exception:
        return {"valid": False, "reason": "invalid", "report": None}


if __name__ == '__main__':
    raise SystemExit(main())
