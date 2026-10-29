#!/usr/bin/env python3
"""Disposable native-auth CI producer; all application execution is unprivileged.

The public source is immutable. Docker and process ownership are separate
boundaries. This producer accepts only observed complete success, never a
subject report alone. Private artifacts and diagnostics are never published.
"""
from __future__ import annotations

import argparse
import ast
import base64
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest

MAX_REPORT = 1048576
MAX_FILE = 16 * 1048576
MAX_SOURCE = 128 * 1048576
MAX_HOST_TOOL = 128 * 1048576
MAX_FILES = 4096
MAX_ELF = 256 * 1048576
MAX_CLI = 2 * 1048576  # Complete captures only; oversize fails closed.
SUITES = ('auth_integration', 'rbac_matrix')
SCRIPTS = ('scripts/live_auth_fixture.py', 'scripts/run-live-auth-acceptance.py',
           'scripts/tests/test_live_auth_acceptance_policy.py', 'scripts/ci-live-auth-acceptance.py')
IDENTITIES = ('source_sha256','helper_sha256','runner_sha256','build_manifest_sha256',
              'web_sha256','auth_sha256','rbac_sha256','runtime_sha256','build_capture_sha256')
TEST_ARGS = ['test','--release','--locked','--offline','--no-run','--tests',
             '--message-format=json','-p','trueid-integration-tests','-p','trueid-web']
WEB_ARGS = ['build','--release','--locked','--offline','--message-format=json',
            '-p','trueid-web','--bin','trueid-web']
HASH = re.compile(r'[0-9a-f]{64}')
TEST_ID = re.compile(r'[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*')
cleanup_uncertain = False
cancelled = False
environment = {}
docker_tool = None
intents = []
image_intents = []
end_time = None
work_end = None
private_capture_root = None
private_capture_bytes = 0
private_capture_sequence = 0


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode('ascii')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def closed(value, keys):
    need(type(value) is dict and set(value) == set(keys), 'SCHEMA')


def exact_int(value, low, high):
    need(type(value) is int and low <= value <= high, 'INTEGER')
    return value


def number(value, high):
    need(type(value) in (int, float) and math.isfinite(value) and 0 <= value <= high, 'NUMBER')


def hash_value(value):
    need(type(value) is str and HASH.fullmatch(value) is not None, 'HASH')


def strict_json(raw, cap=MAX_REPORT, array_cap=512):
    need(type(raw) is bytes and 0 < len(raw) <= cap, 'JSON_BYTES')
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'DUPLICATE_KEY')
            result[key] = value
        return result
    def constant(_value):
        raise Failure('NONFINITE')
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs, parse_constant=constant)
        def walk(item, depth=0):
            need(depth <= 16, 'JSON_DEPTH')
            if type(item) is str:
                need(len(item) <= 65536 and '\0' not in item and
                     not any(0xD800 <= ord(c) <= 0xDFFF for c in item), 'JSON_TEXT')
            elif type(item) is dict:
                need(len(item) <= MAX_FILES, 'JSON_OBJECT')
                for key, child in item.items():
                    walk(key, depth+1); walk(child, depth+1)
            elif type(item) is list:
                need(len(item) <= array_cap, 'JSON_ARRAY')
                for child in item: walk(child, depth+1)
            elif type(item) in (int, float):
                need(math.isfinite(item) and abs(item) <= 2**63-1, 'JSON_NUMBER')
            else:
                need(item is None or type(item) is bool, 'JSON_TYPE')
        walk(value)
        return value
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        raise Failure('JSON_INVALID') from None


def safe_ids(rows, *, empty=False):
    need(type(rows) is list and (rows or empty) and len(rows) <= 256 and
         all(type(x) is str and len(x) <= 256 and TEST_ID.fullmatch(x) for x in rows) and
         rows == sorted(set(rows)), 'INVENTORY')


def validate_native_report(raw: bytes, *, expected: dict, actual_exit: int) -> dict:
    """Pure independent acceptance. It never calls the subject's validator."""
    try:
        need(type(actual_exit) is int and actual_exit == 0, 'ACTUAL_EXIT')
        closed(expected, ('identities','inventory','ignored_inventory','selected'))
        closed(expected['identities'], IDENTITIES)
        for value in expected['identities'].values(): hash_value(value)
        for name in ('inventory','ignored_inventory'):
            closed(expected[name], SUITES)
            for suite in SUITES: safe_ids(expected[name][suite], empty=name == 'ignored_inventory')
        for suite in SUITES:
            need(set(expected['ignored_inventory'][suite]) <= set(expected['inventory'][suite]), 'EXPECTED_IGNORED')
        selected = [{'suite':suite,'id':tid} for suite in SUITES for tid in expected['inventory'][suite]]
        need(0 < len(selected) <= 256 and expected['selected'] == selected, 'EXPECTED_SELECTION')
        doc = strict_json(raw)
        closed(doc, ('schemaVersion','status','phase','category','presence','identities','build_evidence',
                     'discovery','ignored_inventory','selected','per_case','counts','elapsed_s',
                     'owned_drain','private_data_removed'))
        exact_int(doc['schemaVersion'], 1, 1)
        need(doc['status'] == 'PASS' and doc['phase'] == 'complete' and doc['category'] == 'ok', 'COMPLETE_PASS')
        closed(doc['presence'], ('identities','discovery','cases'))
        need(all(x is True for x in doc['presence'].values()), 'PRESENCE')
        closed(doc['identities'], IDENTITIES)
        for value in doc['identities'].values(): hash_value(value)
        need(doc['identities'] == expected['identities'], 'IDENTITIES')
        closed(doc['build_evidence'], ('root_owned_inputs','cargo_records_validated','producer_scope'))
        need(doc['build_evidence']['root_owned_inputs'] is True and
             doc['build_evidence']['cargo_records_validated'] is True and
             doc['build_evidence']['producer_scope'] == 'ROOT_OWNED_CAPTURE_NOT_CRYPTOGRAPHIC_ATTESTATION', 'BUILD_EVIDENCE')
        for name in ('discovery','ignored_inventory'):
            closed(doc[name], SUITES)
            for suite in SUITES: safe_ids(doc[name][suite], empty=name == 'ignored_inventory')
        need(doc['discovery'] == expected['inventory'] and doc['ignored_inventory'] == expected['ignored_inventory'], 'DISCOVERY')
        need(type(doc['selected']) is list and len(doc['selected']) == len(selected), 'SELECTION')
        for row, target in zip(doc['selected'], selected):
            closed(row, ('suite','id')); need(row == target, 'SELECTION')
        need(type(doc['per_case']) is list and len(doc['per_case']) == len(selected), 'CASES')
        certificates, leaves = set(), set()
        for row, target in zip(doc['per_case'], selected):
            closed(row, ('suite','id','status','phase','category','presence','exit','timed_out','elapsed_s',
                         'result','auth','fixture','witness','openssl_commands','owned_drain','private_data_removed'))
            need(row['suite'] == target['suite'] and row['id'] == target['id'] and row['status'] == 'PASS' and
                 row['phase'] == 'complete' and row['category'] == 'ok', 'CASE_PASS')
            exact_int(row['exit'], 0, 0); need(row['timed_out'] is False, 'CASE_TIMEOUT'); number(row['elapsed_s'], 45)
            closed(row['presence'], ('fixture','libtest','witness'))
            need(all(x is True for x in row['presence'].values()), 'CASE_PRESENCE')
            exact_int(row['openssl_commands'], 1, 128)
            need(row['owned_drain'] is True and row['private_data_removed'] is True, 'CASE_CLEANUP')
            result = row['result']; closed(result, ('id','passed','failed','ignored','measured','filtered_out'))
            need(result['id'] == target['id'], 'CASE_ID')
            for key, count in (('passed',1),('failed',0),('ignored',0),('measured',0),
                               ('filtered_out',len(expected['inventory'][target['suite']])-1)):
                exact_int(result[key], count, count)
            closed(row['auth'], ('verified_tls','untrusted_ca_rejected','initial_force_change','three_cookie_rotation',
                                 'changed_password_new_login','both_sessions_revoked'))
            need(all(x is True for x in row['auth'].values()), 'AUTH')
            fixture = row['fixture']
            closed(fixture, ('case_prepared','bootstrap_complete','verified_tls_ready','untrusted_ca_rejected',
                             'wrapper_sessions_revoked','leaf_sha256','ca_sha256','removed'))
            for key in ('case_prepared','bootstrap_complete','verified_tls_ready','untrusted_ca_rejected',
                        'wrapper_sessions_revoked','removed'): need(fixture[key] is True, 'FIXTURE')
            hash_value(fixture['leaf_sha256']); hash_value(fixture['ca_sha256'])
            need(fixture['leaf_sha256'] != fixture['ca_sha256'] and fixture['ca_sha256'] not in certificates | leaves and
                 fixture['leaf_sha256'] not in certificates | leaves, 'CERTIFICATES')
            certificates.add(fixture['ca_sha256']); leaves.add(fixture['leaf_sha256'])
            witness = row['witness']; closed(witness, ('migrations_successful','csrf_witness','rbac_witness'))
            exact_int(witness['migrations_successful'], 1, 10000)
            if target == {'suite':'rbac_matrix','id':'test_csrf_protection'}:
                closed(witness['csrf_witness'], ('applicable','api_keys_csrf_test_key','api_keys_nested_key'))
                need(witness['csrf_witness']['applicable'] is True, 'CSRF_WITNESS')
                exact_int(witness['csrf_witness']['api_keys_csrf_test_key'], 1, 1)
                exact_int(witness['csrf_witness']['api_keys_nested_key'], 1, 1)
            else:
                closed(witness['csrf_witness'], ('applicable',)); need(witness['csrf_witness']['applicable'] is False, 'CSRF_NA')
            if target == {'suite':'rbac_matrix','id':'test_rbac_matrix'}:
                closed(witness['rbac_witness'], ('applicable','users_rbac_operator','users_rbac_viewer','wrong_roles'))
                need(witness['rbac_witness']['applicable'] is True, 'RBAC_WITNESS')
                for key, count in (('users_rbac_operator',1),('users_rbac_viewer',1),('wrong_roles',0)):
                    exact_int(witness['rbac_witness'][key], count, count)
            else:
                closed(witness['rbac_witness'], ('applicable',)); need(witness['rbac_witness']['applicable'] is False, 'RBAC_NA')
        closed(doc['counts'], ('discovered','selected','attempted','passed','failed','not_run'))
        for key in ('discovered','selected','attempted','passed'): exact_int(doc['counts'][key], len(selected), len(selected))
        exact_int(doc['counts']['failed'], 0, 0); exact_int(doc['counts']['not_run'], 0, 0)
        number(doc['elapsed_s'], 1200)
        need(doc['owned_drain'] is True and doc['private_data_removed'] is True, 'CLEANUP')
        return {'valid':True, 'reason':'OK', 'report':doc}
    except (Failure, ValueError, TypeError, KeyError, IndexError, OverflowError, RecursionError):
        return {'valid':False, 'reason':'NATIVE_REPORT_REJECTED', 'report':None}



class Failure(Exception):
    def __init__(self, code):
        self.code = code


def need(ok, code):
    if not ok:
        raise Failure(code)



def cancel(_number, _frame):
    global cancelled
    cancelled = True



def owned_cli_capture(argv, seconds, *, cleanup=False, stdout_cap=1048576, stderr_cap=65536):
    """Bound one CLI and its causally owned children; never reap the anchor early."""
    import ctypes
    import errno
    import math
    global cleanup_uncertain
    process = main_ref = self_ref = terminal = None
    refs = {}
    selector = selectors.DefaultSelector()
    chunks = {'stdout': bytearray(), 'stderr': bytearray()}
    started = time.monotonic()
    problem = None
    clean = False
    armed = False
    previous = None
    libc = None
    active_before = getattr(owned_cli_capture, '_active', False)

    def no_children():
        try: os.waitid(os.P_ALL, 0, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except ChildProcessError: return True
        return False

    def row(dfd):
        fd = os.open('stat', os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=dfd)
        try: data = os.read(fd, 8193)
        finally: os.close(fd)
        need(len(data) <= 8192 and b')' in data, 'OWNED_STAT')
        fields = data[data.rfind(b')') + 2:].split()
        need(len(fields) >= 20, 'OWNED_STAT')
        return {'pid': int(data[:data.index(b' ')]), 'ppid': int(fields[1]),
                'start': int(fields[19])}

    def read(ref):
        try: current = row(ref['proc'])
        except OSError as error:
            if error.errno in (errno.ENOENT, errno.ESRCH): return None
            raise
        need((current['pid'], current['start']) == ref['identity'], 'OWNED_IDENTITY')
        return current

    def close_ref(ref):
        for key in ('pidfd', 'proc'):
            fd = ref[key]
            if fd is not None:
                os.close(fd)
                ref[key] = None

    def pin(pid, parent=None):
        parent_before = read(parent) if parent is not None else None
        need(parent is None or parent_before is not None, 'OWNED_RESCAN')
        dfd = os.open('/proc/' + str(pid), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        pfd = None
        try:
            first = row(dfd)
            pfd = os.pidfd_open(pid, 0)
            last = row(dfd)
            need(first['pid'] == last['pid'] == pid and first['start'] == last['start'], 'OWNED_RESCAN')
            if parent is not None:
                parent_after = read(parent)
                need(parent_after is not None and first['ppid'] == last['ppid'] == parent_before['pid'] ==
                     parent_after['pid'], 'OWNED_RESCAN')
            return {'proc': dfd, 'pidfd': pfd, 'identity': (pid, last['start'])}
        except BaseException:
            if pfd is not None: os.close(pfd)
            os.close(dfd)
            raise

    def exited(ref):
        # WNOWAIT is also the identity-safe readiness observation for an adopted child.
        poller = selectors.DefaultSelector()
        try:
            poller.register(ref['pidfd'], selectors.EVENT_READ)
            return bool(poller.select(0))
        finally: poller.close()

    def discover():
        nonlocal main_ref
        ids = sorted(int(value) for value in os.listdir('/proc') if value.isdecimal())
        need(len(ids) <= 4096, 'OWNED_SCAN_CAP')
        parents = {os.getpid(): self_ref}
        for ref in refs.values():
            if read(ref) is not None: parents[ref['identity'][0]] = ref
        known = {ref['identity'][0] for ref in refs.values()}
        for pid in ids:
            if pid == os.getpid() or pid in known: continue
            dfd = None
            try:
                dfd = os.open('/proc/' + str(pid), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
                candidate = row(dfd)
                parent = parents.get(candidate['ppid'])
                if parent is None: continue
                ref = pin(pid, parent)
            except OSError as error:
                if error.errno in (errno.ENOENT, errno.ESRCH): continue
                raise
            except Failure as error:
                if error.code == 'OWNED_RESCAN': continue
                raise
            finally:
                if dfd is not None: os.close(dfd)
            if len(refs) >= 256:
                close_ref(ref)
                raise Failure('OWNED_PROCESS_CAP')
            refs[ref['identity']] = ref
            parents[pid] = ref
            known.add(pid)
            if process is not None and pid == process.pid and main_ref is None: main_ref = ref

    def observe():
        nonlocal terminal
        if main_ref is not None and terminal is None:
            terminal = os.waitid(os.P_PIDFD, main_ref['pidfd'], os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if terminal is not None:
                need(terminal.si_pid == process.pid and terminal.si_code in
                     (os.CLD_EXITED, os.CLD_KILLED, os.CLD_DUMPED), 'OWNED_MAIN_STATUS')
        for identity, ref in list(refs.items()):
            if ref is main_ref or not exited(ref): continue
            try:
                result = os.waitid(os.P_PIDFD, ref['pidfd'], os.WEXITED | os.WNOHANG)
                need(result is None or result.si_pid == identity[0], 'OWNED_REAP_IDENTITY')
            except ChildProcessError:
                pass  # Its owned living parent reaped it, or it is not adopted yet.
            close_ref(ref)
            del refs[identity]

    def pump(discard=False):
        for key, _mask in selector.select(0.02):
            try: part = os.read(key.fd, 65536)
            except BlockingIOError: continue
            if not part:
                selector.unregister(key.fileobj)
                continue
            if not discard:
                target = chunks[key.data]
                limit = stdout_cap if key.data == 'stdout' else stderr_cap
                room = max(0, limit - len(target))
                target.extend(part[:room])
                need(len(part) <= room, 'CAPTURE_CAP')

    def finish():
        nonlocal clean
        if selector.get_map(): return False
        if process is None:
            clean = not refs and no_children()
            return clean
        if main_ref is None or terminal is None or any(ref is not main_ref for ref in refs.values()): return False
        # Single-thread/no-concurrent-spawn lease makes every other direct child
        # causally owned; an unseen adopted root must be discovered before reap.
        fd = os.open('/proc/self/task/' + str(os.getpid()) + '/children', os.O_RDONLY | os.O_CLOEXEC)
        try: children = os.read(fd, 65537)
        finally: os.close(fd)
        need(len(children) <= 65536, 'OWNED_CHILDREN_CAP')
        if {int(value) for value in children.split()} != {process.pid}: return False
        expected = terminal.si_status if terminal.si_code == os.CLD_EXITED else -terminal.si_status
        actual = process.wait(timeout=0)  # Sole exact reaper, after descendants and PIPE EOF.
        need(actual == expected, 'OWNED_MAIN_REAP_STATUS')
        close_ref(main_ref)
        del refs[main_ref['identity']]
        clean = no_children()
        need(clean, 'OWNED_DRAIN_UNPROVEN')
        return True

    try:
        need(cleanup or not cancelled, 'CANCELLED')
        need(type(seconds) in (int, float) and math.isfinite(seconds) and 0 < seconds <= 1800 and
             type(stdout_cap) is type(stderr_cap) is int and 0 < stdout_cap <= 2097152 and
             0 < stderr_cap <= 2097152, 'CAPTURE_BOUNDS')
        need(not active_before and len(os.listdir('/proc/self/task')) == 1 and
             signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL and no_children(), 'OWNED_CAPTURE_PREFLIGHT')
        owned_cli_capture._active = True
        libc = ctypes.CDLL(None, use_errno=True)
        libc.prctl.restype = ctypes.c_int
        value = ctypes.c_int(-1)
        need(libc.prctl(37, ctypes.byref(value), 0, 0, 0) == 0 and value.value in (0, 1), 'OWNED_GET_SUBREAPER')
        previous = value.value
        need(libc.prctl(36, 1, 0, 0, 0) == 0, 'OWNED_SET_SUBREAPER')
        armed = True
        need(libc.prctl(37, ctypes.byref(value), 0, 0, 0) == 0 and value.value == 1, 'OWNED_VERIFY_SUBREAPER')
        self_ref = pin(os.getpid())
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True, env=environment)
        main_ref = pin(process.pid, self_ref)
        refs[main_ref['identity']] = main_ref
        for label in chunks:
            pipe = getattr(process, label)
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, label)
        while True:
            need(cleanup or not cancelled, 'CANCELLED')
            need(time.monotonic() - started < seconds, 'TIMEOUT')
            discover()
            observe()
            pump()
            if finish(): break
    except BaseException as error:
        cleanup_uncertain = True  # Preserve R2 policy: every capture exception poisons later stages.
        problem = error
    finally:
        if armed and not clean:
            until = time.monotonic() + 6
            term_until = time.monotonic() + 3
            sent = set()
            while time.monotonic() < until:
                try:
                    if self_ref is not None: discover()
                except BaseException:
                    cleanup_uncertain = True
                try:
                    observe()
                except BaseException:
                    cleanup_uncertain = True
                signum = signal.SIGTERM if time.monotonic() < term_until else signal.SIGKILL
                # Failed discovery or one damaged ref never suppresses other proved pidfds.
                for identity, ref in list(refs.items()):
                    try:
                        if (identity, signum) in sent or exited(ref): continue
                        signal.pidfd_send_signal(ref['pidfd'], signum, None, 0)
                        sent.add((identity, signum))
                    except ProcessLookupError: pass
                    except BaseException: cleanup_uncertain = True  # No numeric/global fallback.
                try:
                    pump(discard=True)
                except BaseException:
                    cleanup_uncertain = True
                try:
                    if finish(): break
                except BaseException:
                    cleanup_uncertain = True
                time.sleep(0.01)
        if armed and clean:
            try:
                value = ctypes.c_int(-1)
                need(libc.prctl(36, previous, 0, 0, 0) == 0 and
                     libc.prctl(37, ctypes.byref(value), 0, 0, 0) == 0 and value.value == previous,
                     'OWNED_RESTORE_SUBREAPER')
            except BaseException as error:
                cleanup_uncertain = True
                problem = problem or error
        if armed and not clean:
            cleanup_uncertain = True
            problem = problem or Failure('OWNED_DRAIN_UNPROVEN')
        for ref in list(refs.values()) + ([self_ref] if self_ref is not None else []):
            try: close_ref(ref)
            except BaseException as error:
                cleanup_uncertain = True
                problem = problem or error
        try:
            selector.close()
            if process is not None:
                process.stdout.close()
                process.stderr.close()
        except BaseException as error:
            cleanup_uncertain = True
            problem = problem or error
        if not active_before: owned_cli_capture._active = False
    if problem is not None: raise problem
    need(clean, 'OWNED_DRAIN_UNPROVEN')
    return process.returncode, bytes(chunks['stdout']), bytes(chunks['stderr']), round(time.monotonic() - started, 3)



def budget(seconds, *, cleanup=False):
    need(type(seconds) in (int, float) and math.isfinite(seconds) and seconds > 0, 'BUDGET')
    boundary = end_time-5 if cleanup else work_end
    remaining = boundary-time.monotonic()-7  # The exact donor has a bounded emergency drain.
    need(remaining > 0 and (cleanup or not cancelled), 'TIMEOUT')
    return min(float(seconds), 1800.0, remaining)


def keep_capture(label, raw, errors):
    global private_capture_bytes, private_capture_sequence
    if private_capture_root is None: return
    need(label in ('CLI','CONTAINER') and type(raw) is type(errors) is bytes and len(raw) <= MAX_CLI and len(errors) <= MAX_CLI, 'PRIVATE_CAPTURE')
    private_capture_bytes += len(raw)+len(errors)
    need(private_capture_bytes <= 32*1048576, 'PRIVATE_CAPTURE_CAP')
    private_capture_sequence += 1
    stem = 'capture-'+str(private_capture_sequence).zfill(3)+'-'+label
    for name, data in (('stdout',raw),('stderr',errors)):
        if data: atomic(private_capture_root/(stem+'.'+name), data, 0o600)


def command(argv, seconds=30, *, cap=MAX_CLI, cleanup=False, check=True):
    if argv and argv[0] == 'docker':
        need(type(docker_tool) is str and Path(docker_tool).is_absolute(), 'DOCKER_TOOL_PIN')
        argv = [docker_tool,*argv[1:]]
    code, raw, errors, elapsed = owned_cli_capture(argv, budget(seconds, cleanup=cleanup),
        cleanup=cleanup, stdout_cap=cap, stderr_cap=MAX_CLI)
    need(cleanup or not cancelled, 'CANCELLED')
    if type(code) is int and code != 0: keep_capture('CLI',raw,errors)
    if check: need(type(code) is int and code == 0, 'COMMAND_EXIT')
    return code, raw, errors, elapsed


def tick():
    need(not cancelled and time.monotonic() < work_end, 'TIMEOUT')


def regular(path, cap, *, root=False, readonly=False):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path, 'PUBLIC_PATH')
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 <= info.st_size <= cap, 'PUBLIC_FILE')
    if root: need(info.st_uid == 0 and info.st_gid == 0, 'ROOT_FILE')
    if readonly: need(not info.st_mode & 0o222, 'READONLY_FILE')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need((before.st_dev,before.st_ino,before.st_size) == (info.st_dev,info.st_ino,info.st_size), 'FILE_SNAPSHOT')
        chunks = []
        total = 0
        while True:
            raw = os.read(fd, min(1048576,cap+1-total))
            if not raw: break
            chunks.append(raw); total += len(raw); need(total <= cap, 'FILE_CAP')
        after = os.fstat(fd)
        need((after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns) ==
             (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns), 'FILE_DRIFT')
        raw = b''.join(chunks); need(len(raw) == info.st_size, 'FILE_SIZE'); return raw
    finally: os.close(fd)


def atomic(path, raw, mode=0o444):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_SOURCE, 'WRITE_BYTES')
    path = Path(path)
    need(path.is_absolute() and path.parent.resolve(strict=True) == path.parent and
         not os.path.lexists(path), 'NEW_OUTPUT')
    temporary = path.parent/('.'+path.name+'-'+secrets.token_hex(16))
    fd = os.open(temporary, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC, 0o600)
    try:
        view = memoryview(raw)
        while view:
            n = os.write(fd, view); need(n > 0, 'WRITE'); view = view[n:]
        os.fsync(fd); os.fchmod(fd, mode)
    finally: os.close(fd)
    need(not os.path.lexists(path), 'NEW_OUTPUT')
    os.link(temporary, path, follow_symlinks=False); os.unlink(temporary)
    directory = os.open(path.parent, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try: os.fsync(directory)
    finally: os.close(directory)
    need(regular(path,MAX_SOURCE) == raw, 'WRITE_SNAPSHOT')


def descriptor(path, cap=MAX_FILE, *, root=False, readonly=False):
    raw = regular(path, cap, root=root, readonly=readonly)
    need(raw, 'EMPTY_INPUT')
    return {'path':str(path),'sha256':digest(raw),'bytes':len(raw)}


def source_map(source):
    source = Path(source)
    need(source.is_absolute() and source.resolve(strict=True) == source and source.is_dir(), 'SOURCE_ROOT')
    selected = set()
    forbidden = {'.env','.git','.cargo','.netrc','.npmrc','credentials','secrets','target','node_modules','__pycache__'}
    suffixes = {'.db','.sqlite','.sqlite3','.log','.pem','.key','.p12','.pfx','.env'}
    def add(path):
        rel = path.relative_to(source).as_posix(); pure = PurePosixPath(rel)
        need(not pure.is_absolute() and '..' not in pure.parts and str(pure) == rel and
             not any(x in forbidden or x.startswith('.env') for x in pure.parts) and
             path.suffix.lower() not in suffixes, 'SOURCE_SECRET')
        regular(path, MAX_FILE)
        selected.add(rel); need(len(selected) <= MAX_FILES, 'SOURCE_COUNT')
    def walk(base, all_files=False):
        need(base.is_dir() and base.resolve(strict=True) == base, 'SOURCE_DIRECTORY')
        for parent, dirs, files in os.walk(base, followlinks=False):
            tick()
            keep = []
            for name in sorted(dirs):
                if name in ('target','node_modules','__pycache__','.git'): continue
                path = Path(parent)/name
                need(path.resolve(strict=True) == path and stat.S_ISDIR(path.lstat().st_mode), 'SOURCE_LINK')
                need(not name.startswith('.'), 'SOURCE_HIDDEN'); keep.append(name)
            dirs[:] = keep
            for name in sorted(files):
                path = Path(parent)/name
                if all_files or name == 'Cargo.toml' or name.endswith('.rs'): add(path)
    for name in ('Cargo.toml','Cargo.lock','rust-toolchain.toml','LICENSE','deny.toml','Dockerfile',*SCRIPTS,
                 'integrations/sycope/Dockerfile','integrations/sycope/pyproject.toml',
                 'integrations/sycope/uv.lock','integrations/sycope/.python-version',
                 'integrations/sycope/trueid_api.py','integrations/sycope/trueid_sync.py'): add(source/name)
    for name in ('apps','crates','tests'): walk(source/name)
    for name in ('tests/support','crates/common/migrations','apps/web/assets'): walk(source/name, True)
    sdk = source/'sycope'
    need(sdk.resolve(strict=True) == sdk and sdk.is_dir(), 'SDK_DIRECTORY')
    for path in sorted(sdk.iterdir()):
        if path.name.endswith('.py'): add(path)
    need(any(x.startswith('sycope/') for x in selected) and any(x.startswith('crates/common/migrations/') for x in selected), 'SOURCE_COMPLETENESS')
    result = {}; total = 0
    for name in sorted(selected):
        tick(); raw = regular(source/name, MAX_FILE); total += len(raw); need(total <= MAX_SOURCE, 'SOURCE_CAP')
        result[name] = {'sha256':digest(raw),'bytes':len(raw)}
    return result


def copy_source(source, target, expected):
    target.mkdir(mode=0o755); target.chmod(0o755)
    for rel, info in expected.items():
        tick(); path = target/rel; path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        for directory in [path.parent,*path.parent.parents]:
            if directory == target.parent: break
            directory.chmod(0o755)
        raw = regular(source/rel, MAX_FILE)
        need({'sha256':digest(raw),'bytes':len(raw)} == info, 'SOURCE_DRIFT')
        atomic(path, raw if raw else b'\n') if raw else None
        if not raw:
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600); os.fchmod(fd,0o444); os.fsync(fd); os.close(fd)
        need(regular(path,MAX_FILE) == raw, 'SOURCE_COPY')
    need(source_map(target) == expected and source_map(source) == expected, 'SOURCE_DRIFT')


def inspect_container(cid, *, cleanup=False):
    need(type(cid) is str and re.fullmatch('[0-9a-f]{64}',cid), 'CID')
    _, raw, _, _ = command(['docker','inspect',cid], cleanup=cleanup, cap=MAX_REPORT)
    rows = strict_json(raw)
    need(type(rows) is list and len(rows) == 1 and type(rows[0]) is dict, 'INSPECT')
    return rows[0]


def recover_intent(intent, *, cleanup=False):
    _, raw, _, _ = command(['docker','ps','-aq','--no-trunc','--filter','label=org.trueid.s4.owner='+intent['owner']],
                            cleanup=cleanup, cap=65536)
    rows = raw.decode('ascii').splitlines(); need(len(rows) <= 1, 'CID_AMBIGUOUS')
    for cid in rows:
        info = inspect_container(cid, cleanup=cleanup)
        need(info['Id'] == cid and info['Name'] == '/'+intent['name'] and info['Image'] == intent['image'] and
             info['Config']['Labels'].get('org.trueid.s4.owner') == intent['owner'], 'CID_IDENTITY')
    return rows


def cleanup_intent(intent):
    global cleanup_uncertain
    if intent['closed']: return
    try:
        rows = recover_intent(intent, cleanup=True)
        need(intent['acked'] or rows, 'UNACKNOWLEDGED_CREATE')
        if rows:
            cid = rows[0]
            need(intent['cid'] is None or cid == intent['cid'], 'CID_DRIFT')
            intent['cid'] = cid
            info = inspect_container(cid, cleanup=True)
            if info['State']['Running']:
                command(['docker','stop','--time','15',cid], 25, cleanup=True)
            command(['docker','rm','-f',cid], 30, cleanup=True)
        need(recover_intent(intent, cleanup=True) == [], 'CID_REMAINS')
        intent['closed'] = True
    except BaseException:
        cleanup_uncertain = True
        raise


def container(image, args, *, seconds, mounts, network='none', workdir='/',
              env=(), cap=MAX_CLI):
    global cleanup_uncertain
    owner = secrets.token_hex(16)
    intent = {'name':'trueid-s4-'+owner,'owner':owner,'image':image,'acked':False,'closed':False,'cid':None}
    intents.append(intent)
    user = '1000:1000'
    config = ['docker','create','--name',intent['name'],'--label','org.trueid.s4.owner='+owner,
              '--platform','linux/amd64','--init','--user',user,'--log-driver','none',
              '--read-only','--network',network,'--cap-drop','ALL','--security-opt','no-new-privileges',
              '--pids-limit','256','--cpus','2','--memory','3g','--memory-swap','3g',
              '--stop-signal','SIGINT','--stop-timeout','15','--workdir',workdir,
              '--entrypoint','/usr/bin/env']
    for source, destination, readonly in mounts:
        need(Path(source).is_absolute() and Path(destination).is_absolute(), 'MOUNT')
        config += ['--mount','type=bind,source='+str(source)+',target='+destination+(',readonly' if readonly else '')]
    config += ['--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=128m,uid=1000,gid=1000,mode=0700',
               '--tmpfs','/run-private:rw,nosuid,nodev,noexec,size=512m,uid=1000,gid=1000,mode=0700']
    base = ['-i','PATH=/usr/bin:/bin','LANG=C.UTF-8','HOME=/run-private/home','TMPDIR=/run-private/tmp',
            'PYTHONDONTWRITEBYTECODE=1','PYTHONNOUSERSITE=1','PYTHONOPTIMIZE=0']
    try:
        _, raw, _, _ = command(config+[image]+base+list(env)+list(args), 30, cap=65536)
        cid = raw.decode('ascii').strip(); intent['acked'] = True; intent['cid'] = cid
        need(re.fullmatch('[0-9a-f]{64}',cid) and recover_intent(intent) == [cid], 'CID_IDENTITY')
        code, raw, errors, elapsed = command(['docker','start','--attach',cid], seconds, cap=cap, check=False)
        keep_capture('CONTAINER',raw,errors)
        info = inspect_container(cid)
        need(type(code) is int and type(info['State']['ExitCode']) is int and
             info['Image'] == image and info['Config']['User'] == user and
             info['HostConfig']['NetworkMode'] == network and info['HostConfig']['ReadonlyRootfs'] is True and
             info['State']['Running'] is False and info['State']['OOMKilled'] is False and
             info['State']['ExitCode'] == code, 'CONTAINER_OUTCOME')
        need(not cancelled, 'CANCELLED')
        return {'exit':code,'stdout':raw,'stderr':errors,'elapsed':elapsed,'drained':True}
    finally:
        cleanup_intent(intent)


def prepare_environment(root):
    global environment, docker_tool
    docker = shutil.which('docker'); need(docker is not None, 'DOCKER_REQUIRED')
    docker = Path(docker).resolve(strict=True); descriptor(docker,MAX_HOST_TOOL); docker_tool = str(docker)
    home = root/'host-home'; home.mkdir(mode=0o700)
    config = home/'.docker'; (config/'cli-plugins').mkdir(parents=True,mode=0o700)
    original_home = Path.home()
    candidates = [original_home/'.docker/cli-plugins/docker-buildx',Path('/usr/libexec/docker/cli-plugins/docker-buildx'),
                  Path('/usr/lib/docker/cli-plugins/docker-buildx'),Path('/usr/local/lib/docker/cli-plugins/docker-buildx')]
    plugin = next((p.resolve(strict=True) for p in candidates if p.is_file()),None)
    need(plugin is not None, 'BUILDX_REQUIRED')
    plugin_raw = regular(plugin,MAX_HOST_TOOL); atomic(config/'cli-plugins/docker-buildx',plugin_raw,0o500)
    environment = {'PATH':str(docker.parent)+':/usr/bin:/bin','HOME':str(home),'DOCKER_CONFIG':str(config),'LANG':'C.UTF-8'}
    _, raw, _, _ = command(['docker','buildx','version'], 30, cap=65536)
    need(b'buildx' in raw, 'BUILDX_VERSION')
    command(['docker','info','--format','{{.ID}}'], 30, cap=65536)
    return {'docker':descriptor(docker,MAX_HOST_TOOL),'buildx':descriptor(config/'cli-plugins/docker-buildx',MAX_HOST_TOOL)}


def image_record(intent, *, cleanup=False):
    _, raw, _, _ = command(['docker','image','ls','--no-trunc','--filter','reference='+intent['tag'],
                            '--format','{{.ID}}'], cleanup=cleanup, cap=65536)
    ids = sorted(set(raw.decode('ascii').splitlines())); need(len(ids) <= 1, 'IMAGE_AMBIGUOUS')
    if not ids: return None
    image = ids[0]; need(re.fullmatch('sha256:[0-9a-f]{64}',image), 'IMAGE_ID')
    _, raw, _, _ = command(['docker','image','inspect',image], cleanup=cleanup, cap=MAX_REPORT)
    rows = strict_json(raw); need(type(rows) is list and len(rows) == 1, 'IMAGE_INSPECT')
    info = rows[0]
    need(info['Id'] == image and intent['tag'] in info['RepoTags'] and
         info['Config']['Labels'].get('org.trueid.s4.owner') == intent['owner'], 'IMAGE_IDENTITY')
    return image


def build_image(root, context, dockerfile, name):
    intent = {'tag':'trueid-s4-'+name+':'+secrets.token_hex(16),'owner':secrets.token_hex(16),
              'image':None,'acked':False,'closed':False}
    image_intents.append(intent)
    need(image_record(intent) is None, 'FRESH_IMAGE_TAG')
    iid = root/(name+'.iid')
    command(['docker','build','--platform','linux/amd64','--no-cache','--iidfile',str(iid),
             '--label','org.trueid.s4.owner='+intent['owner'],'-t',intent['tag'],'-f',str(dockerfile),str(context)],1800)
    intent['acked'] = True
    raw = regular(iid,256); image = raw.decode('ascii').strip()
    need(image_record(intent) == image and re.fullmatch('sha256:[0-9a-f]{64}',image), 'IMAGE_ID')
    intent['image'] = image
    return image


def cleanup_images():
    global cleanup_uncertain
    for intent in reversed(image_intents):
        try:
            actual = image_record(intent, cleanup=True)
            # A successful daemon query is required even when the build command failed.
            if actual is None: need(intent['acked'], 'UNACKNOWLEDGED_IMAGE_BUILD')
            if actual is not None:
                need(intent['image'] is None or intent['image'] == actual, 'IMAGE_DRIFT')
                command(['docker','rmi','-f',actual], 60, cleanup=True)
            need(image_record(intent, cleanup=True) is None, 'IMAGE_REMAINS')
            intent['closed'] = True
        except BaseException:
            cleanup_uncertain = True


def cargo_messages(raw):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_CLI and raw.endswith(b'\n'), 'CARGO_BYTES')
    lines = raw.splitlines(); need(0 < len(lines) <= 100000, 'CARGO_LINES')
    records = [strict_json(x,MAX_FILE,8192) for x in lines]
    need(all(type(x) is dict and type(x.get('reason')) is str for x in records), 'CARGO_RECORD')
    finished = [x for x in records if x['reason'] == 'build-finished']
    need(len(finished) == 1 and records[-1] is finished[0] and finished[0].get('success') is True, 'CARGO_FINISHED')
    return records


def artifact_exports(raw, *, role, source_root, target_root):
    records = cargo_messages(raw); exports = {}
    wanted = SUITES if role == 'tests' else ('web',)
    packages = set()
    for label in wanted:
        name = 'trueid-web' if label == 'web' else label
        source = source_root+('/apps/web/src/main.rs' if label == 'web' else '/tests/'+label+'.rs')
        rows = [x for x in records if x['reason'] == 'compiler-artifact' and type(x.get('target')) is dict and
                x['target'].get('name') == name and x['target'].get('kind') == (['bin'] if label == 'web' else ['test']) and
                x['target'].get('src_path') == source and type(x.get('profile')) is dict and
                x['profile'].get('test') is (label != 'web')]
        need(len(rows) == 1, 'CARGO_ARTIFACT'); row = rows[0]
        exe = row.get('executable'); pkg = row.get('package_id')
        need(type(exe) is str and Path(exe).is_absolute() and Path(exe).is_relative_to(Path(target_root)) and
             '..' not in Path(exe).parts and type(pkg) is str and 0 < len(pkg) <= 512, 'CARGO_EXECUTABLE')
        exports[label] = {'package_id':pkg,'cargo_executable':exe}; packages.add(pkg)
    need(len(packages) == 1, 'CARGO_PACKAGE')
    if role == 'tests':
        features = [x.get('features') for x in records if x['reason'] == 'compiler-artifact' and
                    type(x.get('target')) is dict and x['target'].get('name') == 'reqwest']
        need(features and any(type(x) is list and 'cookies' in x and 'rustls' in x for x in features), 'RUST_TLS_FEATURES')
    return exports


def parse_inventory(raw, *, empty=False):
    need(type(raw) is bytes and len(raw) < MAX_REPORT and (not raw or raw.endswith(b'\n')), 'INVENTORY_BYTES')
    text = raw.decode('utf-8'); found = []; count = None
    for line in text.splitlines():
        if not line: continue
        match = re.fullmatch(r'(.+): test',line)
        if match:
            value = match[1]
            need(count is None and TEST_ID.fullmatch(value) and len(value) <= 256 and value not in found, 'INVENTORY')
            found.append(value)
        else:
            match = re.fullmatch(r'([0-9]+) tests?, 0 benchmarks?',line)
            need(match is not None and count is None, 'INVENTORY'); count = int(match[1])
    need((found or empty) and (count is None or count == len(found)), 'INVENTORY')
    result = sorted(found); safe_ids(result,empty=empty); return result


ROOT_IO = r'''import hashlib,json,math,os,shutil,signal,stat,sys,time
from pathlib import Path

def need(value):
    if not value: raise RuntimeError('ROOT_PROMOTION_REJECTED')
def sha(raw): return hashlib.sha256(raw).hexdigest()
def encoded(value): return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')
def read(path, cap=16*1048576, links=False):
    path=Path(path);need(path.is_absolute() and path.resolve(strict=True)==path)
    st=path.lstat();need(stat.S_ISREG(st.st_mode) and (links or st.st_nlink==1) and 0<=st.st_size<=cap)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(fd);need((before.st_dev,before.st_ino)==(st.st_dev,st.st_ino))
        raw=b''
        while len(raw)<=cap:
            chunk=os.read(fd,min(1048576,cap+1-len(raw)))
            if not chunk:break
            raw+=chunk
        after=os.fstat(fd);need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns))
        need(len(raw)==st.st_size);return raw
    finally:os.close(fd)
def output(path,raw,mode=0o444):
    check();path=Path(path);need(path.is_relative_to(root) and not os.path.lexists(path))
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o755)
    need(path.parent.resolve(strict=True)==path.parent)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        view=memoryview(raw)
        while view:
            check();n=os.write(fd,view);need(n>0);view=view[n:]
        os.fsync(fd);os.fchmod(fd,mode)
    finally:os.close(fd)
    st=path.lstat();need(st.st_uid==st.st_gid==0 and st.st_nlink==1 and read(path,256*1048576)==raw)
def desc(path,runtime_path=None,cap=16*1048576):
    raw=read(path,cap);need(raw);return {'path':str(runtime_path or path),'sha256':sha(raw),'bytes':len(raw)}
def check():need(time.monotonic()<deadline)
def tree_map(path):
    result={};total=0
    for parent,dirs,files in os.walk(path,followlinks=False):
        check()
        for name in dirs:
            p=Path(parent)/name;need(p.resolve(strict=True)==p and stat.S_ISDIR(p.lstat().st_mode))
        for name in files:
            p=Path(parent)/name;raw=read(p);total+=len(raw);need(total<=128*1048576 and len(result)<4096)
            result[p.relative_to(path).as_posix()]={'sha256':sha(raw),'bytes':len(raw)}
    return dict(sorted(result.items()))
def remove_contents(path):
    # Work is already causally drained and all Docker users have been removed.
    count=[0]
    def walk(fd):
        for entry in os.scandir(fd):
            check();count[0]+=1;need(count[0]<=250000)
            st=entry.stat(follow_symlinks=False)
            if stat.S_ISDIR(st.st_mode):
                child=os.open(entry.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
                try:
                    now=os.fstat(child);need((now.st_dev,now.st_ino)==(st.st_dev,st.st_ino));walk(child)
                finally:os.close(child)
                os.rmdir(entry.name,dir_fd=fd)
            else:
                need(stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode));os.unlink(entry.name,dir_fd=fd)
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:walk(fd)
    finally:os.close(fd)
need(os.geteuid()==os.getegid()==0)
# Same-host absolute monotonic limit, including plan reads and blocking I/O.
deadline=float(sys.argv[2]);remaining=deadline-time.monotonic()
if not math.isfinite(deadline) or not 0<remaining<=1800:os._exit(2)
def expired(_number,_frame):os._exit(2)
signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,remaining)
os.umask(0o022)
root=Path(sys.argv[1]);need(root.is_absolute() and root.resolve(strict=True)==root)
info=root.lstat();need(stat.S_ISDIR(info.st_mode))
plan_name=sys.argv[3];need(plan_name.startswith('plan-') and plan_name.endswith('.json') and '/'not in plan_name)
plan=json.loads(read(root/'control'/plan_name,1048576));need(plan['root_identity']==[info.st_dev,info.st_ino] and info.st_uid==plan['caller_uid'])
check();mode=plan['mode'];sealed=root/'sealed';work=root/'build'
if mode=='prepare':
    need(not sealed.exists() and not work.exists());sealed.mkdir(mode=0o755);work.mkdir(mode=0o700)
    os.chown(work,1000,1000)
    for name in ('home','tmp','cargo-home','tool-export'):
        p=work/name;p.mkdir(mode=0o700);os.chown(p,1000,1000)
    need(tree_map(root/'source')==plan['source_files'])
    for rel,meta in plan['source_files'].items():
        raw=read(root/'source'/rel);need({'sha256':sha(raw),'bytes':len(raw)}==meta)
        output(sealed/'source'/rel,raw)
    need(tree_map(sealed/'source')==plan['source_files'])
    result={'status':'PASS','source_sha256':sha(encoded(plan['source_files']))}
elif mode=='tools':
    result={'status':'PASS','tools':{}}
    for name in ('cargo','rustc'):
        raw=read(work/'tool-export'/name,256*1048576);need(raw[:6]==b'\x7fELF\x02\x01')
        output(sealed/'tools'/name,raw,0o555)
        result['tools'][name]=desc(sealed/'tools'/name,plan['tool_paths'][name],256*1048576)
elif mode=='build':
    role=plan['role'];need(role in ('tests','web'))
    raw=read(root/'control'/(role+'.jsonl'),2*1048576);need(sha(raw)==plan['cargo_json_sha256'] and raw.endswith(b'\n'))
    output(sealed/'cargo'/(role+'.jsonl'),raw)
    exports={}
    for name,meta in plan['exports'].items():
        check();original=Path(meta['cargo_executable']);need(original.is_relative_to(Path(plan['target_dir'])) and '..'not in original.parts)
        source=work/original.relative_to('/work');need(source.resolve(strict=True)==source)
        st=source.lstat();need(stat.S_ISREG(st.st_mode) and st.st_uid==st.st_gid==1000 and 0<st.st_size<=256*1048576)
        aliases=0;entries=0;target=work/Path(plan['target_dir']).relative_to('/work')
        for parent,dirs,files in os.walk(target,followlinks=False):
            check()
            for leaf in files:
                entries+=1;need(entries<=200000);alias=Path(parent)/leaf;current=alias.lstat()
                if stat.S_ISREG(current.st_mode) and (current.st_dev,current.st_ino)==(st.st_dev,st.st_ino):
                    need(alias.resolve(strict=True)==alias and current.st_uid==current.st_gid==1000);aliases+=1;need(aliases<=256)
        need(aliases==st.st_nlink)
        raw=read(source,256*1048576,links=True)
        need(len(raw)>=64 and raw[:6]==b'\x7fELF\x02\x01' and raw[18:20]==b'\x3e\x00')
        output(sealed/'bin'/name,raw,0o555)
        exports[name]={'package_id':meta['package_id'],'cargo_executable':str(original),'sha256':sha(raw),'bytes':len(raw)}
    record={'schemaVersion':1,'kind':'CARGO_BUILD_CAPTURE','argv':plan['argv'],'source_root':'/src',
            'target_dir':plan['target_dir'],'source_before_sha256':plan['source_sha256'],'source_after_sha256':plan['source_sha256'],
            'exit':0,'timed_out':False,'owned_drain':True,'target_empty_at_start':True,
            'cargo_json':desc(sealed/'cargo'/(role+'.jsonl'),'/inputs/cargo/'+role+'.jsonl'),'exports':exports}
    output(sealed/'builds'/(role+'.json'),encoded(record))
    result={'status':'PASS','capture':desc(sealed/'builds'/(role+'.json'),'/inputs/builds/'+role+'.json'),'exports':exports}
elif mode=='manifest':
    need(tree_map(sealed/'source')==plan['source_files'])
    manifest={'schemaVersion':1,'source_files':plan['source_files'],
              'binaries':{k:desc(sealed/'bin'/k,'/inputs/bin/'+k,256*1048576)for k in ('web','auth_integration','rbac_matrix')},
              'runtime':plan['runtime'],'builds':{k:desc(sealed/'builds'/(k+'.json'),'/inputs/builds/'+k+'.json')for k in ('tests','web')}}
    output(sealed/'manifest.json',encoded(manifest));result={'status':'PASS','manifest':manifest,'manifest_sha256':sha(encoded(manifest))}
elif mode=='cleanup':
    for name in ('build','sealed'):
        path=root/name
        if path.exists():remove_contents(path);path.rmdir()
    result={'status':'PASS','private_data_removed':True}
else:raise RuntimeError('ROOT_MODE')
print(json.dumps(result,sort_keys=True,separators=(',',':'),allow_nan=False))
'''


TOOL_DISCOVERY = r'''set -eu
umask 077
test "$(id -u)" = 1000
test "$(id -g)" = 1000
test -z "$(id -G | tr ' ' '\n' | grep -v '^1000$' || true)"
toolchain=''
for dir in /usr/local/rustup/toolchains/*; do
  if test -x "$dir/bin/rustc"; then
    case "$("$dir/bin/rustc" --version)" in
      'rustc 1.95.0 '*) test -z "$toolchain"; toolchain="$dir" ;;
    esac
  fi
done
test -n "$toolchain"
for name in cargo rustc; do
  file="$toolchain/bin/$name"
  test "$(readlink -f "$file")" = "$file"
  test -f "$file"
  cp --reflink=never "$file" "/work/tool-export/$name"
  chmod 0500 "/work/tool-export/$name"
done
printf '%s\n%s\n' "$toolchain/bin/cargo" "$toolchain/bin/rustc"
'''


PROBE = r'''import hashlib,json,os,platform,shutil,ssl,_ssl,_sqlite3,sqlite3,stat,sys
from pathlib import Path
def need(x):
    if not x:raise RuntimeError('RUNTIME_PROBE')
def desc(path):
    p=Path(path);need(p.is_absolute() and p.resolve(strict=True)==p)
    s=p.lstat();need(stat.S_ISREG(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022 and 0<s.st_size<=256*1048576)
    r=p.read_bytes();need(len(r)==s.st_size);return {'path':str(p),'sha256':hashlib.sha256(r).hexdigest(),'bytes':len(r)}
need(os.geteuid()==os.getegid()==1000 and os.getgroups()in([], [1000]))
need(sys.version_info[:2]==(3,11)and sys.flags.isolated==1 and sys.flags.dont_write_bytecode==1 and sys.flags.optimize==0)
need(platform.system()=='Linux'and platform.machine()=='x86_64')
for key in ('HOME','TMPDIR'):
    p=Path(os.environ[key]);p.mkdir(mode=0o700,parents=True,exist_ok=True);need(p.lstat().st_uid==1000)
python=Path('/proc/self/exe').resolve(strict=True)
paths=json.loads(sys.argv[1]);need(set(paths)=={'cargo','rustc'})
info={'python':desc(python),'openssl':desc(Path(shutil.which('openssl')).resolve(strict=True)),
      'ssl_extension':desc(Path(_ssl.__file__).resolve(strict=True)),
      'sqlite_extension':desc(Path(_sqlite3.__file__).resolve(strict=True)),
      'cargo':desc(paths['cargo']),'rustc':desc(paths['rustc'])}
print(json.dumps({'status':'PASS','runtime':info,'python_version':list(sys.version_info[:3]),'openssl':ssl.OPENSSL_VERSION,
                  'sqlite':sqlite3.sqlite_version,'libc':list(platform.libc_ver()),'uid':os.geteuid(),'gid':os.getegid(),
                  'groups':os.getgroups(),'isolated':sys.flags.isolated,'dont_write_bytecode':sys.flags.dont_write_bytecode,
                  'optimize':sys.flags.optimize},sort_keys=True,separators=(',',':')))
'''


RUNTIME = r'''import ast,base64,hashlib,importlib.util,json,math,os,re,shutil,signal,socket,stat,sys,time,unittest
from pathlib import Path
cancelled=False

def need(x):
    if not x:raise RuntimeError('RUNTIME_REJECTED')
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module;spec.loader.exec_module(module);return module
def read(path,cap=1048576):
    p=Path(path);s=p.lstat();need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_uid==1000 and 0<=s.st_size<=cap)
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:raw=os.read(fd,cap+1)
    finally:os.close(fd)
    need(len(raw)==s.st_size);return raw
def stop(_number,_frame):
    global cancelled
    cancelled=True

def pins():
    pairs=[(unittest.TestSuite,'run'),(unittest.TestSuite,'__call__'),(unittest.TestCase,'run'),
           (unittest.TestCase,'__call__'),(unittest.TestCase,'_callSetUp'),(unittest.TestCase,'_callTestMethod'),
           (unittest.TestCase,'_callTearDown'),(unittest.TestLoader,'loadTestsFromModule'),
           (unittest.TestLoader,'loadTestsFromTestCase'),(unittest.TestLoader,'getTestCaseNames')]
    pairs += [(unittest.TestResult,n)for n in ('startTest','stopTest','addSuccess','addFailure','addError',
                                              'addSkip','addExpectedFailure','addUnexpectedSuccess','addSubTest')]
    return {'classes':{name:getattr(unittest,name)for name in ('TestCase','TestSuite','TestLoader','TestResult')},'members':[(owner,name,getattr(owner,name),getattr(getattr(owner,name),'__code__',None),getattr(getattr(owner,name),'__defaults__',None),getattr(getattr(owner,name),'__kwdefaults__',None))for owner,name in pairs]}
def intact(snapshot):
    return all(getattr(unittest,name)is value for name,value in snapshot['classes'].items())and all(getattr(owner,name)is value and getattr(value,'__code__',None)is code and getattr(value,'__defaults__',None)is defaults and getattr(value,'__kwdefaults__',None)==kw for owner,name,value,code,defaults,kw in snapshot['members'])
def policy(source,expected):
    # Captured locals, not policy-replaceable runtime globals, own the verdict.
    _error=RuntimeError;_getattr=getattr;_type=type;_tuple=tuple;_sorted=sorted
    _all=all;_len=len;_set=set;_isinstance=isinstance;_hasattr=hasattr;_callable=callable
    _globals=globals();_unit=unittest;_load=load
    _CASE,_SUITE,_RESULT,_LOADER=(_unit.TestCase,_unit.TestSuite,_unit.TestResult,_unit.TestLoader)
    _SUITE_RUN=_SUITE.run;_LOAD_MODULE=_LOADER.loadTestsFromModule;_CASE_ID=_CASE.id;_CASE_RUN=_CASE.run
    def stamp(fn):
        return (fn,_getattr(fn,'__code__',None),_getattr(fn,'__defaults__',None),
                _tuple(_sorted((_getattr(fn,'__kwdefaults__',None)or{}).items())))
    def same(fn,record):
        return fn is record[0] and _getattr(fn,'__code__',None)is record[1] and _getattr(fn,'__defaults__',None)is record[2] and _tuple(_sorted((_getattr(fn,'__kwdefaults__',None)or{}).items()))==record[3]
    def guard(value):
        if not value:raise _error('RUNTIME_REJECTED')
    _helpers=_tuple((name,stamp(_globals[name]))for name in ('need','intact','pins','load','stop','policy'))
    _classes=(('TestCase',_CASE),('TestSuite',_SUITE),('TestResult',_RESULT),('TestLoader',_LOADER))
    _case_names=('run','__call__','id','_callSetUp','_callTestMethod','_callTearDown','_callCleanup','doCleanups')
    _assert_names=('assertEqual','assertIn','assertIs','assertIsNone','assertIsNot','assertNotIn','assertTrue')
    _case_names+=_assert_names
    _case_dispatch=_tuple((name,_getattr(_CASE,name))for name in _case_names)
    _base={name:_getattr(_RESULT,name)for name in ('__init__','startTest','stopTest','addSuccess','addFailure','addError','addSkip','addExpectedFailure','addUnexpectedSuccess','addSubTest','wasSuccessful')}
    _core=[]
    for owner,names in ((_CASE,_case_names),(_SUITE,('run','__call__','_handleClassSetUp','_tearDownPreviousClass','_handleModuleFixture','_handleModuleTearDown')),(_LOADER,('__init__','loadTestsFromModule','loadTestsFromTestCase','getTestCaseNames')),(_RESULT,_tuple(_base))):
        _core.extend((owner,name,stamp(_getattr(owner,name)))for name in names)
    _core=_tuple(_core);_seen_stamps=();_proxy_stamps=();_leaves=()
    def verified():
        if _globals.get('unittest')is not _unit:return False
        if not _all(_getattr(_unit,name)is value for name,value in _classes):return False
        if not _all(same(_globals.get(name),record)for name,record in _helpers):return False
        if not _all(same(_getattr(owner,name),record)for owner,name,record in _core):return False
        if not _all(same(_getattr(Seen,name),record)for name,record in _seen_stamps):return False
        if not _all(Observed.__dict__.get(name)is value and same(value.fget if name=='__class__'else value,record)for name,value,record in _proxy_stamps):return False
        return _all(_type(case).__bases__==(_CASE,)and _all(_getattr(_type(case),name)is value for name,value in _case_dispatch)for case in _leaves)
    def check():
        if not verified():raise _error('RUNTIME_REJECTED')
    class Seen(_RESULT):
        def __init__(self):
            _base['__init__'](self);self.started=[];self.stopped=[];self.success=[];self.subtests=[];self.bad=0
        def startTest(self,case):
            local_check();tid=_CASE_ID(case);guard(tid in expected and tid not in self.started);self.started.append(tid);_base['startTest'](self,case);local_check()
        def stopTest(self,case):
            local_check();tid=_CASE_ID(case);guard(tid in self.started and tid not in self.stopped);self.stopped.append(tid);_base['stopTest'](self,case);local_check()
        def addSuccess(self,case):
            local_check();tid=_CASE_ID(case);guard(tid in self.started and tid not in self.success);self.success.append(tid);_base['addSuccess'](self,case);local_check()
        def addFailure(self,case,error):
            local_check();self.bad+=1;_base['addFailure'](self,case,error);local_check()
        def addError(self,case,error):
            local_check();self.bad+=1;_base['addError'](self,case,error);local_check()
        def addSkip(self,case,reason):
            local_check();self.bad+=1;_base['addSkip'](self,case,reason);local_check()
        def addExpectedFailure(self,case,error):
            local_check();self.bad+=1;_base['addExpectedFailure'](self,case,error);local_check()
        def addUnexpectedSuccess(self,case):
            local_check();self.bad+=1;_base['addUnexpectedSuccess'](self,case);local_check()
        def addSubTest(self,case,subtest,error):
            local_check();tid=_CASE_ID(case);guard(tid in self.started and tid not in self.stopped);self.subtests.append({'id':tid,'ordinal':_len(self.subtests),'success':error is None});self.bad+=error is not None;_base['addSubTest'](self,case,subtest,error);local_check()
    _seen_stamps=_tuple((name,stamp(value))for name,value in Seen.__dict__.items()if _callable(value))
    class Observed:
        def __init__(self,case):self.case=case
        @property
        def __class__(self):return _type(self.case)
        def countTestCases(self):return 1
        def __call__(self,result):
            local_check();_CASE_RUN(self.case,result);local_check()
    _proxy_stamps=_tuple((name,value,stamp(value.fget if name=='__class__'else value))for name,value in Observed.__dict__.items()if name=='__class__'or _callable(value))
    # Own closure code/defaults are checked without calling a replaceable global assertion.
    _local=(_tuple((fn,stamp(fn))for fn in (stamp,same,guard,verified,check)))
    def local_check():
        if not _all(same(fn,record)for fn,record in _local):raise _error('RUNTIME_REJECTED')
        check()
    _local_code=local_check.__code__
    tree=ast.parse(source.read_text());guard('load_tests'not in {n.name for n in tree.body if _isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))})
    module=_load('s4_policy',source)
    if local_check.__code__ is not _local_code:raise _error('RUNTIME_REJECTED')
    local_check();guard(not _hasattr(module,'load_tests'))
    loader=_LOADER();local_check();suite=_LOAD_MODULE(loader,module);local_check();guard(not loader.errors)
    ids=[];leaves=[]
    def walk(item):
        if _type(item)is _SUITE:
            for child in item:walk(child)
        else:
            guard(_isinstance(item,_CASE)and _type(item).__bases__==(_CASE,))
            guard(_all(_getattr(_type(item),name)is value for name,value in _case_dispatch))
            method=_getattr(_type(item),item._testMethodName)
            guard(not _getattr(_type(item),'__unittest_skip__',False)and not _getattr(method,'__unittest_skip__',False)and not _getattr(method,'__unittest_expecting_failure__',False))
            ids.append(_CASE_ID(item));leaves.append(item)
    walk(suite);_leaves=_tuple(leaves)
    guard(ids and _sorted(ids)==expected and _len(ids)==_len(_set(ids)));local_check()
    observer=Seen();local_check()
    # Flatten only standard discovered suites; keep standard class/module fixtures.
    flat=_SUITE([Observed(case)for case in _leaves]);local_check()
    _SUITE_RUN(flat,observer)
    if local_check.__code__ is not _local_code:raise _error('RUNTIME_REJECTED')
    local_check()
    guard(not cancelled and observer.testsRun==_len(expected)and _sorted(observer.started)==_sorted(observer.stopped)==_sorted(observer.success)==expected)
    guard(_len(observer.started)==_len(observer.stopped)==_len(observer.success)==_len(_set(expected))and not observer.failures and not observer.errors and not observer.skipped and not observer.expectedFailures and not observer.unexpectedSuccesses and observer.bad==0 and not loader.errors)
    guard(_len(observer.subtests)<=8192);local_check()
    return {'status':'PASS','method_ids':expected,'started':observer.started,'stopped':observer.stopped,'success':observer.success,
            'subtests':observer.subtests,'negative_outcomes':0,'framework_intact':True}
def owner_runner(root):
    runner=load('s4_subject_owner',Path('/src/scripts/run-live-auth-acceptance.py'))
    runner.CANCELLED=False;runner.TIMED_OUT=False
    for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP):
        def handler(_n,_f):
            runner.CANCELLED=True
            stop(_n,_f)
        signal.signal(sig,handler)
    logs=root/'logs';logs.mkdir(mode=0o700)
    return runner,runner.OwnedTree(logs)
def s2(root):
    runner,owner=owner_runner(root);result=None;drained=False;released=False
    deadline=time.monotonic()+1240
    try:
        home=root/'home';tmp=root/'tmp';home.mkdir(mode=0o700);tmp.mkdir(mode=0o700)
        env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','HOME':str(home),'TMPDIR':str(tmp),'PYTHONDONTWRITEBYTECODE':'1','PYTHONNOUSERSITE':'1','PYTHONOPTIMIZE':'0'}
        report=root/'native-report.json';manifest=json.loads(Path('/inputs/manifest.json').read_bytes())
        command=[manifest['runtime']['python']['path'],'-I','-B','/src/scripts/run-live-auth-acceptance.py',
                 '--source-root','/src','--web-binary','/inputs/bin/web','--auth-binary','/inputs/bin/auth_integration',
                 '--rbac-binary','/inputs/bin/rbac_matrix','--build-manifest','/inputs/manifest.json',
                 '--report',str(report),'--timeout','1200','--case-timeout','45']
        identity=owner.spawn(command,cwd=root,env=env,out_cap=1048576,err_cap=1048576)
        code,out,err=owner.captured(identity,deadline);drained=owner.drain(time.monotonic()+15);need(drained)
        owner.release();released=True
        raw=read(report)if report.exists()else b''
        result={'status':'PASS'if code==0 else 'FAIL','actual_exit':code,'report_base64':base64.b64encode(raw).decode(),
                'stdout_bytes':len(out),'stderr_bytes':len(err),'owned_drain':True,'private_data_removed':False}
    finally:
        if not released:
            drained=owner.drain(time.monotonic()+15)
            if drained:owner.release();released=True
        need(drained and released)
    shutil.rmtree(root);need(not root.exists()and not cancelled);result['private_data_removed']=True
    return result
def rust_tls(root):
    runner,owner=owner_runner(root);helper=load('s4_fixture',Path('/src/scripts/live_auth_fixture.py'))
    fixture=None;web=None;released=False;drained=False;result=None;deadline=time.monotonic()+180
    def run_owned(argv,*,cwd,env,deadline,output_limit):
        need(not cancelled and time.monotonic()<deadline)
        child=owner.spawn(list(argv),cwd=cwd,env=env,out_cap=output_limit,err_cap=65536)
        code,out,err=owner.captured(child,deadline);need(code==0 and len(out)<=output_limit);return out
    try:
        listener=socket.socket();listener.bind(('127.0.0.1',0));port=listener.getsockname()[1];listener.close()
        fixture=helper.prepare_case(root/'case',Path('/src'),port,run_owned=run_owned,deadline=deadline)
        web=owner.spawn(['/inputs/bin/web'],cwd=fixture.case_root,env=fixture.server_env,out_cap=1048576,err_cap=1048576)
        helper.bootstrap(fixture,deadline);public=helper.public_summary(fixture)
        need(all(public[k]is True for k in ('case_prepared','bootstrap_complete','verified_tls_ready','untrusted_ca_rejected','wrapper_sessions_revoked')))
        env=helper.test_environment(fixture)
        command=['/inputs/bin/auth_integration','--include-ignored','--exact','test_health','--test-threads=1']
        child=owner.spawn(command,cwd=fixture.case_root,env=env,out_cap=1048576,err_cap=1048576)
        positive,pout,perr=owner.captured(child,deadline);need(positive==0)
        runner.parse_libtest(pout,'test_health',len(json.loads(sys.argv[2])['auth_integration']))
        wrong=root/'wrong';wrong.mkdir(mode=0o700);cert=wrong/'ca.pem';key=wrong/'ca.key'
        penv={'PATH':'/usr/bin:/bin','HOME':str(wrong),'TMPDIR':str(wrong)}
        run_owned(['/usr/bin/openssl','req','-x509','-newkey','rsa:2048','-nodes','-sha256','-days','1','-subj','/CN=unrelated-test-ca','-keyout',str(key),'-out',str(cert)],cwd=wrong,env=penv,deadline=deadline,output_limit=65536)
        correct_hash=hashlib.sha256(Path(env['SSL_CERT_FILE']).read_bytes()).hexdigest();wrong_hash=hashlib.sha256(cert.read_bytes()).hexdigest()
        need(correct_hash!=wrong_hash and not list(Path(env['SSL_CERT_DIR']).iterdir()))
        bad=dict(env);bad['SSL_CERT_FILE']=str(cert);need({k for k in env if env[k]!=bad[k]}=={'SSL_CERT_FILE'})
        need(not owner.exited(owner.anchors[web]['ref']))
        child=owner.spawn(command,cwd=fixture.case_root,env=bad,out_cap=1048576,err_cap=1048576)
        negative,nout,nerr=owner.captured(child,deadline)
        need(type(negative)is int and 0<negative<=255 and not owner.exited(owner.anchors[web]['ref']))
        result={'status':'PASS','positive_exit':positive,'negative_exit':negative,
                'positive_stdout_base64':base64.b64encode(pout).decode(),'positive_stderr_base64':base64.b64encode(perr).decode(),
                'negative_stdout_base64':base64.b64encode(nout).decode(),'negative_stderr_base64':base64.b64encode(nerr).decode(),
                'correct_ca_sha256':correct_hash,'wrong_ca_sha256':wrong_hash,'only_CA_environment_changed':True,
                'live_web_before_and_after':True,'owned_drain':False,'private_data_removed':False}
    finally:
        drained=owner.drain(time.monotonic()+15,web)
        need(drained)
        if fixture is not None:need(helper.remove_case(fixture,drain_confirmed=True))
        owner.release();released=True
    need(released and result is not None and not cancelled);shutil.rmtree(root);need(not root.exists())
    result['owned_drain']=True;result['private_data_removed']=True;return result
need(os.geteuid()==os.getegid()==1000 and os.getgroups()in([], [1000]) and sys.version_info[:2]==(3,11)and sys.flags.isolated==1 and sys.flags.dont_write_bytecode==1 and sys.flags.optimize==0)
os.umask(0o077)
for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP):signal.signal(sig,stop)
for key in ('HOME','TMPDIR'):Path(os.environ[key]).mkdir(mode=0o700,parents=True,exist_ok=True)
mode=sys.argv[1]
if mode=='policy':result=policy(Path('/src/scripts/tests/test_live_auth_acceptance_policy.py'),json.loads(sys.argv[2]))
elif mode in ('s2','tls'):
    root=Path('/run-private')/('supervisor-'+mode);root.mkdir(mode=0o700)
    result=s2(root)if mode=='s2'else rust_tls(root)
else:raise RuntimeError('RUNTIME_MODE')
need(not cancelled);print(json.dumps(result,sort_keys=True,separators=(',',':'),allow_nan=False))
'''


def certificate_kind(raw):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_REPORT, 'TLS_DIAGNOSTICS')
    text = raw.decode('utf-8')
    need(not re.search(r'ConnectionRefused|ConnectionReset|ConnectionAborted|TimedOut|Timeout|timed out|dns error|Name or service not known',text), 'TLS_TRANSPORT')
    lines = [line for line in text.splitlines() if line.startswith('GET request failed: reqwest::Error')]
    need(len(lines) == 1, 'TLS_GET_FAILURE')
    matches = re.findall(r'(?<![A-Za-z0-9_])InvalidCertificate\((UnknownIssuer|BadSignature)\)(?![A-Za-z0-9_])',lines[0])
    need(len(matches) == 1, 'TLS_CERTIFICATE')
    return {'UnknownIssuer':'UNKNOWN_ISSUER','BadSignature':'BAD_SIGNATURE'}[matches[0]]


def policy_ids(raw):
    tree = ast.parse(raw.decode('utf-8'),feature_version=(3,11)); found = []
    need(not any(isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name == 'load_tests' for n in tree.body), 'POLICY_HOOK')
    for node in tree.body:
        if not isinstance(node,ast.ClassDef): continue
        need(not node.decorator_list and node.bases and all(isinstance(base,ast.Attribute) and
             isinstance(base.value,ast.Name) and base.value.id == 'unittest' and base.attr == 'TestCase' for base in node.bases), 'POLICY_CLASS')
        for member in node.body:
            if not isinstance(member,(ast.FunctionDef,ast.AsyncFunctionDef)): continue
            need(isinstance(member,ast.FunctionDef) and member.name not in ('run','__call__','__getattribute__','__getattr__','countTestCases','id'), 'POLICY_METHOD')
            if member.name.startswith('test_'):
                need(not member.decorator_list, 'POLICY_DECORATOR'); found.append('s4_policy.'+node.name+'.'+member.name)
            else:
                need(all(isinstance(d,ast.Name) and d.id in ('classmethod','staticmethod') for d in member.decorator_list), 'POLICY_DECORATOR')
    need(found and len(found) == len(set(found)) and len(found) <= 256, 'POLICY_IDS')
    return sorted(found)


def validate_policy(value, expected):
    closed(value, ('status','method_ids','started','stopped','success','subtests','negative_outcomes','framework_intact'))
    need(value['status'] == 'PASS' and value['method_ids'] == expected and
         all(type(value[k]) is list and sorted(value[k]) == expected and len(value[k]) == len(expected)
             for k in ('started','stopped','success')), 'POLICY_METHODS')
    exact_int(value['negative_outcomes'],0,0); need(value['framework_intact'] is True, 'POLICY_FRAMEWORK')
    need(type(value['subtests']) is list and len(value['subtests']) <= 8192, 'POLICY_SUBTESTS')
    for index, row in enumerate(value['subtests']):
        closed(row,('id','ordinal','success')); exact_int(row['ordinal'],index,index)
        need(row['id'] in expected and row['success'] is True, 'POLICY_SUBTESTS')
    return {'methods':len(expected),'subtests':len(value['subtests'])}


def root_io(root, plan, *, seconds=180, cleanup=False):
    """Narrow byte-only privilege; the exact code snapshot is a kernel argv value."""
    info = root.lstat()
    plan = dict(plan, root_identity=[info.st_dev,info.st_ino], caller_uid=info.st_uid)
    name = 'plan-'+secrets.token_hex(16)+'.json'
    atomic(root/'control'/name, canonical(plan))
    python = Path('/usr/bin/python3').resolve(strict=True)
    pinfo = python.lstat()
    need(pinfo.st_uid == 0 and not pinfo.st_mode & 0o022, 'ROOT_METADATA_PYTHON')
    descriptor(python)
    owner_seconds = budget(seconds,cleanup=cleanup)
    need(owner_seconds > 2, 'ROOT_METADATA_BUDGET')
    child_deadline = time.monotonic()+owner_seconds-1
    argv = [str(python),'-I','-B','-c',ROOT_IO,str(root),str(child_deadline),name]
    if os.geteuid() != 0:
        sudo = Path('/usr/bin/sudo').resolve(strict=True); sinfo = sudo.lstat()
        need(sinfo.st_uid == 0 and not sinfo.st_mode & 0o022, 'ROOT_METADATA_PRIVILEGE')
        argv = [str(sudo),'-n',*argv]
    _, raw, _, _ = command(argv,owner_seconds,cleanup=cleanup,cap=MAX_CLI)
    result = strict_json(raw,MAX_CLI,8192)
    need(type(result) is dict and result.get('status') == 'PASS', 'ROOT_PROMOTION')
    return result


def runtime_mounts(root, tools, *, inputs=True):
    result = [(root/'runtime-control','/control',True),(root/'sealed/source','/src',True)]
    if inputs: result.append((root/'sealed','/inputs',True))
    for key in ('cargo','rustc'):
        result.append((root/'sealed/tools'/key,tools[key]['path'],True))
    return result


def runtime_script(root, sdk, python, mode, args, tools, seconds):
    return container(sdk,[python,'-I','-B','/control/runtime.py',mode,*args],seconds=seconds,
                     mounts=runtime_mounts(root,tools),workdir='/run-private')


def observed_runtime(root, sdk, tools):
    mounts = runtime_mounts(root,tools)
    value = container(sdk,['/usr/local/bin/python','-I','-B','-c',PROBE,
                          json.dumps({k:tools[k]['path']for k in ('cargo','rustc')},separators=(',',':'))],
                      seconds=45,mounts=mounts,workdir='/run-private')
    need(value['exit'] == 0, 'RUNTIME_PROBE')
    probe = strict_json(value['stdout'])
    closed(probe,('status','runtime','python_version','openssl','sqlite','libc','uid','gid','groups',
                  'isolated','dont_write_bytecode','optimize'))
    need(type(probe['python_version']) is list and len(probe['python_version']) == 3 and all(type(x) is int and x >= 0 for x in probe['python_version']), 'RUNTIME_PYTHON')
    for key,wanted in (('uid',1000),('gid',1000),('isolated',1),('dont_write_bytecode',1),('optimize',0)): exact_int(probe[key],wanted,wanted)
    need(type(probe['groups']) is list and all(type(x) is int for x in probe['groups']), 'RUNTIME_GROUPS')
    need(probe['status'] == 'PASS' and probe['python_version'][:2] == [3,11] and
         probe['uid'] == probe['gid'] == 1000 and probe['groups'] in ([],[1000]) and
         probe['isolated'] == probe['dont_write_bytecode'] == 1 and probe['optimize'] == 0 and
         type(probe['openssl']) is str and probe['openssl'].startswith('OpenSSL ') and
         type(probe['sqlite']) is str and type(probe['libc']) is list and probe['libc'][0] == 'glibc', 'RUNTIME_ABI')
    closed(probe['runtime'],('python','openssl','ssl_extension','sqlite_extension','cargo','rustc'))
    for key, item in probe['runtime'].items():
        closed(item,('path','sha256','bytes')); hash_value(item['sha256']); exact_int(item['bytes'],1,MAX_ELF)
        need(type(item['path']) is str and Path(item['path']).is_absolute(), 'RUNTIME_PATH')
        if key in tools: need(item == tools[key], 'ACTUAL_BUILD_TOOL_BYTES_AND_PATHS')
    openssl = container(sdk,[probe['runtime']['openssl']['path'],'version'],seconds=30,mounts=mounts)
    need(openssl['exit'] == 0 and openssl['stdout'].startswith(b'OpenSSL '), 'OPENSSL_ABI')
    return probe['runtime']


def build_native(root, builder, cargo, source_files, role):
    target = '/work/'+role+'-target'
    # The fresh target is observed inside the same immutable builder before Cargo.
    test = container(builder,['/bin/sh','-c','test ! -e "$1" && test ! -L "$1"','sh',target],
                     seconds=30,mounts=[(root/'build','/work',False),(root/'sealed/source','/src',True)],workdir='/src')
    need(test['exit'] == 0, 'FRESH_TARGET')
    env = ['HOME=/work/home','TMPDIR=/work/tmp','CARGO_HOME=/work/cargo-home','CARGO_TARGET_DIR='+target,
           'CARGO_BUILD_JOBS=1','CARGO_NET_OFFLINE=true','CARGO_TERM_COLOR=never','RUSTC='+str(Path(cargo).parent/'rustc')]
    argv = [cargo,*(TEST_ARGS if role == 'tests' else WEB_ARGS)]
    before = source_map(root/'sealed/source'); need(before == source_files, 'BUILD_SOURCE_BEFORE')
    observed = container(builder,argv,seconds=1800,env=env,
                         mounts=[(root/'build','/work',False),(root/'sealed/source','/src',True)],workdir='/src',cap=MAX_CLI)
    need(observed['exit'] == 0 and observed['drained'] is True and source_map(root/'sealed/source') == before, 'BUILD_OUTCOME')
    exports = artifact_exports(observed['stdout'],role=role,source_root='/src',target_root=target)
    atomic(root/'control'/(role+'.jsonl'),observed['stdout'])
    result = root_io(root,{'mode':'build','role':role,'argv':argv,'target_dir':target,'source_sha256':digest(canonical(before)),
                          'cargo_json_sha256':digest(observed['stdout']),'exports':exports},seconds=180)
    need(result['capture']['sha256'] == descriptor(root/'sealed/builds'/(role+'.json'),root=True,readonly=True)['sha256'], 'BUILD_CAPTURE')
    return result


def independent_inventory(root, sdk, python, tools):
    found = {}; ignored = {}
    for suite in SUITES:
        for flag, dest in ((False,found),(True,ignored)):
            args = ['/inputs/bin/'+suite]
            if flag: args += ['--ignored']
            args += ['--list','--format=terse']
            actual = container(sdk,args,seconds=30,mounts=runtime_mounts(root,tools),workdir='/run-private')
            need(actual['exit'] == 0 and actual['drained'], 'INVENTORY_OUTCOME')
            dest[suite] = parse_inventory(actual['stdout'],empty=flag)
        need(set(ignored[suite]) <= set(found[suite]), 'IGNORED_SUBSET')
    need(0 < sum(map(len,found.values())) <= 256, 'INVENTORY_COUNT')
    return found, ignored


def independent_tls(root, sdk, python, tools, inventory):
    actual = runtime_script(root,sdk,python,'tls',[json.dumps(inventory,separators=(',',':'))],tools,240)
    need(actual['exit'] == 0 and actual['drained'], 'RUST_TLS_EXIT')
    value = strict_json(actual['stdout'],MAX_CLI)
    closed(value,('status','positive_exit','negative_exit','positive_stdout_base64','positive_stderr_base64',
                  'negative_stdout_base64','negative_stderr_base64','correct_ca_sha256','wrong_ca_sha256',
                  'only_CA_environment_changed','live_web_before_and_after','owned_drain','private_data_removed'))
    need(value['status'] == 'PASS', 'RUST_TLS_STATUS'); exact_int(value['positive_exit'],0,0)
    exact_int(value['negative_exit'],1,255)
    need(all(value[k] is True for k in ('only_CA_environment_changed','live_web_before_and_after','owned_drain','private_data_removed')), 'RUST_TLS_OBSERVATIONS')
    hash_value(value['correct_ca_sha256']); hash_value(value['wrong_ca_sha256'])
    need(value['correct_ca_sha256'] != value['wrong_ca_sha256'], 'RUST_DISTINCT_CA')
    decoded = {}
    for key in ('positive_stdout','positive_stderr','negative_stdout','negative_stderr'):
        text = value[key+'_base64']; need(type(text) is str and len(text) <= 1500000, 'RUST_TLS_CAPTURE')
        decoded[key] = base64.b64decode(text,validate=True); need(len(decoded[key]) <= MAX_REPORT, 'RUST_TLS_CAPTURE')
    lines = [x for x in decoded['positive_stdout'].decode('utf-8').splitlines() if x]
    need(len(lines) == 3 and lines[0] == 'running 1 test' and lines[1] == 'test test_health ... ok', 'RUST_POSITIVE_RESULT')
    match = re.fullmatch(r'test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; ([0-9]+) filtered out; finished in ([0-9]+(?:\.[0-9]+)?)s',lines[2])
    need(match is not None and int(match[1]) == len(inventory['auth_integration'])-1, 'RUST_POSITIVE_RESULT')
    kind = certificate_kind(decoded['negative_stdout']+b'\n'+decoded['negative_stderr'])
    return {'positive_exit':0,'negative_exit':value['negative_exit'],'certificate_kind':kind,
            'positive_capture_sha256':digest(decoded['positive_stdout']+decoded['positive_stderr']),
            'negative_capture_sha256':digest(decoded['negative_stdout']+decoded['negative_stderr'])}


def expected_native(root, manifest, inventory, ignored):
    source = manifest['source_files']
    return {'identities':{'source_sha256':digest(canonical(source)),
                         'helper_sha256':source[SCRIPTS[0]]['sha256'],'runner_sha256':source[SCRIPTS[1]]['sha256'],
                         'build_manifest_sha256':digest(regular(root/'sealed/manifest.json',MAX_REPORT,root=True,readonly=True)),
                         'web_sha256':manifest['binaries']['web']['sha256'],
                         'auth_sha256':manifest['binaries']['auth_integration']['sha256'],
                         'rbac_sha256':manifest['binaries']['rbac_matrix']['sha256'],
                         'runtime_sha256':digest(canonical(manifest['runtime'])),
                         'build_capture_sha256':digest(canonical(manifest['builds']))},
            'inventory':inventory,'ignored_inventory':ignored,
            'selected':[{'suite':suite,'id':tid}for suite in SUITES for tid in inventory[suite]]}


def no_host_children():
    try: os.waitid(os.P_ALL,0,os.WEXITED|os.WNOHANG|os.WNOWAIT)
    except ChildProcessError: return True
    return False


def validate_build_manifest(root, value, source_files, runtime):
    closed(value,('schemaVersion','source_files','binaries','runtime','builds'))
    exact_int(value['schemaVersion'],1,1)
    need(value['source_files'] == source_files and value['runtime'] == runtime, 'BUILD_MANIFEST')
    closed(value['binaries'],('web','auth_integration','rbac_matrix')); closed(value['builds'],('tests','web'))
    for label in ('web','auth_integration','rbac_matrix'):
        item = value['binaries'][label]; closed(item,('path','sha256','bytes'))
        actual = descriptor(root/'sealed/bin'/label,MAX_ELF,root=True,readonly=False)
        need(item == dict(actual,path='/inputs/bin/'+label), 'ELF_IDENTITY')
        st = (root/'sealed/bin'/label).lstat()
        need(stat.S_IMODE(st.st_mode) == 0o555, 'EXECUTABLE_READONLY')
    for role in ('tests','web'):
        item = value['builds'][role]; closed(item,('path','sha256','bytes'))
        raw = regular(root/'sealed/builds'/(role+'.json'),MAX_REPORT,root=True,readonly=True)
        need(item == {'path':'/inputs/builds/'+role+'.json','sha256':digest(raw),'bytes':len(raw)}, 'CAPTURE_IDENTITY')
        doc = strict_json(raw)
        closed(doc,('schemaVersion','kind','argv','source_root','target_dir','source_before_sha256','source_after_sha256',
                    'exit','timed_out','owned_drain','target_empty_at_start','cargo_json','exports'))
        exact_int(doc['schemaVersion'],1,1); exact_int(doc['exit'],0,0)
        target = '/work/'+role+'-target'
        need(doc['kind'] == 'CARGO_BUILD_CAPTURE' and doc['argv'] == [runtime['cargo']['path'],*(TEST_ARGS if role=='tests'else WEB_ARGS)] and
             doc['source_root'] == '/src' and doc['target_dir'] == target and
             doc['source_before_sha256'] == doc['source_after_sha256'] == digest(canonical(source_files)) and
             doc['timed_out'] is False and doc['owned_drain'] is True and doc['target_empty_at_start'] is True, 'CAPTURE_PROVENANCE')
        jsonl = regular(root/'sealed/cargo'/(role+'.jsonl'),MAX_CLI,root=True,readonly=True)
        need(doc['cargo_json'] == {'path':'/inputs/cargo/'+role+'.jsonl','sha256':digest(jsonl),'bytes':len(jsonl)}, 'JSONL_IDENTITY')
        exports = artifact_exports(jsonl,role=role,source_root='/src',target_root=target)
        closed(doc['exports'],exports)
        for label, source in exports.items():
            item = doc['exports'][label]; closed(item,('package_id','cargo_executable','sha256','bytes'))
            exact_int(item['bytes'],1,MAX_ELF); hash_value(item['sha256'])
            need(item['package_id'] == source['package_id'] and item['cargo_executable'] == source['cargo_executable'] and
                 item['sha256'] == value['binaries'][label]['sha256'] and item['bytes'] == value['binaries'][label]['bytes'], 'EXPORT_JOIN')
    return value


def execute(root, source, source_files):
    tools_host = prepare_environment(root)
    runtime_control=root/'runtime-control';runtime_control.mkdir(mode=0o755);runtime_control.chmod(0o755)
    atomic(runtime_control/'runtime.py',RUNTIME.encode())
    builder_file = root/'Builder.Dockerfile'
    atomic(builder_file,b'FROM rust:1.95.0-bookworm\nRUN apt-get update && apt-get install -y --no-install-recommends ca-certificates pkg-config libssl-dev binutils && rm -rf /var/lib/apt/lists/*\nWORKDIR /src\n')
    builder = build_image(root,root/'source',builder_file,'builder')
    sdk = build_image(root,root/'source',root/'source/integrations/sycope/Dockerfile','sdk')
    root_io(root,{'mode':'prepare','source_files':source_files})
    mounts = [(root/'build','/work',False),(root/'sealed/source','/src',True)]
    discovery = container(builder,['/bin/sh','-c',TOOL_DISCOVERY],seconds=45,mounts=mounts,workdir='/src')
    need(discovery['exit'] == 0, 'TOOL_DISCOVERY')
    lines = discovery['stdout'].decode('ascii').splitlines()
    need(len(lines) == 2 and all(re.fullmatch(r'/usr/local/rustup/toolchains/[A-Za-z0-9_.-]+/bin/'+name,path)
         for name,path in zip(('cargo','rustc'),lines)), 'TOOL_PATHS')
    tool_paths = dict(zip(('cargo','rustc'),lines))
    tools = root_io(root,{'mode':'tools','tool_paths':tool_paths})['tools']
    runtime = observed_runtime(root,sdk,tools)
    fetch = container(builder,[tool_paths['cargo'],'fetch','--locked'],seconds=900,network='bridge',mounts=mounts,workdir='/src',
                      env=['HOME=/work/home','TMPDIR=/work/tmp','CARGO_HOME=/work/cargo-home',
                           'CARGO_BUILD_JOBS=1','RUSTC='+tool_paths['rustc'],'CARGO_TERM_COLOR=never'])
    need(fetch['exit'] == 0 and source_map(root/'sealed/source') == source_files, 'LOCKED_FETCH')
    build_native(root,builder,tool_paths['cargo'],source_files,'tests')
    build_native(root,builder,tool_paths['cargo'],source_files,'web')
    final = root_io(root,{'mode':'manifest','source_files':source_files,'runtime':runtime})
    manifest = validate_build_manifest(root,final['manifest'],source_files,runtime)
    need(final['manifest_sha256'] == digest(regular(root/'sealed/manifest.json',MAX_REPORT,root=True,readonly=True)), 'MANIFEST_BYTES')
    inventory, ignored = independent_inventory(root,sdk,runtime['python']['path'],tools)
    methods = policy_ids(regular(root/'sealed/source'/SCRIPTS[2],MAX_FILE,root=True,readonly=True))
    policy = runtime_script(root,sdk,runtime['python']['path'],'policy',[json.dumps(methods,separators=(',',':'))],tools,180)
    need(policy['exit'] == 0 and policy['drained'], 'POLICY_EXIT')
    policy_counts = validate_policy(strict_json(policy['stdout'],MAX_CLI,8192),methods)
    tls = independent_tls(root,sdk,runtime['python']['path'],tools,inventory)
    # Reserve enough actual remaining budget for the one unchanged 1200-second invocation.
    need(work_end-time.monotonic() > 1287, 'FULL_S2_BUDGET_REQUIRED')
    subject = runtime_script(root,sdk,runtime['python']['path'],'s2',[],tools,1280)
    need(subject['exit'] == 0 and subject['drained'], 'S2_CONTAINER_EXIT')
    received = strict_json(subject['stdout'],MAX_CLI)
    closed(received,('status','actual_exit','report_base64','stdout_bytes','stderr_bytes','owned_drain','private_data_removed'))
    need(received['status'] == 'PASS' and received['owned_drain'] is True and received['private_data_removed'] is True, 'S2_SUPERVISOR')
    exact_int(received['actual_exit'],0,0); exact_int(received['stdout_bytes'],0,MAX_REPORT); exact_int(received['stderr_bytes'],0,MAX_REPORT)
    need(type(received['report_base64']) is str and len(received['report_base64']) <= 1500000, 'S2_REPORT_BYTES')
    raw = base64.b64decode(received['report_base64'],validate=True)
    expected = expected_native(root,manifest,inventory,ignored)
    accepted = validate_native_report(raw,expected=expected,actual_exit=received['actual_exit'])
    need(accepted['valid'] is True, 'NATIVE_REPORT_REJECTED')
    need(source_map(source) == source_files and source_map(root/'sealed/source') == source_files, 'FINAL_SOURCE_IDENTITY')
    need(all(descriptor(Path(item['path']),MAX_HOST_TOOL) == item for item in tools_host.values()), 'HOST_TOOL_DRIFT')
    return {'counts':dict(accepted['report']['counts'],policy_methods=policy_counts['methods'],policy_subtests=policy_counts['subtests']),
            'identities':expected['identities'],'images':{'builder':builder,'sdk':sdk},
            'tools':tools_host,'tls':tls,'native_report_sha256':digest(raw)}


class Arguments(argparse.ArgumentParser):
    def error(self, _message):
        raise Failure('INVALID_ARGUMENT')


def public_summary(accepted, failure, cleaned):
    # Exact small public DTO; no raw error, environment, file/DB/key, logs or private paths.
    result = {'schemaVersion':1,'scope':'C03_S4_CI_AUTH_PRODUCER','status':'PASS' if accepted is not None and failure is None and cleaned else 'FAIL',
              'category':'ok' if accepted is not None and failure is None and cleaned else (failure or 'CLEANUP_FAILED'),
              'counts':None,'identities':None,'images':None,'cleanup':cleaned}
    if accepted is not None:
        counts=dict(accepted['counts'],rust_tls_positive_exit=accepted['tls']['positive_exit'],rust_tls_negative_exit=accepted['tls']['negative_exit'])
        identities={'native':accepted['identities'],'native_report_sha256':accepted['native_report_sha256'],
                    'host_tools_sha256':digest(canonical(accepted['tools'])),
                    'rust_tls_proof_sha256':digest(canonical(accepted['tls']))}
        result.update(counts=counts,identities=identities,images=accepted['images'])
    need(type(result['category']) is str and re.fullmatch('[A-Z_]{1,64}|ok',result['category']), 'SAFE_CATEGORY')
    return result


def main(argv=None):
    global end_time, work_end, cancelled, cleanup_uncertain, intents, image_intents, docker_tool
    global private_capture_root, private_capture_bytes, private_capture_sequence
    cancelled=False;cleanup_uncertain=False;intents=[];image_intents=[];docker_tool=None
    private_capture_root=None;private_capture_bytes=0;private_capture_sequence=0
    parser=Arguments(description='Build and independently accept disposable native authentication tests.')
    parser.add_argument('--source-root',required=True,type=Path)
    parser.add_argument('--report',required=True,type=Path)
    parser.add_argument('--timeout',required=True,type=int)
    try:
        args=parser.parse_args(argv)
        timeout=float(args.timeout)
        need(timeout>0 and math.isfinite(timeout) and math.isfinite(time.monotonic()+timeout), 'INVALID_ARGUMENT')
        need(sys.platform=='linux' and sys.version_info>=(3,11) and os.uname().machine=='x86_64', 'LINUX_REQUIRED')
        need(args.source_root.is_absolute() and args.source_root.resolve(strict=True)==args.source_root and
             args.report.is_absolute() and args.report.parent.resolve(strict=True)==args.report.parent and
             not args.report.is_relative_to(args.source_root) and not os.path.lexists(args.report), 'INVALID_ARGUMENT')
        end_time=time.monotonic()+timeout
        work_end=end_time-min(90,max(15,timeout/10))
    except (Failure,ValueError,OverflowError,OSError):
        return 2
    root=None;accepted=None;failure=None;cleaned=False
    previous={sig:signal.getsignal(sig)for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP,signal.SIGALRM)}
    def alarm(_number,_frame):
        raise Failure('TIMEOUT')
    def terminal_alarm(_number,_frame):
        # Cleanup handlers must not swallow the absolute process deadline.
        os._exit(2)
    for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP):signal.signal(sig,cancel)
    signal.signal(signal.SIGALRM,alarm)
    signal.setitimer(signal.ITIMER_REAL,max(0.001,work_end-time.monotonic()))
    try:
        os.umask(0o077);tick()
        source_files=source_map(args.source_root)
        need(source_files[SCRIPTS[3]]['sha256']==digest(regular(Path(__file__).resolve(strict=True),MAX_FILE)), 'DRIVER_SOURCE_IDENTITY')
        temporary_parent=Path(tempfile.gettempdir()).resolve(strict=True)
        need(not temporary_parent.is_relative_to(args.source_root), 'PRIVATE_CONTEXT_OUTSIDE_SOURCE')
        root=Path(tempfile.mkdtemp(prefix='trueid-s4-',dir=temporary_parent)).resolve(strict=True)
        need(not root.is_relative_to(args.source_root), 'PRIVATE_CONTEXT_OUTSIDE_SOURCE')
        root.chmod(0o700);(root/'control').mkdir(mode=0o700)
        private_capture_root=root/'control'
        copy_source(args.source_root,root/'source',source_files)
        accepted=execute(root,args.source_root,source_files)
    except BaseException as error:
        failure=error.code if type(error)is Failure and type(error.code)is str and re.fullmatch('[A-Z_]{1,64}',error.code)else 'INTERNAL_ERROR'
    finally:
        signal.signal(signal.SIGALRM,terminal_alarm)
        remaining=end_time-time.monotonic()
        if remaining<=0:os._exit(2)
        signal.setitimer(signal.ITIMER_REAL,remaining)
        for intent in reversed(intents):
            try:cleanup_intent(intent)
            except BaseException:cleanup_uncertain=True
        cleanup_images()
        # Byte removal is permitted only after all process/container/image ownership is known.
        if root is not None and failure is None and accepted is not None and not cancelled and not cleanup_uncertain and all(x['closed']for x in intents) and no_host_children():
            try:
                if (root/'build').exists()or(root/'sealed').exists():
                    root_io(root,{'mode':'cleanup'},seconds=60,cleanup=True)
                info=root.lstat();need(stat.S_ISDIR(info.st_mode)and info.st_uid==os.geteuid()and root.resolve(strict=True)==root,'OWN_ROOT')
                shutil.rmtree(root);need(not root.exists(),'OWN_ROOT_REMAINS')
            except BaseException:cleanup_uncertain=True
        cleaned=not cleanup_uncertain and all(x['closed']for x in intents)and all(x['closed']for x in image_intents)and no_host_children()and(root is None or not root.exists())
        if cancelled:failure='CANCELLED'
        if not cleaned:failure=failure or 'CLEANUP_FAILED'
    # A late signal or the terminal deadline must make the actual process nonzero,
    # even if an atomic PASS file has already reached stable storage.
    def terminal_signal(_number,_frame):
        raise SystemExit(2)
    for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP):signal.signal(sig,terminal_signal)
    remaining=end_time-time.monotonic()
    if remaining<=0:os._exit(2)
    signal.setitimer(signal.ITIMER_REAL,remaining)
    try:
        summary=public_summary(accepted,failure,cleaned);raw=canonical(summary)
        need(len(raw)<=MAX_REPORT,'SUMMARY_CAP');atomic(args.report,raw,0o600)
        need(not cancelled and time.monotonic()<end_time,'TIMEOUT')
        # The file is the sole public artifact; stdout contains no diagnostics.
        return 0 if summary['status']=='PASS' else 1
    except (Failure,OSError,ValueError):
        return 2
    finally:
        # The absolute hard alarm remains armed until actual interpreter exit.
        pass
        # Keep terminal nonzero behavior until the interpreter actually exits.


if __name__ == '__main__':
    raise SystemExit(main())
