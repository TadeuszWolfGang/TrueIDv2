"""Strict Sycope acceptance policy: complete real runs with PASS-only outcomes."""

import unittest


# Only PASS is an accepted terminal outcome.
_TERMINAL_STATUSES = frozenset({"PASS"})


def _check_id(value, seen):
    """Validate a single identifier string, tracking duplicates."""
    if not isinstance(value, str) or not value:
        raise ValueError("inventory ids must be nonempty strings")
    if value in seen:
        raise ValueError("duplicate id in inventory: %r" % (value,))
    seen.add(value)


def _check_inventory(ids, label):
    """Validate a nonempty tuple of unique nonempty string ids."""
    if not isinstance(ids, tuple):
        raise ValueError(label + " must be a tuple")
    seen = set()
    for item in ids:
        _check_id(item, seen)
    if not seen:
        raise ValueError(label + " must not be empty")
    return seen


def suite_ids(suite: unittest.TestSuite) -> tuple[str, ...]:
    """Recursively snapshot every TestCase id in *suite*.

    Retains order and duplicates. Does not consume, run, or mutate the
    suite. Unsupported leaves raise ValueError.
    """
    if not isinstance(suite, unittest.TestSuite):
        raise ValueError("suite_ids expects a unittest.TestSuite")
    ids: list[str] = []
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            ids.extend(suite_ids(item))
        elif isinstance(item, unittest.TestCase):
            ids.append(item.id())
        else:
            raise ValueError("unsupported test leaf: %r" % (item,))
    return tuple(ids)


class AcceptanceResult(unittest.TestResult):
    """A TestResult that records per-method lifecycle and terminal events."""

    def __init__(self):
        super().__init__()
        self.started_ids: list[str] = []
        self.stopped_ids: list[str] = []
        self.terminal_events: list[tuple[str, str]] = []
        self.failing_subtests = 0

    def startTest(self, test):
        self.started_ids.append(test.id())
        super().startTest(test)

    def stopTest(self, test):
        self.stopped_ids.append(test.id())
        super().stopTest(test)

    def addSuccess(self, test):
        super().addSuccess(test)
        self.terminal_events.append(("PASS", test.id()))

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.terminal_events.append(("SKIP", test.id()))

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.terminal_events.append(("FAIL", test.id()))

    def addError(self, test, err):
        super().addError(test, err)
        self.terminal_events.append(("ERROR", test.id()))

    def addExpectedFailure(self, test, err):
        super().addExpectedFailure(test, err)
        self.terminal_events.append(("EXPECTED_FAILURE", test.id()))

    def addUnexpectedSuccess(self, test):
        super().addUnexpectedSuccess(test)
        self.terminal_events.append(("UNEXPECTED_SUCCESS", test.id()))

    def addSubTest(self, test, subtest, err):
        super().addSubTest(test, subtest, err)
        if err is not None:
            self.failing_subtests += 1


def validate_result(
    result: AcceptanceResult,
    *,
    expected_ids: tuple[str, ...],
    discovered_ids: tuple[str, ...],
    selected_ids: tuple[str, ...],
    loader_errors: tuple[str, ...] = (),
    timed_out: bool = False,
    cleanup_failed: bool = False,
) -> bool:
    """Accept complete, successful observations with no skipped methods."""
    if loader_errors or timed_out or cleanup_failed or not isinstance(result, AcceptanceResult):
        return False
    try:
        expected = _check_inventory(expected_ids, "expected_ids")
        discovered = _check_inventory(discovered_ids, "discovered_ids")
        selected = _check_inventory(selected_ids, "selected_ids")
        started = _check_inventory(tuple(result.started_ids), "started_ids")
        stopped = _check_inventory(tuple(result.stopped_ids), "stopped_ids")
        if not expected == discovered == selected == started == stopped:
            return False
        if type(result.testsRun) is not int or result.testsRun != len(expected):
            return False
        if (result.failures or result.errors or result.skipped or result.expectedFailures or
                result.unexpectedSuccesses or result.failing_subtests or result.shouldStop or
                not result.wasSuccessful()):
            return False
        events = list(result.terminal_events)
        if len(events) != len(expected):
            return False
        event_ids = []
        for status, event_id in events:
            if not isinstance(status, str) or status not in _TERMINAL_STATUSES:
                return False
            event_ids.append(event_id)
        if _check_inventory(tuple(event_ids), "terminal_ids") != expected:
            return False
    except (ValueError, TypeError, AttributeError):
        return False
    return True


# Native orchestration is deliberately appended after the exact reviewed policy.
import argparse
import ast
import datetime
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time


_N_LIVE = (
    'test_trueid_api_integration.TrueIdApiIntegrationTests.test_live_mappings_endpoint',
    'test_trueid_api_integration.TrueIdApiIntegrationTests.test_live_events_endpoint',
)
_N_PHASES = ('live_mappings', 'live_events', 'offline')
_N_ENV_KEYS = ('TRUEID_TEST_URL', 'TRUEID_TEST_API_KEY', 'REQUESTS_CA_BUNDLE')
_N_COOKIES = ('trueid_access_token', 'trueid_refresh_token', 'trueid_csrf_token')
_N_CATEGORIES = ('failures', 'errors', 'skipped', 'expectedFailures', 'unexpectedSuccesses')
_N_LOG_CAP = 1048576
_N_REPORT_CAP = 524288
_N_CORE = (unittest.TestCase.run, unittest.TestCase.id, unittest.TestLoader.loadTestsFromModule)
_N_SPAWN_DEPTH = 0
_N_PENDING_ABORT = False
_N_CLEANUP_STATE = None


class _NFailure(Exception):
    def __init__(self, code):
        self.code = code


class _NAbort(BaseException):
    pass


def _n_need(condition, code):
    if not condition:
        raise _NFailure(code)


def _n_sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _n_file(path, cap=2097152):
    info = path.lstat()
    _n_need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= cap,
            'SOURCE_METADATA')
    return path.read_bytes()


def _n_new(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)


def _n_json_write(path, value):
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')
    _n_need(len(raw) <= _N_REPORT_CAP, 'REPORT_BOUND')
    _n_new(path, raw)


def _n_pairs(pairs):
    value = {}
    for key, item in pairs:
        _n_need(key not in value, 'JSON_DUPLICATE')
        value[key] = item
    return value


def _n_json(raw):
    _n_need(type(raw) is bytes and 0 < len(raw) <= _N_REPORT_CAP, 'JSON_BOUND')
    def constant(_value):
        raise _NFailure('JSON_NONFINITE')
    try:
        text = raw.decode('utf-8', errors='strict')
        _n_need('\0' not in text and not any(0xD800 <= ord(c) <= 0xDFFF for c in text), 'JSON_TEXT')
        value = json.loads(text, object_pairs_hook=_n_pairs, parse_constant=constant)
    except (UnicodeError, ValueError, RecursionError):
        raise _NFailure('JSON_INVALID') from None
    def walk(item, depth):
        _n_need(depth <= 16, 'JSON_DEPTH')
        if isinstance(item, dict):
            for key, child in item.items():
                walk(key, depth + 1)
                walk(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                walk(child, depth + 1)
        elif isinstance(item, str):
            _n_need('\0' not in item and not any(0xD800 <= ord(c) <= 0xDFFF for c in item), 'JSON_TEXT')
    walk(value, 0)
    return value


def _n_private(path):
    info = path.lstat()
    return (stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 1000 and
            stat.S_IMODE(info.st_mode) == 0o700 and path.resolve() == path)


def _n_mkdir(path):
    path.mkdir(mode=0o700)
    _n_need(_n_private(path), 'PRIVATE_DIRECTORY')


def _n_no_dotenv(path):
    for directory in (path, *path.parents):
        _n_need(not (directory / '.env').exists() and not (directory / '.env').is_symlink(), 'DOTENV')


def _n_runtime():
    _n_need(os.getuid() == os.getgid() == 1000 and sys.version_info[:2] == (3, 11) and
            sys.flags.isolated and sys.dont_write_bytecode and sys.flags.optimize == 0 and __debug__,
            'ISOLATED_RUNTIME')


def _n_sources(root):
    _n_need(root.is_absolute() and root.resolve() == root, 'SOURCE_ROOT')
    sdk = root / 'sycope'
    tests = root / 'integrations/sycope/tests'
    _n_need(sdk.is_dir() and tests.is_dir() and not sdk.is_symlink() and not tests.is_symlink(),
            'SOURCE_LAYOUT')
    paths = sorted(sdk.glob('*.py')) + [root / 'integrations/sycope/trueid_api.py',
                                      root / 'integrations/sycope/trueid_sync.py'] + sorted(tests.glob('test_*.py'))
    _n_need(3 <= len(paths) <= 128, 'SOURCE_CLOSURE')
    result = {}
    total = 0
    for path in paths:
        relative = path.relative_to(root).as_posix()
        _n_need(path.resolve() == path and relative not in result, 'SOURCE_ALIAS')
        raw = _n_file(path)
        raw.decode('utf-8', errors='strict')
        total += len(raw)
        _n_need(total <= 2097152, 'SOURCE_BOUND')
        result[relative] = _n_sha(raw)
    return result


def _n_tree(path):
    _n_need(path.is_dir() and path.resolve() == path, 'PUBLIC_RUNTIME_DIRECTORY')
    values = {}
    total = 0
    for item in sorted(path.rglob('*')):
        _n_need(not item.is_symlink(), 'PUBLIC_RUNTIME_LINK')
        if item.is_file():
            info = item.lstat()
            _n_need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 67108864,
                    'PUBLIC_RUNTIME_METADATA')
            raw = item.read_bytes()
            total += len(raw)
            _n_need(len(values) < 4096 and total <= 268435456, 'PUBLIC_RUNTIME_BOUND')
            values[item.relative_to(path).as_posix()] = _n_sha(raw)
    _n_need(values, 'PUBLIC_RUNTIME_EMPTY')
    return _n_sha(json.dumps(values, sort_keys=True, separators=(',', ':')).encode())


def _n_ast_inventory(root, manifest):
    ids = []
    for relative in sorted(manifest):
        if not relative.startswith('integrations/sycope/tests/test_'):
            continue
        tree = ast.parse((root / relative).read_text(encoding='utf-8'))
        module = Path(relative).stem
        _n_need(not any(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == 'load_tests'
                        for n in tree.body), 'DISCOVERY_HOOK')
        for node in tree.body:
            if not isinstance(node, ast.ClassDef):
                continue
            methods = [n for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                       and n.name.startswith('test')]
            if not methods:
                continue
            _n_need(len(node.bases) == 1 and isinstance(node.bases[0], ast.Attribute) and
                    isinstance(node.bases[0].value, ast.Name) and node.bases[0].value.id == 'unittest' and
                    node.bases[0].attr == 'TestCase', 'UNSUPPORTED_TEST_CLASS')
            for method in methods:
                _n_need(isinstance(method, ast.FunctionDef) and method.name.startswith('test_'),
                        'UNSUPPORTED_TEST_METHOD')
                ids.append(module + '.' + node.name + '.' + method.name)
    _n_need(ids and len(ids) == len(set(ids)) and all(value in ids for value in _N_LIVE), 'AST_INVENTORY')
    integration = {value for value in ids if value.startswith('test_trueid_api_integration.')}
    _n_need(integration == set(_N_LIVE), 'UNSUPPORTED_LIVE_INVENTORY')
    return tuple(sorted(ids))


def _n_copy(root, destination, manifest):
    _n_mkdir(destination)
    for relative, expected in manifest.items():
        target = destination / relative
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        raw = _n_file(root / relative)
        _n_need(_n_sha(raw) == expected, 'SOURCE_CHANGED')
        _n_new(target, raw)
    _n_need(_n_sources(destination) == manifest, 'COPY_HASH')


def _n_import_paths(copy_root):
    prefixes = (Path(sys.prefix).resolve(), Path(sys.base_prefix).resolve())
    for value in sys.path:
        _n_need(value and any(Path(value).resolve().is_relative_to(prefix) for prefix in prefixes),
                'EXTERNAL_IMPORT_ROOT')
    sys.path[:0] = [str(copy_root), str(copy_root / 'integrations/sycope'),
                   str(copy_root / 'integrations/sycope/tests')]


def _n_origins(copy_root, source_root, manifest):
    test_names = {Path(relative).stem for relative in manifest if '/tests/' in relative}
    for name, module in tuple(sys.modules.items()):
        filename = getattr(module, '__file__', None)
        if not filename:
            continue
        path = Path(filename).resolve()
        if name == '__main__' and path == Path(__file__).resolve():
            continue
        owned = path.is_relative_to(copy_root)
        if owned:
            _n_need(path.relative_to(copy_root).as_posix() in manifest, 'UNKNOWN_PROJECT_IMPORT')
        if name.split('.')[0] in {'sycope', 'trueid_api', 'trueid_sync'} | test_names:
            _n_need(owned, 'PROJECT_IMPORT_ESCAPE')
        _n_need(not path.is_relative_to(source_root), 'CANONICAL_PROJECT_IMPORT')
    requests_module = sys.modules.get('requests')
    _n_need(requests_module is not None and not Path(requests_module.__file__).resolve().is_relative_to(copy_root),
            'FROZEN_REQUESTS_ORIGIN')


def _n_discover(copy_root, expected):
    loader = unittest.TestLoader()
    directory = copy_root / 'integrations/sycope/tests'
    suite = loader.discover(str(directory), pattern='test_*.py', top_level_dir=str(directory))
    leaves = []
    def visit(item, depth=0):
        _n_need(depth <= 16 and len(leaves) <= 10000, 'DISCOVERY_BOUND')
        if type(item) is unittest.TestSuite:
            for child in item:
                visit(child, depth + 1)
        else:
            _n_need(isinstance(item, unittest.TestCase) and type(item).__bases__ == (unittest.TestCase,) and
                    type(item).run is unittest.TestCase.run and type(item).id is unittest.TestCase.id,
                    'UNSUPPORTED_DISCOVERED_CASE')
            leaves.append(item)
    visit(suite)
    ids = tuple(sorted(unittest.TestCase.id(case) for case in leaves))
    _n_need(not loader.errors and ids == expected and len(ids) == len(set(ids)), 'AST_DISCOVERY_DISAGREEMENT')
    for module_name in {value.split('.')[0] for value in ids}:
        _n_need('load_tests' not in vars(sys.modules[module_name]), 'DISCOVERY_HOOK')
    return leaves, ids, len(loader.errors)


def _n_remaining(deadline, ceiling=5.0):
    left = deadline - time.monotonic()
    _n_need(left > 0, 'DEADLINE')
    return min(left, ceiling)


def _n_arm(state, deadline):
    global _N_CLEANUP_STATE
    _N_CLEANUP_STATE = None
    previous = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM, signal.SIGALRM)}
    _n_need(not (signal.pthread_sigmask(signal.SIG_BLOCK, set()) & set(previous)), 'BLOCKED_RUNTIME_SIGNALS')
    def handler(number, _frame):
        global _N_PENDING_ABORT
        target = _N_CLEANUP_STATE if _N_CLEANUP_STATE is not None else state
        target['timed_out'] |= number == signal.SIGALRM
        target['category'] = 'DEADLINE' if number == signal.SIGALRM else 'INTERRUPTED'
        if _N_CLEANUP_STATE is not None:
            return
        if _N_SPAWN_DEPTH:
            _N_PENDING_ABORT = True
            return
        raise _NAbort()
    for number in previous:
        signal.signal(number, handler)
    signal.setitimer(signal.ITIMER_REAL, _n_remaining(deadline, 86400.0))
    return previous


def _n_cleanup_signals(state):
    global _N_CLEANUP_STATE
    # Retain the armed, stateful handler: record cancellation without interrupting cleanup.
    _N_CLEANUP_STATE = state
    signal.setitimer(signal.ITIMER_REAL, 0)


def _n_restore_signals(previous):
    global _N_CLEANUP_STATE
    signal.setitimer(signal.ITIMER_REAL, 0)
    for number, handler in previous.items():
        signal.signal(number, handler)
    _N_CLEANUP_STATE = None


def _n_group_exists(group):
    try:
        os.killpg(group, 0)
        return True
    except ProcessLookupError:
        return False


class _NChild:
    """Own one new process group and drain its private, bounded diagnostics."""
    def __init__(self, argv, environment, cwd, log_path, owners, native=False):
        global _N_SPAWN_DEPTH, _N_PENDING_ABORT
        self.truncated = False
        self.drain_failed = False
        self.escalated = False
        self.native = native
        self.log_path = log_path
        self.log = os.fdopen(os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb')
        # Defer our Python handler, not the OS signal mask inherited across exec.
        _N_SPAWN_DEPTH += 1
        try:
            self.process = subprocess.Popen(argv, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
            owners.append(self)
            self.thread = threading.Thread(target=self._drain, daemon=True)
            self.thread.start()
        except BaseException:
            self.log.close()
            raise
        finally:
            _N_SPAWN_DEPTH -= 1
            if not _N_SPAWN_DEPTH and _N_PENDING_ABORT:
                _N_PENDING_ABORT = False
                raise _NAbort()

    def _drain(self):
        retained = 0
        try:
            while True:
                chunk = self.process.stdout.read(16384)
                if not chunk:
                    break
                room = max(0, _N_LOG_CAP - retained)
                if len(chunk) > room:
                    self.truncated = True
                try:
                    self.log.write(chunk[:room])
                    retained += min(room, len(chunk))
                except OSError:
                    self.drain_failed = True
        except BaseException:
            self.drain_failed = True
        finally:
            self.process.stdout.close()
            self.log.close()

    def wait(self, timeout):
        code = self.process.wait(timeout=timeout)
        self.thread.join(timeout=2)
        _n_need(not self.thread.is_alive() and not self.truncated and not self.drain_failed, 'DIAGNOSTIC_BOUND')
        return code

    def stop(self, native=False):
        initial = signal.SIGINT if native else signal.SIGTERM
        grace = 15.0 if native else 30.0
        escalated = False
        if _n_group_exists(self.process.pid):
            os.killpg(self.process.pid, initial)
        until = time.monotonic() + grace
        while _n_group_exists(self.process.pid) and time.monotonic() < until:
            self.process.poll()
            time.sleep(0.05)
        if _n_group_exists(self.process.pid):
            escalated = True
            self.escalated = True
            os.killpg(self.process.pid, signal.SIGTERM)
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
            if _n_group_exists(self.process.pid):
                os.killpg(self.process.pid, signal.SIGKILL)
        try:
            self.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            return False
        self.thread.join(timeout=2)
        return (not escalated and not _n_group_exists(self.process.pid) and not self.thread.is_alive() and
                not self.truncated and not self.drain_failed and (not native or self.process.returncode == 0))


def _n_tool(argv, environment, cwd, owners, deadline, number):
    child = _NChild(argv, environment, str(cwd), cwd / ('tool-%d.log' % number), owners)
    try:
        code = child.wait(_n_remaining(deadline, 15))
    except subprocess.TimeoutExpired:
        raise _NFailure('OPENSSL_TIMEOUT') from None
    _n_need(code == 0 and not _n_group_exists(child.process.pid), 'OPENSSL_FAILED')
    owners.remove(child)


def _n_base_env(home, tmp):
    return {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'TZ': 'UTC',
            'HOME': str(home), 'TMPDIR': str(tmp), 'PYTHONDONTWRITEBYTECODE': '1',
            'PYTHONNOUSERSITE': '1', 'PYTHONOPTIMIZE': '0'}


def _n_certificates(case, openssl, environment, owners, deadline):
    ca = case / 'ca.crt'
    cakey = case / 'ca.key'
    cert = case / 'leaf.crt'
    key = case / 'leaf.key'
    csr = case / 'leaf.csr'
    ext = case / 'leaf.ext'
    _n_new(ext, b'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n')
    commands = [
        [openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', '1',
         '-subj', '/CN=C01-private-CA', '-keyout', str(cakey), '-out', str(ca),
         '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign'],
        [openssl, 'req', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-subj', '/CN=127.0.0.1',
         '-keyout', str(key), '-out', str(csr)],
        [openssl, 'x509', '-req', '-sha256', '-days', '1', '-in', str(csr), '-CA', str(ca),
         '-CAkey', str(cakey), '-CAcreateserial', '-CAserial', str(case / 'ca.srl'),
         '-extfile', str(ext), '-out', str(cert)],
    ]
    for number, command in enumerate(commands):
        _n_tool(command, environment, case, owners, deadline, number)
    for path in (ca, cakey, cert, key, csr, ext, case / 'ca.srl'):
        _n_need(stat.S_IMODE(path.stat().st_mode) == 0o600, 'CERTIFICATE_MODE')
    return ca, cert, key


def _n_listener(port):
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=0.25):
            return True
    except ConnectionRefusedError:
        return False
    except OSError:
        raise _NFailure('LISTENER_PROBE') from None


def _n_health(child, port, ca, deadline):
    readiness = min(deadline, time.monotonic() + 30)
    while time.monotonic() < readiness:
        _n_need(child.process.poll() is None, 'NATIVE_EARLY_EXIT')
        connection = http.client.HTTPSConnection('127.0.0.1', port,
                    context=ssl.create_default_context(cafile=str(ca)), timeout=_n_remaining(readiness, 2))
        try:
            connection.request('GET', '/health')
            response = connection.getresponse()
            if response.status == 200:
                _n_need(response.read(1) == b'', 'HEALTH_BODY')
                break
        except (OSError, http.client.HTTPException):
            pass
        finally:
            connection.close()
        time.sleep(min(0.1, _n_remaining(readiness, 0.1)))
    else:
        raise _NFailure('HTTPS_READINESS')
    untrusted = http.client.HTTPSConnection('127.0.0.1', port,
                    context=ssl.create_default_context(), timeout=_n_remaining(deadline, 2))
    try:
        untrusted.request('GET', '/health')
        untrusted.getresponse()
    except ssl.SSLCertVerificationError:
        return
    finally:
        untrusted.close()
    raise _NFailure('UNTRUSTED_TLS_ACCEPTED')


def _n_session(ca, sessions):
    import requests
    session = requests.Session()
    sessions.append(session)
    session.trust_env = False
    session.verify = str(ca)
    return session


def _n_request(session, method, url, deadline, expected, **kwargs):
    import requests
    limit = _n_remaining(deadline, 5)
    try:
        with session.request(method, url, timeout=(min(limit, 3), limit), allow_redirects=False,
                             stream=True, **kwargs) as response:
            _n_need(response.status_code == expected, 'HTTP_STATUS')
            raw = bytearray()
            for chunk in response.iter_content(4096):
                _n_remaining(deadline)
                raw.extend(chunk)
                _n_need(len(raw) <= 65536, 'HTTP_BODY_BOUND')
            return bytes(raw)
    except requests.Timeout:
        raise _NFailure('REQUEST_TIMEOUT') from None


def _n_auth(body, force):
    value = _n_json(body)
    _n_need(isinstance(value, dict) and isinstance(value.get('user'), dict) and
            value['user'].get('role') == 'Admin' and value.get('force_password_change') is force,
            'ADMIN_AUTH_SCHEMA')
    return value


def _n_cookie_values(session):
    values = {name: session.cookies.get(name) for name in _N_COOKIES}
    _n_need(all(type(value) is str and value for value in values.values()), 'AUTH_COOKIES')
    return values


def _n_bootstrap(port, ca, password, sessions, deadline):
    base = 'https://127.0.0.1:%d' % port
    admin = _n_session(ca, sessions)
    login = _n_auth(_n_request(admin, 'POST', base + '/api/auth/login', deadline, 200,
                             json={'username': 'admin', 'password': password}), True)
    _n_need(login.get('requires_2fa') is False, 'AUTH_2FA')
    before = _n_cookie_values(admin)
    changed = 'Aa1!' + secrets.token_urlsafe(24)
    _n_need(changed != password, 'PASSWORD_FRESHNESS')
    body = _n_request(admin, 'POST', base + '/api/auth/change-password', deadline, 200,
                      json={'current_password': password, 'new_password': changed},
                      headers={'X-CSRF-Token': before['trueid_csrf_token']})
    _n_need(body == b'', 'PASSWORD_RESPONSE_BODY')
    after = _n_cookie_values(admin)
    _n_need(all(after[name] != before[name] for name in _N_COOKIES), 'COOKIE_ROTATION')
    _n_auth(_n_request(admin, 'GET', base + '/api/auth/me', deadline, 200), False)
    fresh = _n_session(ca, sessions)
    fresh_login = _n_auth(_n_request(fresh, 'POST', base + '/api/auth/login', deadline, 200,
                                   json={'username': 'admin', 'password': changed}), False)
    _n_need(fresh_login.get('requires_2fa') is False, 'AUTH_2FA')
    cookies = _n_cookie_values(fresh)
    description = 'c01-' + secrets.token_hex(16)
    key_body = _n_json(_n_request(fresh, 'POST', base + '/api/v1/api-keys', deadline, 201,
                      json={'description': description, 'role': 'Viewer', 'expires_in_days': 1},
                      headers={'X-CSRF-Token': cookies['trueid_csrf_token']}))
    _n_need(isinstance(key_body, dict) and isinstance(key_body.get('record'), dict) and
            type(key_body.get('key')) is str and bool(key_body['key']) and
            type(key_body.get('notice')) is str, 'KEY_SCHEMA')
    record = key_body['record']
    _n_need(record.get('role') == 'Viewer' and record.get('is_active') is True and
            record.get('description') == description and type(record.get('expires_at')) is str, 'KEY_RECORD')
    try:
        expiry = datetime.datetime.fromisoformat(record['expires_at'].replace('Z', '+00:00'))
    except ValueError:
        raise _NFailure('KEY_EXPIRY') from None
    _n_need(expiry.tzinfo is not None and expiry.utcoffset() == datetime.timedelta(0) and
            expiry > datetime.datetime.now(datetime.timezone.utc), 'KEY_EXPIRY')
    anonymous = _n_session(ca, sessions)
    _n_need(not anonymous.cookies, 'ANONYMOUS_COOKIES')
    for path in ('/api/v1/mappings', '/api/v1/events?since=0'):
        _n_request(anonymous, 'GET', base + path, deadline, 401)
    return base, key_body['key']


def _n_native(context, case, owners, sessions, state):
    _n_mkdir(case)
    native_tmp = case / 'tmp'
    _n_mkdir(native_tmp)
    _n_no_dotenv(case)
    environment = _n_base_env(Path(context['home']), native_tmp)
    ca, cert, key = _n_certificates(case, context['openssl'], environment, owners, context['deadline'])
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    _n_need(not _n_listener(port), 'UNRELATED_LISTENER')
    database = case / 'fixture.db'
    _n_new(database, b'')
    password = 'Aa1!' + secrets.token_urlsafe(24)
    environment.update({'TRUEID_DEV_MODE': 'false', 'HTTP_BIND': '127.0.0.1:%d' % port,
        'TRUSTED_PROXIES': '', 'JWT_SECRET': secrets.token_urlsafe(32),
        'ENGINE_SERVICE_TOKEN': secrets.token_urlsafe(32), 'CONFIG_ENCRYPTION_KEY': secrets.token_hex(32),
        'DATABASE_URL': 'sqlite://' + str(database) + '?mode=rwc', 'TRUEID_ADMIN_USER': 'admin',
        'TRUEID_ADMIN_PASS': password, 'TLS_CERT': str(cert), 'TLS_KEY': str(key),
        'TRUEID_MIGRATIONS_DIR': context['migrations'], 'ASSETS_DIR': context['assets'],
        'ENGINE_API_URL': 'http://127.0.0.1:9'})
    child = _NChild([context['web_binary']], environment, str(case), case / 'native.log', owners, native=True)
    state['native'] = child
    state['native_pid'] = child.process.pid
    state['port'] = port
    _n_health(child, port, ca, context['deadline'])
    state['tls_ok'] = True
    base, api_key = _n_bootstrap(port, ca, password, sessions, context['deadline'])
    state['auth_ok'] = state['expiry_ok'] = True
    state['certificate_sha256'] = _n_sha(_n_file(cert))
    os.environ['TRUEID_TEST_URL'] = base
    os.environ['TRUEID_TEST_API_KEY'] = api_key
    os.environ['REQUESTS_CA_BUNDLE'] = str(ca)


def _n_observations(result, expected):
    def safe_id(value):
        return value if value in expected else 'NON_METHOD_EVENT'
    def identity(case):
        if type(case) is str:
            return safe_id(case)
        value = unittest.TestCase.id(case) if isinstance(case, unittest.TestCase) else None
        return safe_id(value)
    observations = {
        'tests_run': result.testsRun, 'started_ids': [safe_id(value) for value in result.started_ids],
        'stopped_ids': [safe_id(value) for value in result.stopped_ids],
        'terminal_events': [(status, safe_id(value)) for status, value in result.terminal_events],
        'failing_subtests': result.failing_subtests, 'should_stop': result.shouldStop,
    }
    for name in _N_CATEGORIES:
        values = getattr(result, name)
        cases = values if name == 'unexpectedSuccesses' else [
            value if type(value) is str else value[0] for value in values]
        observations[name] = [identity(case) for case in cases]
    return observations


def _n_worker(context_path):
    _n_runtime()
    os.umask(0o077)
    context = _n_json(_n_file(context_path, _N_REPORT_CAP))
    root = Path(context['worker_root'])
    _n_need(_n_private(root) and context_path.parent == root, 'WORKER_CONTEXT')
    home, tmp = Path(context['home']), Path(context['tmp'])
    _n_need(_n_private(home) and _n_private(tmp) and os.environ == _n_base_env(home, tmp), 'WORKER_ENVIRONMENT')
    _n_need(_n_sha(Path(sys.executable).read_bytes()) == context['runtime_hashes']['python'] and
            _n_sha(Path(__file__).read_bytes()) == context['runtime_hashes']['runner'], 'WORKER_RUNTIME_HASH')
    worker_started = time.monotonic()
    state = {'phase': context['phase'], 'stage': 'START', 'category': None, 'timed_out': False,
             'cleanup_ok': True, 'tls_ok': False, 'auth_ok': False, 'expiry_ok': False,
             'source_ok': False, 'origins_ok': False, 'certificate_sha256': None,
             'native_pid': None, 'native_exit': None, 'native_escalated': False, 'loader_errors': None,
             'retained_private_work': False}
    owners, sessions = [], []
    source = Path(context['source_root'])
    copy_root = root / 'sdk'
    case = root / 'case'
    result = None
    discovered, selected = (), ()
    previous = _n_arm(state, context['deadline'])
    try:
        _n_copy(source, copy_root, context['manifest'])
        _n_need(_n_ast_inventory(copy_root, context['manifest']) == tuple(context['expected']), 'COPIED_AST')
        _n_import_paths(copy_root)
        if context['phase'] != 'offline':
            state['stage'] = 'NATIVE_BOOTSTRAP'
            _n_native(context, case, owners, sessions, state)
        else:
            _n_need(all(name not in os.environ for name in _N_ENV_KEYS), 'OFFLINE_ENVIRONMENT')
        expected_environment = dict(os.environ)
        state['stage'] = 'DISCOVERY'
        leaves, discovered, state['loader_errors'] = _n_discover(copy_root, tuple(context['expected']))
        _n_origins(copy_root, source, context['manifest'])
        state['origins_ok'] = True
        wanted = ({_N_LIVE[0]} if context['phase'] == 'live_mappings' else
                  {_N_LIVE[1]} if context['phase'] == 'live_events' else set(discovered) - set(_N_LIVE))
        cases = [case_object for case_object in leaves if unittest.TestCase.id(case_object) in wanted]
        selected = tuple(unittest.TestCase.id(case_object) for case_object in cases)
        _n_need(set(selected) == wanted and len(selected) == len(wanted) and wanted, 'SELECTED_INVENTORY')
        state['stage'] = 'TESTS'
        result = AcceptanceResult()
        result.startTestRun()
        try:
            unittest.TestSuite(cases).run(result)
        finally:
            result.stopTestRun()
        _n_need((unittest.TestCase.run, unittest.TestCase.id, unittest.TestLoader.loadTestsFromModule) == _N_CORE,
                'UNITTEST_CHANGED')
        _n_remaining(context['deadline'])
        if state.get('native') is not None:
            _n_need(state['native'].process.poll() is None, 'NATIVE_EARLY_EXIT')
        _n_origins(copy_root, source, context['manifest'])
        _n_need(_n_sources(copy_root) == context['manifest'] and _n_sources(source) == context['manifest'],
                'POST_TEST_SOURCE_HASH')
        _n_need(dict(os.environ) == expected_environment, 'WORKER_ENVIRONMENT_CHANGED')
        state['source_ok'] = True
        state['stage'] = 'OBSERVED'
    except _NFailure as error:
        state['category'] = error.code
        state['timed_out'] |= error.code in {'DEADLINE', 'OPENSSL_TIMEOUT', 'REQUEST_TIMEOUT', 'HTTPS_READINESS'}
    except _NAbort:
        pass
    except BaseException:
        state['category'] = 'WORKER_STAGE_FAILED'
    finally:
        _n_cleanup_signals(state)
        for name in _N_ENV_KEYS:
            os.environ.pop(name, None)
        for session in reversed(sessions):
            try:
                session.close()
            except BaseException:
                state['cleanup_ok'] = False
        if state.get('native') is None:
            for child in owners:
                if child.native:
                    state['native'] = child
                    state['native_pid'] = child.process.pid
        for child in reversed(owners):
            try:
                state['cleanup_ok'] &= child.stop(native=child.native)
            except BaseException:
                state['cleanup_ok'] = False
        if state.get('native') is not None:
            state['native_exit'] = state['native'].process.returncode
            state['native_escalated'] = state['native'].escalated
        if 'port' in state:
            try:
                state['cleanup_ok'] &= not _n_listener(state['port'])
            except BaseException:
                state['cleanup_ok'] = False
        try:
            groups_gone = all(not _n_group_exists(child.process.pid) for child in owners)
        except BaseException:
            groups_gone = False
        if groups_gone:
            for owned in (case, copy_root):
                if owned.exists():
                    try:
                        shutil.rmtree(owned)
                        state['cleanup_ok'] &= not owned.exists()
                    except BaseException:
                        state['cleanup_ok'] = False
        else:
            state['cleanup_ok'] = False
            state['retained_private_work'] = True
        _n_restore_signals(previous)
    observation = _n_observations(result, tuple(context['expected'])) if result is not None else None
    okay = (state['category'] is None and state['cleanup_ok'] and state['source_ok'] and state['origins_ok'] and
            result is not None and validate_result(result, expected_ids=tuple(sorted(selected)),
                discovered_ids=tuple(sorted(selected)), selected_ids=selected, timed_out=state['timed_out']))
    if context['phase'] != 'offline':
        okay &= state['tls_ok'] and state['auth_ok'] and state['expiry_ok']
    safe_state = {key: value for key, value in state.items() if key not in {'native', 'port'}}
    safe_state['elapsed_seconds'] = round(time.monotonic() - worker_started, 3)
    payload = {'state': safe_state, 'inventory': list(discovered), 'selected_ids': list(selected),
               'observations': observation, 'runtime_hashes': context['runtime_hashes'], 'complete': bool(okay)}
    _n_json_write(root / 'result.json', payload)
    return 0 if okay else 1


def _n_admit_observation(payload, context):
    _n_need(type(payload) is dict and set(payload) == {'state', 'inventory', 'selected_ids', 'observations',
                                                    'runtime_hashes', 'complete'}, 'WORKER_REPORT_SCHEMA')
    _n_need(payload['runtime_hashes'] == context['runtime_hashes'] and type(payload['complete']) is bool and
            payload['inventory'] in ([], context['expected']), 'WORKER_REPORT_IDENTITY')
    state = payload['state']
    _n_need(type(state) is dict and set(state) == {'phase', 'stage', 'category', 'timed_out', 'cleanup_ok',
            'tls_ok', 'auth_ok', 'expiry_ok', 'source_ok', 'origins_ok', 'certificate_sha256',
            'native_pid', 'native_exit', 'native_escalated', 'loader_errors', 'elapsed_seconds',
            'retained_private_work'},
            'WORKER_STATE_SCHEMA')
    _n_need(state['phase'] == context['phase'] and state['stage'] in
            {'START', 'NATIVE_BOOTSTRAP', 'DISCOVERY', 'TESTS', 'OBSERVED'}, 'WORKER_REPORT_STATE')
    category = state['category']
    _n_need(category is None or (type(category) is str and 0 < len(category) <= 64 and
            all(character in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789' for character in category)), 'SAFE_CATEGORY')
    for key in ('timed_out', 'cleanup_ok', 'tls_ok', 'auth_ok', 'expiry_ok', 'source_ok',
                'origins_ok', 'native_escalated', 'retained_private_work'):
        _n_need(type(state[key]) is bool, 'WORKER_STATE_TYPE')
    _n_need(state['loader_errors'] is None or
            (type(state['loader_errors']) is int and 0 <= state['loader_errors'] <= 10000), 'LOADER_COUNTER')
    _n_need(type(state['elapsed_seconds']) in (float, int) and
            0 <= state['elapsed_seconds'] <= 7200, 'ELAPSED_BOUND')
    for key in ('native_pid', 'native_exit'):
        _n_need(state[key] is None or type(state[key]) is int, 'NATIVE_COUNTER')
    cert = state['certificate_sha256']
    _n_need(cert is None or (type(cert) is str and len(cert) == 64 and
            all(c in '0123456789abcdef' for c in cert)), 'CERTIFICATE_HASH')
    if context['phase'] == 'offline':
        _n_need(state['native_pid'] is None and state['native_exit'] is None and cert is None and
                not any(state[key] for key in ('tls_ok', 'auth_ok', 'expiry_ok')), 'OFFLINE_NATIVE_STATE')
    observed = payload['observations']
    if observed is None:
        _n_need(payload['complete'] is False and payload['selected_ids'] == [], 'MISSING_OBSERVATIONS')
        return payload
    _n_need(type(observed) is dict and set(observed) == {'tests_run', 'started_ids', 'stopped_ids',
            'terminal_events', 'failing_subtests', 'should_stop', *_N_CATEGORIES}, 'OBSERVATION_SCHEMA')
    wanted = ([ _N_LIVE[0] ] if context['phase'] == 'live_mappings' else
              [ _N_LIVE[1] ] if context['phase'] == 'live_events' else
              sorted(set(context['expected']) - set(_N_LIVE)))
    _n_need(type(payload['selected_ids']) is list and sorted(payload['selected_ids']) == wanted and
            len(payload['selected_ids']) == len(wanted), 'WORKER_SELECTION')
    for key in ('started_ids', 'stopped_ids'):
        _n_need(type(observed[key]) is list and len(observed[key]) <= 10000 and
                all(value in context['expected'] or value == 'NON_METHOD_EVENT' for value in observed[key]),
                'OBSERVED_INVENTORY')
    _n_need(type(observed['tests_run']) is int and 0 <= observed['tests_run'] <= 10000 and
            type(observed['failing_subtests']) is int and 0 <= observed['failing_subtests'] <= 10000 and
            type(observed['should_stop']) is bool, 'OBSERVED_COUNTERS')
    for name in _N_CATEGORIES:
        _n_need(type(observed[name]) is list and len(observed[name]) <= 10000 and
                all(value in context['expected'] or value == 'NON_METHOD_EVENT' for value in observed[name]),
                'OBSERVED_NEGATIVE_RESULT')
    _n_need(type(observed['terminal_events']) is list and len(observed['terminal_events']) <= 10000,
            'OBSERVED_TERMINALS')
    for event in observed['terminal_events']:
        _n_need(type(event) is list and len(event) == 2 and
                event[0] in {'PASS', 'SKIP', 'FAIL', 'ERROR', 'EXPECTED_FAILURE', 'UNEXPECTED_SUCCESS'} and
                (event[1] in context['expected'] or event[1] == 'NON_METHOD_EVENT'), 'OBSERVED_TERMINALS')
    return payload


def _n_aggregate(workers, expected):
    # These are actual serialized observations, never TestCase/callback replay.
    aggregate = AcceptanceResult()
    selected = []
    for worker in workers:
        observed = worker['observations']
        aggregate.testsRun += observed['tests_run']
        aggregate.started_ids.extend(observed['started_ids'])
        aggregate.stopped_ids.extend(observed['stopped_ids'])
        aggregate.terminal_events.extend(tuple(event) for event in observed['terminal_events'])
        aggregate.failing_subtests += observed['failing_subtests']
        aggregate.shouldStop |= observed['should_stop']
        for name in _N_CATEGORIES:
            getattr(aggregate, name).extend(observed[name])
        selected.extend(worker['selected_ids'])
    discovered = tuple(workers[0]['inventory'])
    _n_need(len(workers) == 3 and all(tuple(worker['inventory']) == discovered for worker in workers),
            'WORKER_INVENTORY_AGREEMENT')
    accepted = validate_result(aggregate, expected_ids=expected, discovered_ids=discovered,
            selected_ids=tuple(selected), timed_out=any(w['state']['timed_out'] for w in workers),
            cleanup_failed=not all(w['state']['cleanup_ok'] for w in workers))
    return _n_observations(aggregate, expected), accepted


def main(argv=None):
    parser = argparse.ArgumentParser(description='Run isolated native Sycope acceptance.')
    parser.add_argument('--source-root', type=Path)
    parser.add_argument('--web-binary', type=Path)
    parser.add_argument('--python', type=Path)
    parser.add_argument('--timeout', type=int)
    parser.add_argument('--report', type=Path)
    parser.add_argument('--_worker', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args._worker is not None:
        return _n_worker(args._worker)
    if any(value is None for value in (args.source_root, args.web_binary, args.python, args.timeout, args.report)):
        parser.error('all five public arguments are required')
    _n_runtime()
    old_umask = os.umask(0o077)
    report = {'status': 'FAIL', 'complete': False, 'category': None, 'workers': [], 'cleanup_ok': True,
              'execution_scope': 'OWNED_NATIVE_FIXTURE_ORIGINAL_TESTS', 'policy_regressions': 'NOT_RUN'}
    owners = []
    work = None
    previous = None
    report_admitted = False
    unverified_worker = False
    state = {'timed_out': False, 'category': None}
    started = time.monotonic()
    try:
        _n_need(1 <= args.timeout <= 3600 and args.report.is_absolute() and
                _n_private(args.report.parent) and not args.report.exists() and not args.report.is_symlink(),
                'PUBLIC_ARGUMENTS')
        report_admitted = True
        source = args.source_root
        _n_need(args.web_binary.is_absolute() and args.python.is_absolute(), 'EXTERNAL_RUNTIME_PATHS')
        _n_need(args.python.is_file() and args.web_binary.is_file() and os.access(args.python, os.X_OK) and
                os.access(args.web_binary, os.X_OK), 'RUNTIME_EXECUTABLES')
        openssl = shutil.which('openssl', path='/usr/bin:/bin')
        _n_need(openssl is not None, 'OPENSSL_REQUIRED')
        openssl = str(Path(openssl).resolve(strict=True))
        manifest = _n_sources(source)
        expected = _n_ast_inventory(source, manifest)
        migrations = source / 'crates/common/migrations'
        assets = source / 'apps/web/assets'
        public_hashes = {'migrations': _n_tree(migrations), 'assets': _n_tree(assets)}
        runtime_hashes = {'runner': _n_sha(Path(__file__).read_bytes()),
                          'python': _n_sha(args.python.read_bytes()),
                          'web': _n_sha(args.web_binary.read_bytes()),
                          'openssl': _n_sha(Path(openssl).read_bytes())}
        report.update({'expected_ids': list(expected), 'source_hashes': manifest,
                       'public_runtime_hashes': public_hashes, 'runtime_hashes': runtime_hashes})
        work = Path(tempfile.mkdtemp(prefix='c01-native-', dir=args.report.parent)).resolve()
        _n_need(_n_private(work), 'PRIVATE_WORK_ROOT')
        _n_no_dotenv(work)
        deadline = started + args.timeout
        previous = _n_arm(state, deadline)
        for phase in _N_PHASES:
            worker_root = work / phase
            _n_mkdir(worker_root)
            home, tmp = worker_root / 'home', worker_root / 'tmp'
            _n_mkdir(home)
            _n_mkdir(tmp)
            context = {'phase': phase, 'worker_root': str(worker_root), 'home': str(home), 'tmp': str(tmp),
                'source_root': str(source), 'manifest': manifest, 'expected': list(expected),
                'migrations': str(migrations), 'assets': str(assets), 'runtime_hashes': runtime_hashes,
                'web_binary': str(args.web_binary), 'openssl': openssl, 'deadline': deadline}
            context_path = worker_root / 'context.json'
            _n_json_write(context_path, context)
            unverified_worker = True
            child = _NChild([str(args.python), '-I', '-B', str(Path(__file__).resolve()),
                            '--_worker', str(context_path)], _n_base_env(home, tmp), str(worker_root),
                            worker_root / 'worker.log', owners)
            try:
                code = child.wait(_n_remaining(deadline, args.timeout))
            except subprocess.TimeoutExpired:
                state['timed_out'] = True
                raise _NFailure('WORKER_TIMEOUT') from None
            _n_need(not _n_group_exists(child.process.pid), 'WORKER_DESCENDANTS_REMAIN')
            payload = _n_json(_n_file(worker_root / 'result.json', _N_REPORT_CAP))
            admitted = _n_admit_observation(payload, context)
            report['workers'].append(admitted)
            unverified_worker = not admitted['state']['cleanup_ok']
            _n_need(code == (0 if admitted['complete'] else 1), 'WORKER_EXIT')
            _n_need(admitted['state']['stage'] == 'OBSERVED' and admitted['state']['category'] is None and
                    admitted['state']['loader_errors'] == 0 and admitted['state']['cleanup_ok'] and
                    admitted['state']['source_ok'] and admitted['state']['origins_ok'] and
                    not admitted['state']['timed_out'] and admitted['inventory'] == list(expected) and
                    admitted['observations'] is not None, 'WORKER_STAGE_INCOMPLETE')
            if phase != 'offline':
                _n_need(all(admitted['state'][key] for key in ('tls_ok', 'auth_ok', 'expiry_ok')) and
                        admitted['state']['native_exit'] == 0 and not admitted['state']['native_escalated'] and
                        type(admitted['state']['native_pid']) is int and admitted['state']['native_pid'] > 0 and
                        admitted['state']['certificate_sha256'] is not None, 'LIVE_WITNESSES')
            owners.remove(child)
        report['observations'], report['policy_accepted'] = _n_aggregate(report['workers'], expected)
        _n_need(report['policy_accepted'] and all(worker['complete'] for worker in report['workers']),
                'FULL_POLICY_REJECTED')
        _n_need(report['workers'][0]['state']['native_pid'] != report['workers'][1]['state']['native_pid'] and
                report['workers'][0]['state']['certificate_sha256'] !=
                report['workers'][1]['state']['certificate_sha256'], 'DISTINCT_FIXTURES')
        _n_need(_n_sources(source) == manifest and _n_tree(migrations) == public_hashes['migrations'] and
                _n_tree(assets) == public_hashes['assets'], 'CANONICAL_SOURCE_CHANGED')
        _n_need(_n_sha(args.web_binary.read_bytes()) == runtime_hashes['web'] and
                _n_sha(args.python.read_bytes()) == runtime_hashes['python'] and
                _n_sha(Path(openssl).read_bytes()) == runtime_hashes['openssl'] and
                _n_sha(Path(__file__).read_bytes()) == runtime_hashes['runner'], 'RUNTIME_CHANGED')
        report['complete'] = True
    except _NFailure as error:
        report['category'] = error.code
    except _NAbort:
        report['category'] = state['category']
    except BaseException:
        report['category'] = 'PARENT_STAGE_FAILED'
    finally:
        if previous is not None:
            _n_cleanup_signals(state)
        for child in reversed(owners):
            try:
                report['cleanup_ok'] &= child.stop()
            except BaseException:
                report['cleanup_ok'] = False
        if unverified_worker:
            report['cleanup_ok'] = False
        if work is not None and report['cleanup_ok']:
            try:
                shutil.rmtree(work)
                report['cleanup_ok'] &= not work.exists()
            except BaseException:
                report['cleanup_ok'] = False
        report['retained_private_work'] = work is not None and work.exists()
        if previous is not None:
            _n_restore_signals(previous)
        if report['category'] is None and state['category'] is not None:
            report['category'] = state['category']
        report['complete'] &= (report['cleanup_ok'] and not state['timed_out'] and
                               report['category'] is None and state['category'] is None)
        report['status'] = 'PASS' if report['complete'] else 'FAIL'
        report['timed_out'] = state['timed_out']
        report['elapsed_seconds'] = round(time.monotonic() - started, 3)
        try:
            if report_admitted:
                _n_json_write(args.report, report)
        finally:
            os.umask(old_umask)
    return 0 if report['complete'] else 1 if report_admitted else 2


if __name__ == '__main__':
    try:
        _n_exit_code = main()
    except SystemExit:
        raise
    except BaseException:
        # Never export a traceback, exception text or private context paths.
        sys.stderr.write('C01_NATIVE_CONTROL_FAILED\n')
        _n_exit_code = 2
    sys.exit(_n_exit_code)
