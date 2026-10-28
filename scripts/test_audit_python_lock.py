"""Offline behavioral tests for the frozen Python-lock audit and its Linux CLI."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import select
import shutil
import signal
import ssl
import stat
import sys
import tempfile
import time
import unittest
from unittest import mock


SCANNER_PATH = Path(__file__).with_name("audit-python-lock.py")
SPEC = importlib.util.spec_from_file_location("audit_python_lock_under_test", SCANNER_PATH)
audit = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = audit
SPEC.loader.exec_module(audit)
FIELDS = {"status", "lock_sha256", "manifest_sha256", "inventory", "submitted",
          "completed", "batches", "advisories", "error"}


def encoded(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read_small(path, limit=16384):
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise AssertionError("test witness exceeded its fixed bound")
    return raw


def record(name, version="1.0", source=None, **extra):
    return {"name": name, "version": version,
            "source": {"registry": "https://pypi.org/simple"} if source is None else source, **extra}


def identity(pid):
    try:
        raw = read_small(Path("/proc/%s/stat" % pid), 4096).decode()
        fields = raw.rsplit(")", 1)[1].split()
        return {"pid": pid, "ppid": int(fields[1]), "pgrp": int(fields[2]),
                "session": int(fields[3]), "state": fields[0], "start": int(fields[19])}
    except (OSError, ValueError, IndexError):
        return None


def witness(path):
    value = identity(os.getpid())
    temporary = path.with_suffix(".new")
    temporary.write_bytes(encoded(value))
    os.replace(temporary, path)


def reap_child(pid, seconds=3.0):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        try:
            observed, status = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return None
        if observed == pid:
            return status
        time.sleep(0.01)
    # waitpid still proves this exact unreaped child belongs to this test.
    try:
        observed, status = os.waitpid(pid, os.WNOHANG)
        if observed == pid:
            return status
        os.kill(pid, signal.SIGKILL)
    except (ChildProcessError, ProcessLookupError):
        pass
    until = time.monotonic() + 2.0
    while time.monotonic() < until:
        try:
            observed, status = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return None
        if observed:
            return status
        time.sleep(0.01)
    raise AssertionError("test-owned child did not reap within the cleanup bound")


class Response:
    def __init__(self, body=None, *, status=200, headers=None, chunk=65536,
                 read_error=None, close_error=False, read_hook=None):
        self.body = encoded({"results": [{}]}) if body is None else body
        self.status = status
        self.headers = [("Content-Type", "application/json")] if headers is None else headers
        self.chunk = chunk
        self.read_error, self.close_error, self.read_hook = read_error, close_error, read_hook
        self.offset, self.reads, self.closed = 0, 0, False
        self.close_hook = None

    def getheaders(self):
        return self.headers

    def read(self, size):
        self.reads += 1
        if self.read_hook is not None:
            self.read_hook(self)
        if self.read_error is not None:
            raise self.read_error
        count = min(size, self.chunk)
        value = self.body[self.offset:self.offset + count]
        self.offset += len(value)
        return value

    def close(self):
        self.closed = True
        if self.close_hook is not None:
            self.close_hook()
        if self.close_error:
            raise OSError("private fake response close detail")


class Boundary:
    def __init__(self, responses, *, connect=None, request=None, get_error=None,
                 connect_error=None, connection_close_error=False, events=None):
        self.responses = list(responses)
        self.connect_hook, self.request_hook = connect, request
        self.get_error, self.connect_error = get_error, connect_error
        self.connection_close_error = connection_close_error
        self.connections, self.requests = [], []
        self.events, self.event_count = events, 0

    def note(self, event, **fields):
        if self.events is not None:
            self.event_count += 1
            if self.event_count > 32:
                raise AssertionError("too many fake-boundary witness events")
            raw = encoded({"event": event, "pid": os.getpid(), "ppid": os.getppid(), **fields}) + b"\n"
            if len(raw) > 512:
                raise AssertionError("fake-boundary event too large")
            with self.events.open("ab") as stream:
                stream.write(raw)

    def __call__(self, host, *, timeout, context):
        if self.connect_hook is not None:
            self.connect_hook()
        if self.connect_error is not None:
            raise self.connect_error
        self.note("connect", host=host, verified=context.verify_mode == ssl.CERT_REQUIRED,
                  hostname=context.check_hostname)
        owner = self
        index = len(self.connections)

        class Connection:
            closed = False

            def request(self, method, path, *, body, headers):
                owner.requests.append({"method": method, "path": path, "body": body,
                                       "headers": headers})
                owner.note("request", method=method, path=path, body_sha256=digest(body))
                if owner.request_hook is not None:
                    owner.request_hook()

            def getresponse(self):
                if owner.get_error is not None:
                    raise owner.get_error
                response = owner.responses[index]
                owner.note("response")
                response.close_hook = lambda: owner.note("response_close")
                return response

            def close(self):
                self.closed = True
                owner.note("connection_close")
                if owner.connection_close_error:
                    raise OSError("private fake connection close detail")

        connection = Connection()
        connection.host, connection.timeout, connection.context = host, timeout, context
        self.connections.append(connection)
        return connection


class OwnedMain:
    """A private test session keeps its unreaped anchor reserved through cleanup."""
    def __init__(self, folder, label, args, boundary, seconds, output_fd=None):
        self.folder, self.label = folder, label
        self.args, self.boundary, self.seconds = args, boundary, seconds
        self.output_fd = output_fd
        self.anchor_path = folder / (label + "-anchor.json")
        self.result_path = folder / (label + "-result.json")
        self.pid, self.anchor, self.started, self.reaped = None, None, None, False

    def start(self):
        self.started = time.monotonic()
        self.pid = os.fork()
        if self.pid == 0:
            try:
                os.setsid()
                witness(self.anchor_path)
                previous = {n: signal.getsignal(n) for n in (signal.SIGINT, signal.SIGTERM)}
                output = io.StringIO() if self.output_fd is None else os.fdopen(os.dup(self.output_fd), "w", encoding="utf-8")
                flags = None if self.output_fd is None else os.get_blocking(self.output_fd)
                with mock.patch.object(audit.http.client, "HTTPSConnection", self.boundary), \
                        mock.patch.object(audit, "RUN_SECONDS", self.seconds), contextlib.redirect_stdout(output):
                    code = audit.main(self.args)
                left = read_small(Path("/proc/self/task/%s/children" % os.getpid()), 4096).decode().split()
                result = {"code": code, "output": output.getvalue() if self.output_fd is None else None,
                          "handlers_restored": all(signal.getsignal(n) == value for n, value in previous.items()),
                          "flags_restored": flags is None or os.get_blocking(self.output_fd) == flags,
                          "remaining_direct_children": left}
                self.result_path.write_bytes(encoded(result))
                os._exit(0)
            except BaseException:
                os._exit(99)
        self.anchor = identity(self.pid)
        if self.anchor is None or self.anchor["ppid"] != os.getpid():
            raise AssertionError("unproven test anchor")
        return self

    def current(self):
        value = identity(self.pid) if self.pid is not None else None
        if value is None or self.anchor is None or value["start"] != self.anchor["start"] or value["ppid"] != os.getpid():
            return None
        return value

    def wait_anchor(self):
        until = time.monotonic() + 2
        while time.monotonic() < until:
            if self.anchor_path.exists():
                value = json.loads(read_small(self.anchor_path))
                current = self.current()
                if current is not None and value["start"] == current["start"]:
                    if value["pid"] == value["pgrp"] == value["session"] == self.pid:
                        return value
            time.sleep(0.01)
        raise AssertionError("private test session handshake missing")

    def result(self, seconds):
        until = time.monotonic() + seconds
        while time.monotonic() < until:
            # WNOWAIT observes the real outer exit while retaining its PID/session lease.
            observed = os.waitid(os.P_PID, self.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if observed is not None:
                if observed.si_code != os.CLD_EXITED or observed.si_status != 0:
                    raise AssertionError("test outer did not exit normally")
                return json.loads(read_small(self.result_path))
            time.sleep(0.01)
        raise AssertionError("owned main exceeded its independent outer bound")

    def members(self):
        values = []
        for index, path in enumerate(Path("/proc").iterdir()):
            if index > 16384:
                raise AssertionError("process inventory bound")
            if path.name.isdigit():
                value = identity(int(path.name))
                if value is not None and value["session"] == self.pid:
                    values.append(value)
        return values

    def signal_group(self, number):
        current = self.current()
        if current is None or current["pgrp"] != self.pid or current["session"] != self.pid:
            raise AssertionError("private group ownership unproven")
        if self.pid in (os.getpid(), os.getpgrp(), os.getsid(0)):
            raise AssertionError("trusted driver cannot be signaled")
        try:
            os.killpg(self.pid, number)
        except ProcessLookupError:
            pass

    def cleanup(self):
        if self.pid is None or self.reaped:
            return
        current = self.current()
        if current is None:
            raise AssertionError("unreaped anchor identity lost; no unknown PID kill")
        # Before setsid the authored fixture cannot have launched scanner/main.
        if current["session"] != self.pid or current["pgrp"] != self.pid:
            os.kill(self.pid, signal.SIGTERM)
            until = time.monotonic() + 0.5
            while time.monotonic() < until:
                current = self.current()
                if current is None or current["state"] == "Z" or current["session"] == self.pid:
                    break
                time.sleep(0.01)
            current = self.current()
            if current is None:
                raise AssertionError("anchor ownership lost during startup cleanup")
            if current["session"] != self.pid:
                os.kill(self.pid, signal.SIGKILL)
                until = time.monotonic() + 1
                while time.monotonic() < until:
                    current = self.current()
                    if current is None or current["state"] == "Z":
                        break
                    time.sleep(0.01)
        current = self.current()
        if current is not None and current["session"] == current["pgrp"] == self.pid:
            members = self.members()
            if any(v["state"] != "Z" for v in members):
                self.signal_group(signal.SIGTERM)
            until = max(time.monotonic() + 0.5, self.started + self.seconds + 1.0)
            while time.monotonic() < until:
                members = self.members()
                if all(v["state"] == "Z" for v in members):
                    break
                time.sleep(0.02)
            if any(v["state"] != "Z" for v in self.members()):
                self.signal_group(signal.SIGKILL)
            until = time.monotonic() + 2
            while time.monotonic() < until:
                members = self.members()
                anchor = self.current()
                if not any(v["pid"] != self.pid for v in members) and anchor is not None and anchor["state"] == "Z":
                    break
                time.sleep(0.01)
            if any(v["pid"] != self.pid for v in self.members()):
                raise AssertionError("private session descendants not drained; anchor retained")
        # Reap only after the private session has no descendants; never release its PID early.
        until = time.monotonic() + 2
        while time.monotonic() < until:
            observed, _status = os.waitpid(self.pid, os.WNOHANG)
            if observed == self.pid:
                self.reaped = True
                return
            time.sleep(0.01)
        raise AssertionError("test anchor did not reap")


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="trueid-lock-test-"))
        self.addCleanup(shutil.rmtree, self.work)
        self.serial = 0

    def project(self, records=None, *, root=("demo-root", "0.1.0"), manifest=None,
                include_root=True, prefix="version=1\nrevision=3\n"):
        self.serial += 1
        folder = self.work / ("p%s" % self.serial)
        folder.mkdir()
        rows = [record("alpha", "1.0")] if records is None else copy.deepcopy(records)
        if include_root:
            rows.append(record(root[0], root[1], {"virtual": "."}))
        parts = [prefix]
        for row in rows:
            parts.append("\n[[package]]\n")
            for key, value in row.items():
                if key == "source":
                    value = "{" + ",".join(k + "=" + json.dumps(v) for k, v in value.items()) + "}"
                else:
                    value = json.dumps(value)
                parts.append(key + "=" + value + "\n")
        lock = folder / "uv.lock"
        lock.write_text("".join(parts))
        declared = root if manifest is None else manifest
        (folder / "pyproject.toml").write_text(
            "[project]\nname=" + json.dumps(declared[0]) + "\nversion=" + json.dumps(declared[1]) + "\n")
        return lock

    def summary(self, code, report, expected_code):
        self.assertIs(type(code), int)
        self.assertEqual(code, expected_code)
        self.assertEqual(set(report), FIELDS)
        self.assertEqual(report["status"], ("CLEAN", "FINDINGS", "ERROR")[code])
        for key in ("submitted", "completed", "batches"):
            self.assertIs(type(report[key]), int)
            self.assertGreaterEqual(report[key], 0)
        if code == 2:
            self.assertIs(type(report["error"]), str)
            self.assertTrue(report["error"])
        else:
            self.assertIsNone(report["error"])
            self.assertEqual(report["submitted"], len(report["inventory"]))
            self.assertEqual(report["completed"], len(report["inventory"]))
            self.assertEqual(bool(report["advisories"]), code == 1)
        self.assertLessEqual(len(encoded(report)) + 1, 1048576)

    def scan(self, lock, responses=None, boundary=None):
        boundary = boundary or Boundary([Response()] if responses is None else responses)
        with mock.patch.object(audit.http.client, "HTTPSConnection", boundary):
            code, report = audit.scan(lock)
        return code, report, boundary

    def main(self, args, boundary, *, seconds=60.0):
        output = io.StringIO()
        handlers = {n: signal.getsignal(n) for n in (signal.SIGINT, signal.SIGTERM)}
        with mock.patch.object(audit.http.client, "HTTPSConnection", boundary), \
                mock.patch.object(audit, "RUN_SECONDS", seconds), contextlib.redirect_stdout(output):
            code = audit.main(args)
        self.assertEqual({n: signal.getsignal(n) for n in handlers}, handlers)
        raw = output.getvalue()
        self.assertEqual(raw.count("\n"), 1)
        self.assertTrue(raw.endswith("\n"))
        self.assertLessEqual(len(raw.encode()), 1048576)
        report = json.loads(raw)
        self.summary(code, report, code)
        return code, report

    def dead_and_reaped(self, value):
        self.assertIsNotNone(value)
        current = identity(value["pid"])
        self.assertTrue(current is None or current["start"] != value["start"])
        with self.assertRaises(ChildProcessError):
            os.waitpid(value["pid"], os.WNOHANG)

    def owned_main(self, label, args, boundary, seconds=1.5, output_fd=None):
        outer = OwnedMain(self.work, label, args, boundary, seconds, output_fd)
        self.addCleanup(outer.cleanup)  # Armed before fork, handshake, assertions or HTTP witness.
        outer.start()
        outer.wait_anchor()
        return outer

    def owned_summary(self, outer, seconds=4):
        result = outer.result(seconds)
        self.assertTrue(result["handlers_restored"])
        self.assertTrue(result["flags_restored"])
        self.assertEqual(result["remaining_direct_children"], [])
        return result

    def test_real_public_lock_complete_inventory_and_verified_request(self):
        lock = SCANNER_PATH.parent.parent / "integrations/sycope/uv.lock"
        expected = [{"name": n, "version": v} for n, v in [
            ("certifi", "2026.10.23"), ("charset-normalizer", "3.5.1"),
            ("idna", "3.19"), ("requests", "2.34.2"), ("urllib3", "2.8.0")]]
        response = Response(encoded({"results": [{}, {"vulns": []}, {}, {}, {}]}), chunk=7)
        code, report, boundary = self.scan(lock, [response])
        self.summary(code, report, 0)
        self.assertEqual(report["inventory"], expected)
        self.assertEqual((report["submitted"], report["completed"], report["batches"]), (5, 5, 1))
        self.assertEqual(report["lock_sha256"], digest(lock.read_bytes()))
        self.assertEqual(report["manifest_sha256"], digest(lock.with_name("pyproject.toml").read_bytes()))
        self.assertEqual(len(boundary.requests), 1)
        request = boundary.requests[0]
        self.assertEqual((request["method"], request["path"]), ("POST", "/v1/querybatch"))
        self.assertEqual(request["headers"], {"Content-Type": "application/json", "Accept": "application/json"})
        self.assertEqual(json.loads(request["body"]), {"queries": [
            {"package": {"ecosystem": "PyPI", "name": p["name"]}, "version": p["version"]} for p in expected]})
        connection = boundary.connections[0]
        self.assertEqual(connection.host, "api.osv.dev")
        self.assertGreater(connection.timeout, 0)
        self.assertLessEqual(connection.timeout, 10)
        self.assertTrue(connection.context.check_hostname)
        self.assertEqual(connection.context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(connection.closed and response.closed)
        self.assertGreater(response.reads, 1)

    def test_normalization_versions_and_sixth_transitive_finding(self):
        rows = [record("Z", "2"), record("Alpha_Pkg", "v1.0"), record("alpha.pkg", "1!2.0rc1.post2.dev3+LOCAL-1"),
                record("dev-only", "1.0", **{"resolution-markers": ["python_version < '3.8'"]}), record("optional", "2.0"),
                record("sixth-transitive", "3.0")]
        expected = [{"name": n, "version": v} for n, v in [
            ("alpha-pkg", "1!2.0rc1.post2.dev3+LOCAL-1"), ("alpha-pkg", "v1.0"),
            ("dev-only", "1.0"), ("optional", "2.0"), ("sixth-transitive", "3.0"), ("z", "2")]]
        lock = self.project(rows, root=("Other_Root", "4.0"), manifest=("other-root", "4.0"))
        lock.write_text(lock.read_text() + '\n[package.optional-dependencies]\nextra=[{name="optional"}]\n'
                        '[package.dev-dependencies]\ntest=[{name="dev-only"}]\n')
        initial_hashes = digest(lock.read_bytes()), digest(lock.with_name("pyproject.toml").read_bytes())
        response = Response(encoded({"results": [{}, {}, {}, {}, {"vulns": [{"id": "ADV-6"}]}, {}]}))
        code, report, boundary = self.scan(lock, [response])
        self.summary(code, report, 1)
        self.assertEqual(report["inventory"], expected)
        self.assertEqual(report["advisories"], [{"name": "sixth-transitive", "version": "3.0", "ids": ["ADV-6"]}])
        self.assertEqual(len(boundary.requests), 1)
        self.assertEqual((report["submitted"], report["completed"], report["batches"]), (6, 6, 1))
        self.assertEqual((report["lock_sha256"], report["manifest_sha256"]), initial_hashes)
        self.assertEqual(json.loads(boundary.requests[0]["body"]), {"queries": [
            {"package": {"ecosystem": "PyPI", "name": p["name"]}, "version": p["version"]} for p in expected]})

    def test_valid_pep440_spellings_are_preserved(self):
        versions = ["1", "1.2.3", "v1.0", "2!1.0", "1.0-alpha1", "1.0b2", "1.0preview3",
                    "1.0c4", "1.0-2", "1.0.post3", "1.0rev4", "1.0.dev5", "1.0+LOCAL_6"]
        for version in versions:
            with self.subTest(label=version):
                lock = self.project([record("pkg", version)])
                code, report, boundary = self.scan(lock)
                self.summary(code, report, 0)
                self.assertEqual(report["inventory"], [{"name": "pkg", "version": version}])
                self.assertEqual(json.loads(boundary.requests[0]["body"])["queries"][0]["version"], version)

    def test_invalid_inventory_root_schema_and_sources_never_query(self):
        variants = [([record(name)], {}) for name in ["", "-x", "x-", "a/b", "a b", "é"]]
        variants += [([record("pkg", version)], {}) for version in ["", ">=1", "1.*", "1 garbage", "url:x", True, 1]]
        variants += [([record("x", source=source)], {}) for source in [
            {"registry": "http://pypi.org/simple"}, {"registry": "https://evil.invalid/simple"},
            {"registry": "https://pypi.org/simple", "extra": True}, {"git": "https://example.invalid/repo"},
            {"path": "."}, {"editable": "."}, {"url": "https://example.invalid/x"}, {}]]
        variants += [([record("a.b"), record("A_B")], {}), ([], {}),
                     ([record("x")], {"include_root": False}),
                     ([record("x")], {"manifest": ("wrong", "0.1.0")}),
                     ([record("x")], {"manifest": ("demo-root", "9")}),
                     ([record("extra", source={"virtual": "."})], {}),
                     ([record("x")], {"prefix": "version=true\nrevision=3\n"}),
                     ([record("x")], {"prefix": "version=1.0\nrevision=3\n"}),
                     ([record("x")], {"prefix": "version=1\nrevision=3.0\n"}),
                     ([record("x")], {"prefix": "version=1\nrevision=2\n"})]
        for index, (rows, options) in enumerate(variants):
            with self.subTest(label="invalid-inventory-%s" % index):
                lock = self.project(rows, **options)
                code, report, boundary = self.scan(lock, [])
                self.summary(code, report, 2)
                self.assertEqual(report["error"], "INPUT")
                self.assertEqual(boundary.connections, [])

        malformed_manifests = ['[other]\nvalue=1\n', 'project=1\n', 'project=[]\n', 'project="x"\n',
            '[project]\nversion="0.1.0"\n', '[project]\nname="demo-root"\n',
            '[project]\nname=1\nversion="0.1.0"\n', '[project]\nname=true\nversion="0.1.0"\n',
            '[project]\nname=["demo-root"]\nversion="0.1.0"\n',
            '[project]\nname="demo-root"\nversion=1\n', '[project]\nname="demo-root"\nversion=true\n']
        for index, contents in enumerate(malformed_manifests):
            with self.subTest(label="manifest-type-%s" % index):
                lock = self.project()
                lock.with_name("pyproject.toml").write_text(contents)
                code, report, boundary = self.scan(lock, [])
                self.summary(code, report, 2)
                self.assertEqual(report["error"], "INPUT")
                self.assertEqual(boundary.connections, [])

    def test_input_file_failures_are_bounded_and_safe(self):
        for filename, variant in [(name, kind) for name in ["uv.lock", "pyproject.toml"]
                                  for kind in ["missing", "utf8", "toml", "empty", "oversize", "symlink", "fifo"]]:
            with self.subTest(label=filename + ":" + variant):
                lock = self.project()
                target = lock.with_name(filename)
                if variant == "missing": target.unlink()
                elif variant == "utf8": target.write_bytes(b"\xff")
                elif variant == "toml": target.write_text("[broken")
                elif variant == "empty": target.write_bytes(b"")
                elif variant == "oversize": target.write_bytes(b"x" * 1048577)
                elif variant == "symlink":
                    other = target.with_name("original"); target.rename(other); target.symlink_to(other)
                elif variant == "fifo": target.unlink(); os.mkfifo(target)
                started = time.monotonic()
                code, report, boundary = self.scan(lock, [])
                self.summary(code, report, 2)
                self.assertLess(time.monotonic() - started, 2)
                self.assertEqual(boundary.connections, [])

    def test_chunking_second_batch_mapping_and_later_error_over_findings(self):
        rows = [record("pkg%04d" % i) for i in range(1002)]
        lock = self.project(rows)
        first = [{"vulns": [{"id": "FIRST"}]}] + [{} for _ in range(999)]
        responses = [Response(encoded({"results": first})),
                     Response(encoded({"results": [{}, {"vulns": [{"id": "LAST"}]}]}))]
        code, report, boundary = self.scan(lock, responses)
        self.summary(code, report, 1)
        queries = [json.loads(r["body"])["queries"] for r in boundary.requests]
        self.assertEqual([len(q) for q in queries], [1000, 2])
        self.assertEqual([q["package"]["name"] for batch in queries for q in batch],
                         ["pkg%04d" % i for i in range(1002)])
        self.assertEqual(report["advisories"], [
            {"name": "pkg0000", "version": "1.0", "ids": ["FIRST"]},
            {"name": "pkg1001", "version": "1.0", "ids": ["LAST"]}])
        for index, later in enumerate([Response(status=503), Response(encoded({"results": []})),
                      Response(encoded({"results": [{"next_page_token": ""}, {}]}))]):
            with self.subTest(label="later-error-%s" % index):
                code, report, boundary = self.scan(lock, [Response(encoded({"results": first})), later])
                self.summary(code, report, 2)
                self.assertEqual((report["submitted"], report["completed"], report["batches"]), (1002, 1000, 2))
                self.assertEqual(len(boundary.requests), 2)
                self.assertTrue(all(c.closed for c in boundary.connections))

    def test_osv_result_shapes_ids_and_timestamps(self):
        good = [{}, {"vulns": []}, {"vulns": [{"id": "X"}]},
                {"vulns": [{"id": "Z"}, {"id": "A"}, {"id": "Z"}]},
                {"vulns": [{"id": "X", "modified": "2026-10-28T12:34:56.123+01:30"}]},
                {"vulns": [{"id": "X", "modified": "2016-12-31T23:59:60Z"}]}]
        bad = [None, [], 1, {"error": "private"}, {"vulns": None}, {"vulns": [None]},
               {"vulns": [{}]}, {"vulns": [{"id": True}]}, {"vulns": [{"id": ""}]},
               {"vulns": [{"id": " "}]}, {"vulns": [{"id": "x\n"}]}, {"vulns": [{"id": "x" * 257}]}]
        bad += [{"vulns": [{"id": "X", "modified": value}]} for value in [
            None, 1, "2026-10-28", "2026-10-28T12:34:56", "2026-02-30T00:00:00Z",
            "2026-10-28T24:00:00Z", "2026-10-28T12:34:60Z", "2026-10-28T00:00:00+24:00"]]
        bad += [{"next_page_token": token, "vulns": [{"id": "X"}]} for token in ["", None, "next"]]
        bad += [{"vulns": [{"id": "X"}, {"id": "X", "modified": "invalid"}]}]
        for index, (result, wanted) in enumerate([(r, 1 if r.get("vulns") else 0) for r in good] + [(r, 2) for r in bad]):
            with self.subTest(label="osv-entry-%s" % index):
                code, report, boundary = self.scan(self.project(), [Response(encoded({"results": [result]}))])
                self.summary(code, report, wanted)
                self.assertEqual(len(boundary.requests), 1)
                if wanted == 1:
                    self.assertEqual(report["advisories"][0]["ids"], sorted({v["id"] for v in result["vulns"]}))
        for index, payload in enumerate([[], None, {}, {"results": None}, {"results": []}, {"results": [{}, {}]},
                        {"results": [{}], "extra": True}]):
            with self.subTest(label="osv-root-%s" % index):
                code, report, _ = self.scan(self.project(), [Response(encoded(payload))])
                self.summary(code, report, 2)

    def test_strict_json_and_response_boundaries(self):
        invalid = [b'{"x":1,"\\u0078":2}', b'{"outer":{"x":1,"x":2}}', b'{}{}', b'{',
                   b'\xff', b'\xef\xbb\xbf{}', b'{"x":"\x00"}', b'{"x":"\\u0000"}',
                   b'{"x":"\\ud800"}', b'{"x":"\\udfff"}', b'{"\\u0000":1}', b'{"\\ud800":1}',
                   b'{"\\udfff":1}', b'NaN', b'Infinity', b'-Infinity', b'1e10000', b'-1e10000',
                   b'[' * 17 + b'0' + b']' * 17, b' ' * 1048577]
        for index, raw in enumerate(invalid):
            with self.subTest(label="json-invalid-%s" % index):
                with self.assertRaises((ValueError, UnicodeError, RecursionError)):
                    audit.strict_json(raw)
                code, report, _ = self.scan(self.project(), [Response(raw)])
                self.summary(code, report, 2)
        for index, raw in enumerate([b'{"x":"[{]}","n":1.25}', b'[' * 16 + b'0' + b']' * 16,
                    b' ' * (1048576 - 2) + b'{}']):
            with self.subTest(label="json-valid-%s" % index):
                self.assertIsNotNone(audit.strict_json(raw))

    def test_http_headers_status_stream_and_resource_failures(self):
        body = encoded({"results": [{}]})
        good_headers = [[("Content-Type", "application/json; charset=\"UTF-8\""),
                         ("Content-Encoding", "identity"), ("Content-Length", str(len(body)))],
                        [("content-type", "APPLICATION/JSON"), ("Transfer-Encoding", "chunked")]]
        for index, headers in enumerate(good_headers):
            with self.subTest(label="headers-valid-%s" % index):
                response = Response(body, headers=headers, chunk=1)
                code, report, boundary = self.scan(self.project(), [response])
                self.summary(code, report, 0)
                self.assertTrue(response.closed and boundary.connections[0].closed)
        headers = [[], [("Content-Type", "text/plain")], [("Content-Type", "application/jsonp")],
                   [("Content-Type", "application/json; charset=latin1")],
                   [("Content-Type", "application/json"), ("Content-Type", "application/json")],
                   [("Content-Type", "application/json"), ("Content-Encoding", "gzip")],
                   [("Content-Type", "application/json"), ("Content-Encoding", "")],
                   [("Content-Type", "application/json"), ("Content-Length", "1")],
                   [("Content-Type", "application/json"), ("Content-Length", str(len(body) + 1))],
                   [("Content-Type", "application/json"), ("Content-Length", "-1")],
                   [("Content-Type", "application/json"), ("Content-Length", "+" + str(len(body)))],
                   [("Content-Type", "application/json"), ("Content-Length", "1048577")],
                   [("Content-Type", "application/json"), ("Content-Length", str(len(body))), ("Content-Length", str(len(body)))],
                   [("Content-Type", "application/json"), ("Transfer-Encoding", "gzip")],
                   [("Content-Type", "application/json"), ("Transfer-Encoding", "chunked"), ("Content-Length", str(len(body)))],
                   {"Content-Type": "application/json"}, [["Content-Type", "application/json"]]]
        responses = [Response(body, headers=h) for h in headers]
        responses += [Response(body, status=s) for s in [True, 301, 401, 429, 500]]
        responses += [Response(b"x" * 1048577), Response(body, read_error=TimeoutError("private read")),
                      Response(body, close_error=True)]
        for index, response in enumerate(responses):
            with self.subTest(label="http-invalid-%s" % index):
                code, report, boundary = self.scan(self.project(), [response])
                self.summary(code, report, 2)
                self.assertTrue(response.closed and boundary.connections[0].closed)
                self.assertNotIn("private", encoded(report).decode())
        for index, options in enumerate([{"connect_error": ssl.SSLError("private TLS")}, {"connect_error": OSError("private DNS")},
                        {"get_error": OSError("private response")}, {"connection_close_error": True}]):
            with self.subTest(label="transport-%s" % index):
                response = Response(body)
                boundary = Boundary([response], **options)
                code, report, _ = self.scan(self.project(), boundary=boundary)
                self.summary(code, report, 2)
                self.assertEqual(report["error"], "OSV_TRANSPORT")
                self.assertTrue(all(c.closed for c in boundary.connections))

    def test_input_mutation_overrides_findings_and_initial_hashes_remain(self):
        for filename in ["uv.lock", "pyproject.toml"]:
            with self.subTest(label=filename):
                lock = self.project()
                before = digest(lock.read_bytes()), digest(lock.with_name("pyproject.toml").read_bytes())
                target = lock.with_name(filename)
                def change():
                    target.write_bytes(target.read_bytes() + b"\n# changed during HTTP\n")
                boundary = Boundary([Response(encoded({"results": [{"vulns": [{"id": "X"}]}]}))], request=change)
                code, report, _ = self.scan(lock, boundary=boundary)
                self.summary(code, report, 2)
                self.assertEqual(report["error"], "INPUT_CHANGED")
                self.assertEqual((report["lock_sha256"], report["manifest_sha256"]), before)
        lock = self.project()
        manifest = lock.with_name("pyproject.toml")
        original = digest(manifest.read_bytes())
        def mutate_in_worker(): manifest.write_bytes(manifest.read_bytes() + b"\n# child change\n")
        code, report = self.main(["--lock", str(lock)], Boundary([Response()], request=mutate_in_worker))
        self.summary(code, report, 2)
        self.assertEqual(report["error"], "INPUT_CHANGED")
        self.assertEqual(report["manifest_sha256"], original)

    def test_main_real_fork_cli_codes_usage_and_default_outside_cwd(self):
        lock = self.project()
        for index, (args, response, wanted) in enumerate([(["--lock", str(lock)], Response(), 0),
            (["--lock=" + str(lock)], Response(encoded({"results": [{"vulns": [{"id": "X"}]}]})), 1),
            (["--lock", str(lock)], Response(encoded({"results": []})), 2)]):
            with self.subTest(label="main-code-%s" % index):
                events_path = self.work / ("main-events-%s.jsonl" % index)
                code, report = self.main(args, Boundary([response], events=events_path))
                self.summary(code, report, wanted)
                events = [json.loads(line) for line in read_small(events_path).splitlines()]
                self.assertEqual([e["event"] for e in events],
                                 ["connect", "request", "response", "response_close", "connection_close"])
                self.assertTrue(all(e["pid"] != os.getpid() and e["ppid"] == os.getpid() for e in events))
                self.assertEqual(events[0]["host"], "api.osv.dev")
                self.assertTrue(events[0]["verified"] and events[0]["hostname"])
        for index, args in enumerate([["--bad"], ["--lock"], ["--lock="], ["--lock", "a", "b"], ["--lock", "\0"], "invalid"]):
            with self.subTest(label="usage-%s" % index):
                code, report = self.main(args, Boundary([]))
                self.summary(code, report, 2)
                self.assertEqual(report["error"], "USAGE")
        layout = self.work / "layout"
        (layout / "scripts").mkdir(parents=True)
        destination = layout / "integrations/sycope"
        shutil.copytree(lock.parent, destination)
        before = Path.cwd()
        try:
            os.chdir(self.work)
            with mock.patch.object(audit, "__file__", str(layout / "scripts/audit-python-lock.py")):
                code, report = self.main([], Boundary([Response()]))
            self.summary(code, report, 0)
            self.assertEqual(report["lock_sha256"], digest((destination / "uv.lock").read_bytes()))
        finally:
            os.chdir(before)

    def test_real_deadline_stalled_connect_trickle_and_exact_reap(self):
        for kind in ["connect_term_resistant", "trickle"]:
            with self.subTest(label=kind):
                mark = self.work / (kind + ".json")
                progress = self.work / (kind + ".reads")
                def connect():
                    witness(mark)
                    if kind == "connect_term_resistant":
                        signal.signal(signal.SIGTERM, signal.SIG_IGN)
                        while True: time.sleep(0.02)
                def progressing(response):
                    time.sleep(0.04)
                    with progress.open("ab") as stream: stream.write(b".")
                response = Response(b" " * 300 + encoded({"results": [{}]}), chunk=1,
                                    read_hook=progressing) if kind == "trickle" else Response()
                started = time.monotonic()
                outer = self.owned_main(kind, ["--lock", str(self.project())],
                                        Boundary([response], connect=connect), seconds=1.5)
                try:
                    result = self.owned_summary(outer, 4)
                    elapsed = time.monotonic() - started
                    value = json.loads(read_small(mark))
                    report = json.loads(result["output"])
                    self.summary(result["code"], report, 2)
                    self.assertEqual(report["error"], "DEADLINE")
                    self.assertGreater(elapsed, 0.7)
                    self.assertLess(elapsed, 3.5)
                    self.assertEqual(value["ppid"], outer.pid)
                    self.dead_and_reaped(value)
                    if kind == "trickle": self.assertGreaterEqual(len(read_small(progress)), 3)
                finally:
                    outer.cleanup()

    def test_actual_sigint_and_sigterm_restore_handlers_and_reap_worker(self):
        for number in [signal.SIGINT, signal.SIGTERM]:
            with self.subTest(label="signal-%s" % number):
                lock = self.project()
                mark = self.work / ("interrupt-%s.json" % number)
                def blocked():
                    witness(mark)
                    while True: time.sleep(0.02)
                outer = self.owned_main("interrupt-%s" % number, ["--lock", str(lock)],
                                        Boundary([Response()], connect=blocked), seconds=5.0)
                try:
                    worker = None
                    until = time.monotonic() + 2
                    while time.monotonic() < until:
                        if mark.exists():
                            worker = json.loads(read_small(mark))
                            break
                        time.sleep(0.01)
                    self.assertIsNotNone(worker)
                    self.assertEqual(worker["ppid"], outer.pid)
                    # Primary test signal targets only main; group drain is emergency cleanup only.
                    os.kill(outer.pid, number)
                    result = self.owned_summary(outer, 4)
                    report = json.loads(result["output"])
                    self.summary(result["code"], report, 2)
                    self.assertEqual(report["error"], "INTERRUPTED")
                    self.assertEqual(result["output"].count("\n"), 1)
                    self.dead_and_reaped(worker)
                finally:
                    outer.cleanup()

    def test_owned_fixture_cleans_after_assertion_without_expected_http_witness(self):
        actual_mark = self.work / "failure-path-actual-worker.json"
        absent_mark = self.work / "intentionally-unwritten-http-witness.json"
        def blocked_without_expected_mark():
            witness(actual_mark)
            while True: time.sleep(0.02)
        outer = self.owned_main("cleanup-failure-path", ["--lock", str(self.project())],
                                Boundary([Response()], connect=blocked_without_expected_mark), seconds=1.5)
        until = time.monotonic() + 2
        while not actual_mark.exists() and time.monotonic() < until:
            time.sleep(0.01)
        self.assertTrue(actual_mark.exists())
        self.assertFalse(absent_mark.exists())
        worker = json.loads(read_small(actual_mark))
        with self.assertRaises(AssertionError):
            try:
                self.fail("intentional test-local assertion before expected witness acquisition")
            finally:
                outer.cleanup()
        self.assertTrue(outer.reaped)
        self.assertEqual(outer.members(), [])
        self.dead_and_reaped(worker)

    def valid_report(self, code=0):
        return {"status": ("CLEAN", "FINDINGS", "ERROR")[code], "lock_sha256": "a" * 64,
                "manifest_sha256": "b" * 64, "inventory": [{"name": "alpha", "version": "1.0"}],
                "submitted": 1, "completed": 1, "batches": 1,
                "advisories": [{"name": "alpha", "version": "1.0", "ids": ["X"]}] if code == 1 else [],
                "error": "INPUT" if code == 2 else None}

    def test_real_report_validator_rejects_inconsistent_typed_dto(self):
        for code in [0, 1, 2]:
            with self.subTest(label="report-valid-%s" % code):
                report = self.valid_report(code)
                self.assertIs(audit._validate_report(report, code), report)
        bad = [{"unknown": 1}, {"submitted": True}, {"completed": -1}, {"completed": 2},
               {"batches": 2}, {"lock_sha256": "bad"}, {"manifest_sha256": None},
               {"inventory": [{"name": "ALPHA", "version": "1.0"}]},
               {"inventory": [{"name": "alpha", "version": "1.0"}] * 2},
               {"status": "FINDINGS"}, {"error": "INPUT"},
               {"advisories": [{"name": "alpha", "version": "1.0", "ids": ["X"]}]},
               {"advisories": [{"name": "unknown", "version": "1.0", "ids": ["X"]}]}]
        for index, update in enumerate(bad):
            with self.subTest(label="report-invalid-%s" % index):
                report = dict(self.valid_report(), **update)
                with self.assertRaises((ValueError, TypeError, KeyError)):
                    audit._validate_report(report, 0)
        for index, ids in enumerate([[], ["X", "X"], ["Z", "A"], ["\n"], [True]]):
            with self.subTest(label="advisory-ids-%s" % index):
                report = self.valid_report(1); report["advisories"][0]["ids"] = ids
                with self.assertRaises((ValueError, TypeError, KeyError)):
                    audit._validate_report(report, 1)
        for index, category in enumerate(["UNKNOWN", None, True, 1, {}, []]):
            with self.subTest(label="error-category-%s" % index):
                report = self.valid_report(2); report["error"] = category
                with self.assertRaises((ValueError, TypeError, KeyError)):
                    audit._validate_report(report, 2)
        partial = self.valid_report(2)
        partial.update(inventory=[{"name": "pkg%04d" % n, "version": "1.0"} for n in range(1001)],
                       submitted=1001, completed=1000, batches=2, error="OSV_HTTP",
                       advisories=[{"name": "pkg0000", "version": "1.0", "ids": ["X"]}])
        self.assertIs(audit._validate_report(partial, 2), partial)
        partial["advisories"][0]["name"] = "pkg1000"
        with self.assertRaises(ValueError): audit._validate_report(partial, 2)
        report = self.valid_report(); report["inventory"][0]["name"] = "a" * 1048576
        with self.assertRaises(ValueError): audit._validate_report(report, 0)

    def exit_status(self, code):
        pid = os.fork()
        if pid == 0: os._exit(code)
        self.addCleanup(reap_child, pid, 0.1)
        value = reap_child(pid, 2)
        self.assertIsNotNone(value)
        return value

    def worker_envelope(self, code=0):
        report = self.valid_report(code)
        return {"code": code, "report": report, "inventory_sha256": digest(encoded(report["inventory"])),
                "report_sha256": digest(encoded(report))}

    def test_private_memfd_actual_exit_identity_hashes_and_bounds(self):
        fd = os.memfd_create("test-audit-report", os.MFD_CLOEXEC)
        self.addCleanup(os.close, fd)
        os.fchmod(fd, 0o600)
        info = os.fstat(fd); original_identity = (info.st_dev, info.st_ino)
        statuses = {code: self.exit_status(code) for code in [0, 1, 2, 3]}
        for code in [0, 1, 2]:
            with self.subTest(label="ipc-valid-%s" % code):
                raw = encoded(self.worker_envelope(code)); os.ftruncate(fd, 0); os.pwrite(fd, raw, 0)
                actual, report = audit._read_worker_report(fd, original_identity, statuses[code])
                self.summary(actual, report, code)
        envelope = self.worker_envelope()
        cases = [(b"", original_identity, statuses[0], 0o600),
                 (b"{", original_identity, statuses[0], 0o600),
                 (encoded(envelope), (info.st_dev, info.st_ino + 1), statuses[0], 0o600),
                 (encoded(envelope), original_identity, statuses[1], 0o600),
                 (encoded(envelope), original_identity, statuses[3], 0o600),
                 (encoded(envelope), original_identity, statuses[0], 0o644),
                 (b" " * (1048576 + 257), original_identity, statuses[0], 0o600),
                 (encoded(dict(envelope, code=True)), original_identity, statuses[0], 0o600),
                 (encoded(dict(envelope, inventory_sha256="0" * 64)), original_identity, statuses[0], 0o600),
                 (encoded(dict(envelope, report_sha256="0" * 64)), original_identity, statuses[0], 0o600),
                 (encoded(dict(envelope, extra=0)), original_identity, statuses[0], 0o600),
                 (encoded({k: v for k, v in envelope.items() if k != "report"}), original_identity, statuses[0], 0o600),
                 (encoded(envelope)[:-1] + b',"code":0}', original_identity, statuses[0], 0o600)]
        for index, (raw, bound_identity, status, mode) in enumerate(cases):
            with self.subTest(label="ipc-invalid-%s" % index):
                os.fchmod(fd, mode); os.ftruncate(fd, 0); os.pwrite(fd, raw, 0)
                with self.assertRaises((ValueError, TypeError, KeyError)):
                    audit._read_worker_report(fd, bound_identity, status)

    def test_stdout_pipe_flags_broken_and_unsupported_destinations(self):
        lock = self.project()
        read_fd, write_fd = os.pipe()
        writer = io.TextIOWrapper(os.fdopen(write_fd, "wb", closefd=False), encoding="utf-8")
        self.addCleanup(os.close, read_fd); self.addCleanup(os.close, write_fd); self.addCleanup(writer.close)
        before = os.get_blocking(write_fd)
        with contextlib.redirect_stdout(writer), mock.patch.object(audit.http.client, "HTTPSConnection", Boundary([Response()])):
            self.assertEqual(audit.main(["--lock", str(lock)]), 0)
        self.assertEqual(os.get_blocking(write_fd), before)
        ready, _, _ = select.select([read_fd], [], [], 1)
        self.assertEqual(ready, [read_fd])
        raw = os.read(read_fd, 1048576)
        report = json.loads(raw)
        self.summary(0, report, 0)
        self.assertEqual(raw, encoded(report) + b"\n")
        self.assertEqual(report["lock_sha256"], digest(lock.read_bytes()))
        regular_path = self.work / "stdout.txt"
        with regular_path.open("w") as regular, contextlib.redirect_stdout(regular), \
                mock.patch.object(audit.http.client, "HTTPSConnection", Boundary([Response()])):
            self.assertEqual(audit.main(["--lock", str(lock)]), 2)
        self.assertEqual(regular_path.read_bytes(), b"")
        class Custom:
            def __init__(self): self.writes = []
            def write(self, value): self.writes.append(value)
            def flush(self): pass
        custom = Custom()
        with contextlib.redirect_stdout(custom), mock.patch.object(audit.http.client, "HTTPSConnection", Boundary([Response()])):
            self.assertEqual(audit.main(["--lock", str(lock)]), 2)
        self.assertEqual(custom.writes, [])

    def test_broken_pipe_real_main_returns_error_and_reaps_worker(self):
        read_fd, write_fd = os.pipe()
        os.close(read_fd)
        self.addCleanup(os.close, write_fd)
        mark = self.work / "broken-worker.json"
        def connected(): witness(mark)
        before = os.get_blocking(write_fd)
        started = time.monotonic()
        outer = self.owned_main("broken-output", ["--lock", str(self.project())],
                                Boundary([Response()], connect=connected), output_fd=write_fd)
        try:
            result = self.owned_summary(outer, 4)
            self.assertEqual(result["code"], 2)
            self.assertIsNone(result["output"])
            self.assertEqual(os.get_blocking(write_fd), before)
            self.assertLess(time.monotonic() - started, 3.5)
            self.dead_and_reaped(json.loads(read_small(mark)))
        finally:
            outer.cleanup()

    def test_blocked_output_real_main_is_bounded_without_fallback_json(self):
        read_fd, write_fd = os.pipe()
        self.addCleanup(os.close, read_fd); self.addCleanup(os.close, write_fd)
        os.set_blocking(write_fd, False)
        filled = 0
        while filled <= 1048576:
            try: filled += os.write(write_fd, b"x" * 4096)
            except BlockingIOError: break
        self.assertLessEqual(filled, 1048576)
        os.set_blocking(write_fd, True)
        mark = self.work / "backpressure-worker.json"
        def connected(): witness(mark)
        started = time.monotonic()
        outer = self.owned_main("blocked-output", ["--lock", str(self.project())],
                                Boundary([Response()], connect=connected), output_fd=write_fd)
        try:
            result = self.owned_summary(outer, 4)
            self.assertEqual(result["code"], 2)
            self.assertTrue(os.get_blocking(write_fd))
            self.assertLess(time.monotonic() - started, 3.5)
            self.dead_and_reaped(json.loads(read_small(mark)))
            os.set_blocking(read_fd, False)
            received = bytearray()
            while len(received) < filled:
                try: received.extend(os.read(read_fd, min(65536, filled - len(received))))
                except BlockingIOError: break
            self.assertEqual(bytes(received), b"x" * filled)
            with self.assertRaises(BlockingIOError): os.read(read_fd, 1)
        finally:
            outer.cleanup()

    def test_scanner_import_is_passive(self):
        output = io.StringIO()
        boundary = Boundary([])
        child_file = Path("/proc/self/task/%s/children" % os.getpid())
        before = child_file.read_text()
        name = "audit_python_lock_second_import"
        spec = importlib.util.spec_from_file_location(name, SCANNER_PATH)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        self.addCleanup(sys.modules.pop, name, None)
        with mock.patch.object(audit.http.client, "HTTPSConnection", boundary), contextlib.redirect_stdout(output):
            spec.loader.exec_module(module)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(boundary.connections, [])
        self.assertEqual(child_file.read_text(), before)


if __name__ == "__main__":
    unittest.main()
