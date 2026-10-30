"""Linux-only CLI safety regressions using synthetic databases and real tools."""

import contextlib
import datetime
import errno
import gzip
import json
import os
from pathlib import Path
import resource
import selectors
import shutil
import signal
import sqlite3
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest


REPO = Path(__file__).resolve().parents[1]


class BackupRestoreTests(unittest.TestCase):
    _unreaped_anchors = []
    @classmethod
    def setUpClass(cls):
        if sys.platform != "linux" or os.geteuid() == 0:
            raise RuntimeError("TEST_ENVIRONMENT_REQUIRES_NONROOT_LINUX")
        if not hasattr(os, "WNOWAIT") or signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
            raise RuntimeError("TEST_ENVIRONMENT_REQUIRES_WAITABLE_OWNED_CHILDREN")
        cls.tools = {name: shutil.which(name, path=os.defpath) for name in
                     ("bash", "sqlite3", "gzip", "gunzip", "find", "stat", "cp", "mv",
                      "mktemp", "date", "mkdir", "du", "cut", "wc", "rm")}
        missing = [name for name, path in cls.tools.items() if path is None]
        if missing:
            raise RuntimeError("TEST_ENVIRONMENT_MISSING_TOOLS: " + ",".join(missing))
        cls.scripts = {name: REPO / "scripts" / (name + ".sh")
                       for name in ("backup", "restore")}
        for name, path in cls.scripts.items():
            source = path.read_text(encoding="utf-8")
            if "/bin/systemctl" in source or "/sbin/systemctl" in source:
                raise RuntimeError("TEST_BOUNDARY_REQUIRES_NAME_RESOLVED_SYSTEMCTL")
            checked = subprocess.run([cls.tools["bash"], "-n", str(path)],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                     timeout=5, check=False)
            if checked.returncode:
                raise RuntimeError("TEST_ENVIRONMENT_BASH_SYNTAX: " + name)
        print("BACKUP_RESTORE_PREFLIGHT tools=real bash_syntax=ok synthetic_only=true")

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="trueid-recovery-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.work = self.root / "work"
        self.live = self.work / "live"
        self.inputs = self.root / "inputs"
        self.output = self.root / "backups"
        self.control = self.root / "control"
        self.bin = self.root / "bin"
        for path in (self.work, self.live, self.inputs, self.output, self.control,
                     self.bin, self.root / "home", self.root / "tmp"):
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.chmod(0o700)
        self.target = self.live / "net-identity.db"
        self.state = self.control / "state.json"
        self.calls = self.control / "calls.jsonl"
        self.marker = self.control / "entered"
        self.release = self.control / "release"
        os.mkfifo(self.release, 0o600)
        self.calls.write_bytes(b"")
        self.calls.chmod(0o600)
        self.restore_ledgers = []
        self._control("inactive")
        shim = "#!" + sys.executable + "\n" + textwrap.dedent(r'''
            import json
            import os
            from pathlib import Path
            import stat
            import sys
            os.umask(0o077)
            root = Path(os.environ["TEST_CONTROL"])
            args = sys.argv[1:]
            record = (json.dumps(args) + "\n").encode()
            log_path = root / "calls.jsonl"
            if log_path.stat().st_size + len(record) > 65536:
                raise SystemExit(78)
            with log_path.open("ab") as log:
                log.write(record)
            cfg = json.loads((root / "state.json").read_text())
            commands = [arg for arg in args if arg in ("show", "is-active")]
            if len(commands) != 1:
                raise SystemExit(79)
            units = [arg.removesuffix(".service") + ".service"
                     for arg in args if arg.startswith("trueid-")]
            if not units or any(unit not in cfg["units"] for unit in units):
                raise SystemExit(4)
            mode = cfg["barrier"]
            candidate = False
            if mode in ("pause_after_candidate", "active_after_candidate") or any(
                    value == "active_after_candidate" for value in cfg["units"].values()):
                for path in Path(cfg["parent"]).rglob("*"):
                    if str(path) == cfg["target"]:
                        continue
                    try:
                        if stat.S_ISREG(path.lstat().st_mode):
                            with path.open("rb") as handle:
                                candidate |= handle.read(16) == b"SQLite format 3\x00"
                    except OSError:
                        pass
            if candidate and mode == "pause_after_candidate":
                try:
                    with (root / "entered").open("x") as marker:
                        marker.write("ready\n")
                    with (root / "release").open("rb", buffering=0) as release:
                        release.read(1)
                except FileExistsError:
                    pass
            states = []
            for unit in units:
                value = cfg["units"][unit]
                if value == "active_after_candidate":
                    value = "active" if candidate else "inactive"
                states.append("active" if candidate and mode == "active_after_candidate" else value)
            if "malformed" in states:
                print("not-a-systemd-state")
                raise SystemExit(0)
            loaded = ["not-found" if state in ("unknown", "not-found") else "loaded"
                      for state in states]
            active = ["inactive" if load == "not-found" else state
                      for load, state in zip(loaded, states)]
            if commands[0] == "is-active":
                if "--quiet" not in args:
                    print("\n".join(active))
                raise SystemExit(0 if "active" in active else 4 if "not-found" in loaded else 3)
            props = []
            for index, arg in enumerate(args):
                if arg.startswith("--property="):
                    props.extend(arg.split("=", 1)[1].split(","))
                elif arg in ("--property", "-p") and index + 1 < len(args):
                    props.extend(args[index + 1].split(","))
            props = props or ["Id", "LoadState", "ActiveState", "SubState"]
            substates = {"inactive": "dead", "active": "running", "failed": "failed",
                         "activating": "start", "deactivating": "stop", "reloading": "reload"}
            for index, unit in enumerate(units):
                if index:
                    print()
                values = {"Id": unit, "LoadState": loaded[index], "ActiveState": active[index],
                          "SubState": substates.get(active[index], "unknown"),
                          "User": str(os.getuid()), "Group": str(os.getgid())}
                for prop in props:
                    value = values.get(prop, "")
                    print(value if "--value" in args else prop + "=" + value)
            raise SystemExit(4 if "not-found" in loaded else 0)
        ''')
        (self.bin / "systemctl").write_text(shim, encoding="utf-8")
        (self.bin / "systemctl").chmod(0o700)

    def _control(self, mode):
        required = {"trueid-web.service", "trueid-engine.service"}
        barrier = mode if isinstance(mode, str) and mode.endswith("_candidate") else None
        units = ({unit: "inactive" if barrier else mode for unit in required}
                 if isinstance(mode, str) else dict(mode))
        self.assertEqual(set(units), required, "FIXTURE_REQUIRES_BOTH_UNIT_STATES")
        self.state.write_text(json.dumps({"units": units, "barrier": barrier,
                                          "target": str(self.target), "parent": str(self.live)}),
                              encoding="utf-8")
        self.state.chmod(0o600)
        self.marker.unlink(missing_ok=True)

    def _env(self, changes=None):
        env = {"PATH": str(self.bin) + os.pathsep + os.defpath,
               "HOME": str(self.root / "home"), "TMPDIR": str(self.root / "tmp"),
               "LC_ALL": "C", "TZ": "UTC", "PYTHONDONTWRITEBYTECODE": "1",
               "TEST_CONTROL": str(self.control)}
        env.update(changes or {})
        return env

    @staticmethod
    def _leader_status(process):
        if process.returncode is not None:
            raise RuntimeError("OWNED_ANCHOR_ALREADY_REAPED")
        observed = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        if observed is not None and (observed.si_pid != process.pid or observed.si_code not in
                                     (os.CLD_EXITED, os.CLD_KILLED, os.CLD_DUMPED)):
            raise RuntimeError("OWNED_LEADER_STATUS_INVALID")
        return observed

    def _signal_owned(self, process, number):
        self._leader_status(process)
        if process.pid == os.getpgrp() or os.getpgid(process.pid) != process.pid:
            raise RuntimeError("OWNED_SESSION_IDENTITY_LOST")
        os.killpg(process.pid, number)

    @staticmethod
    def _owned_live_group(pid, deadline):
        live = []
        count = 0
        with os.scandir("/proc") as entries:
            for entry in entries:
                if time.monotonic() >= deadline:
                    raise TimeoutError("OWNED_DRAIN_DEADLINE")
                if not entry.name.isdecimal():
                    continue
                count += 1
                if count > 4096:
                    raise RuntimeError("OWNED_PROC_SCAN_CAP")
                fd = None
                try:
                    if os.getpgid(int(entry.name)) != pid:
                        continue
                    fd = os.open(entry.path + "/stat", os.O_RDONLY | os.O_CLOEXEC |
                                 os.O_NOFOLLOW | os.O_NONBLOCK)
                    raw = os.read(fd, 4097)
                    if len(raw) > 4096:
                        raise RuntimeError("OWNED_PROC_STAT_CAP")
                    fields = raw.rpartition(b") ")[2].split()
                    if len(fields) < 4:
                        raise RuntimeError("OWNED_PROC_STAT_INVALID")
                    if int(fields[2]) == pid and int(entry.name) != pid:
                        if int(fields[3]) != pid:
                            raise RuntimeError("OWNED_GROUP_SESSION_MISMATCH")
                        if fields[0] not in (b"Z", b"X"):
                            live.append(int(entry.name))
                except OSError as error:
                    if error.errno not in (errno.ENOENT, errno.ESRCH):
                        raise
                finally:
                    if fd is not None:
                        os.close(fd)
        return live

    def _invoke(self, argv, *, env=None, answer=None, limit=None, barrier=None):
        deadline = time.monotonic() + 10
        operation_end = deadline - 2
        if answer is not None and (not isinstance(answer, bytes) or len(answer) > 16):
            raise RuntimeError("OWNED_INPUT_BOUND")
        if barrier is not None and barrier[0] not in ("observe", "deny_replace", "sidecar", "interrupt"):
            raise RuntimeError("OWNED_BARRIER_KIND")
        def child_setup():
            os.umask(0o022)
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            if limit is not None:
                resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
        process = subprocess.Popen(argv, cwd=self.work, env=self._env(env),
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True,
                                   preexec_fn=child_setup)
        selector = selectors.DefaultSelector()
        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        sent = 0
        action_done = barrier is None
        barrier_done = barrier is None
        failure = None
        terminal = None
        def remember(error):
            nonlocal failure
            if failure is None:
                failure = error
            elif hasattr(failure, "add_note"):
                failure.add_note("OWNED_CLEANUP_FAILURE: " + repr(error))
            else:
                print("OWNED_CLEANUP_FAILURE: " + repr(error), file=sys.stderr)
        def close_input():
            if not process.stdin.closed:
                with contextlib.suppress(KeyError):
                    selector.unregister(process.stdin)
                process.stdin.close()
        def pump(discard=False, until=operation_end):
            nonlocal sent
            for key, _ in selector.select(min(0.02, max(0, until - time.monotonic()))):
                if key.data == "stdin":
                    try:
                        sent += os.write(key.fd, answer[sent:])
                    except BrokenPipeError:
                        close_input()
                    except BlockingIOError:
                        continue
                    if not process.stdin.closed and sent == len(answer):
                        close_input()
                    continue
                room = 1048575 - sum(map(len, buffers.values()))
                try:
                    part = os.read(key.fd, 65536 if discard else min(65536, room + 1))
                except BlockingIOError:
                    continue
                if not part:
                    selector.unregister(key.fileobj)
                elif not discard:
                    buffers[key.data].extend(part[:room])
                    if len(part) > room:
                        raise RuntimeError("OWNED_CAPTURE_LIMIT")
        try:
            for stream, name in ((process.stdout, "stdout"), (process.stderr, "stderr")):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, name)
            if answer:
                os.set_blocking(process.stdin.fileno(), False)
                selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
            else:
                close_input()
            while True:
                if time.monotonic() >= operation_end:
                    raise TimeoutError("OWNED_OPERATION_DEADLINE")
                terminal = self._leader_status(process)
                if barrier is not None and not barrier_done and self.marker.exists():
                    if not action_done:
                        kind, expected = barrier
                        if kind == "observe":
                            with self.target.open("rb") as handle:
                                actual = handle.read(len(expected) + 1)
                            self.assertEqual(actual, expected, "TARGET_CHANGED_BEFORE_ACTIVATION")
                        elif kind == "deny_replace":
                            self.live.chmod(0o500)
                        elif kind == "sidecar":
                            sidecar = Path(str(self.target) + "-wal")
                            sidecar.write_bytes(b"late-writer-state")
                            sidecar.chmod(0o600)
                        else:
                            self._signal_owned(process, signal.SIGTERM)
                            barrier_done = True
                        action_done = True
                    if not barrier_done:
                        fd = None
                        try:
                            fd = os.open(self.release, os.O_WRONLY | os.O_NONBLOCK)
                            if os.write(fd, b"x") == 1:
                                barrier_done = True
                        except OSError as error:
                            if error.errno not in (errno.ENXIO, errno.EAGAIN):
                                raise
                        finally:
                            if fd is not None:
                                os.close(fd)
                if terminal is not None:
                    code = terminal.si_status if terminal.si_code == os.CLD_EXITED else -terminal.si_status
                    self.assertTrue(barrier_done,
                                    "RESTORE_STAGED_OFFLINE_GUARD_NOT_REACHED exit=" + str(code))
                    break
                pump()
        except BaseException as error:
            remember(error)
        try:
            self._signal_owned(process, signal.SIGKILL)
            try:
                close_input()
            except BaseException as input_error:
                remember(input_error)
            while True:
                if time.monotonic() >= deadline:
                    raise TimeoutError("OWNED_DRAIN_DEADLINE")
                terminal = self._leader_status(process)
                try:
                    pump(discard=failure is not None, until=deadline)
                except RuntimeError as capture_error:
                    if str(capture_error) != "OWNED_CAPTURE_LIMIT":
                        raise
                    remember(capture_error)
                    continue
                if terminal is not None and not selector.get_map():
                    if not self._owned_live_group(process.pid, deadline):
                        break
            expected_code = terminal.si_status if terminal.si_code == os.CLD_EXITED else -terminal.si_status
            actual_code = process.wait(timeout=0)
            if actual_code != expected_code:
                raise RuntimeError("OWNED_REAP_STATUS_MISMATCH")
        except BaseException as cleanup_error:
            if process.returncode is None:
                self._unreaped_anchors.append(process)
            remember(cleanup_error)
        finally:
            try:
                selector.close()
            except BaseException as close_error:
                remember(close_error)
            for stream in (process.stdin, process.stdout, process.stderr):
                try:
                    stream.close()
                except BaseException as close_error:
                    remember(close_error)
        if failure is not None:
            raise failure
        return subprocess.CompletedProcess(argv, actual_code, bytes(buffers["stdout"]),
                                           bytes(buffers["stderr"]))

    def _record_restore(self, result=None):
        with self.calls.open("rb") as handle:
            raw = handle.read(65537)
        self.assertLessEqual(len(raw), 65536, "FIXTURE_CONTROL_LEDGER_CAP")
        calls = [json.loads(line) for line in raw.splitlines()]
        probed = {arg.removesuffix(".service") + ".service" for call in calls for arg in call
                  if arg.startswith("trueid-")}
        ledger = {"invocation": len(self.restore_ledgers) + 1, "commands": calls,
                  "units": sorted(probed), "returncode": None if result is None else result.returncode}
        self.restore_ledgers.append(ledger)
        self.assertTrue(all("show" in call or "is-active" in call for call in calls),
                        "RESTORE_CHANGED_SERVICE_STATE")
        return ledger

    def _script(self, name, args, *, env=None, answer=b"y\n", **kwargs):
        if name == "restore":
            self.calls.write_bytes(b"")
        try:
            result = self._invoke([self.tools["bash"], str(self.scripts[name]), *map(str, args)],
                                  env=env, answer=answer, **kwargs)
        except BaseException as error:
            if name == "restore":
                try:
                    self._record_restore()
                except BaseException as ledger_error:
                    if hasattr(error, "add_note"):
                        error.add_note("RESTORE_LEDGER_FAILURE: " + repr(ledger_error))
                    else:
                        print("RESTORE_LEDGER_FAILURE: " + repr(ledger_error), file=sys.stderr)
            raise
        if name == "restore":
            ledger = self._record_restore(result)
            if result.returncode == 0 and answer != b"n\n":
                self.assertEqual(set(ledger["units"]),
                                 {"trueid-web.service", "trueid-engine.service"},
                                 "BOTH_RESTORE_UNITS_NOT_OBSERVED_IN_THIS_INVOCATION")
        return result

    @staticmethod
    def _note(result):
        return (result.stdout + result.stderr).decode("utf-8", "replace")[-4000:]

    def _db(self, path, value, blob_bytes=0):
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with contextlib.closing(sqlite3.connect(path)) as connection, connection:
            connection.execute("CREATE TABLE fixture (id INTEGER PRIMARY KEY, value TEXT, data BLOB)")
            connection.execute("INSERT INTO fixture VALUES (1, ?, zeroblob(?))", (value, blob_bytes))
        path.chmod(0o600)
        return path

    def _rows(self, path):
        with contextlib.closing(sqlite3.connect("file:" + str(path) + "?mode=ro&immutable=1", uri=True)) as connection:
            self.assertEqual(connection.execute("PRAGMA integrity_check").fetchall(), [("ok",)])
            return connection.execute("SELECT id, value, length(data) FROM fixture ORDER BY id").fetchall()

    def _gz(self, source, target):
        result = self._invoke([self.tools["gzip"], "-c", str(source)])
        self.assertEqual(result.returncode, 0, "FIXTURE_GZIP_FAILED: " + self._note(result))
        target.write_bytes(result.stdout)
        target.chmod(0o600)
        return target

    def _read_backup(self, path):
        checked = self._invoke([self.tools["gzip"], "-t", str(path)])
        self.assertEqual(checked.returncode, 0, "PUBLISHED_GZIP_INVALID: " + self._note(checked))
        decoded = self.root / "inspected.db"
        decoded.write_bytes(gzip.decompress(path.read_bytes()))
        decoded.chmod(0o600)
        return self._rows(decoded)

    def _published(self, directory=None):
        return sorted((directory or self.output).glob("trueid-*.db.gz"))

    def _assert_failed_unchanged(self, result, before, metadata):
        self.assertNotEqual(result.returncode, 0, "UNSAFE_RESTORE_ACCEPTED: " + self._note(result))
        self.assertEqual(self.target.read_bytes(), before, "TARGET_CHANGED_ON_REFUSAL")
        current = self.target.stat()
        self.assertEqual((current.st_uid, current.st_gid, stat.S_IMODE(current.st_mode)), metadata,
                         "TARGET_METADATA_CHANGED_ON_REFUSAL")

    def _restore_fixture(self, blob_bytes=0):
        self._db(self.target, "original")
        self.target.chmod(0o644)
        incoming = self._db(self.inputs / "incoming.db", "replacement", blob_bytes)
        meta = self.target.stat()
        return incoming, self.target.read_bytes(), (meta.st_uid, meta.st_gid, 0o644)

    def _restore(self, source, **kwargs):
        return self._script("restore", [source],
                            env={"DATABASE_URL": "sqlite://" + str(self.target)}, **kwargs)

    def test_backup_preserves_legacy_default_database(self):
        self._db(self.work / "net-identity.db", "legacy-default")
        self._db(self.work / "data" / "net-identity.db", "different-configured-db")
        result = self._script("backup", [self.output])
        self.assertEqual(result.returncode, 0, self._note(result))
        self.assertEqual(len(self._published()), 1)
        self.assertEqual(self._read_backup(self._published()[0]), [(1, "legacy-default", 0)])

    def test_configured_sqlite_forms_queries_and_spaces_select_the_right_db(self):
        self._db(self.work / "net-identity.db", "decoy")
        chosen = self._db(self.work / "data" / "selected db.sqlite3", "configured")
        values = [str(chosen), "sqlite://" + str(chosen) + "?mode=rwc",
                  "sqlite:" + str(chosen) + "?mode=rw&cache=shared",
                  "sqlite:data/selected db.sqlite3?mode=rwc&cache=shared"]
        for index, value in enumerate(values):
            with self.subTest(uri_form=index):
                out = self.output / ("case " + str(index))
                out.mkdir(mode=0o700)
                result = self._script("backup", [out], env={"DATABASE_URL": value})
                self.assertEqual(result.returncode, 0, "CONFIGURED_DB_NOT_CAPTURED: " + self._note(result))
                self.assertEqual(len(self._published(out)), 1)
                self.assertEqual(self._read_backup(self._published(out)[0]), [(1, "configured", 0)])

    def test_backup_online_snapshot_includes_committed_wal_rows(self):
        source = self._db(self.work / "net-identity.db", "before-wal")
        with contextlib.closing(sqlite3.connect(source)) as connection, connection:
            self.assertEqual(connection.execute("PRAGMA journal_mode=WAL").fetchone()[0], "wal")
            connection.execute("PRAGMA wal_autocheckpoint=0")
            connection.execute("INSERT INTO fixture VALUES (2, 'committed-in-wal', zeroblob(7))")
            connection.commit()
            self.assertTrue(Path(str(source) + "-wal").is_file(), "FIXTURE_WAL_NOT_HELD")
            result = self._script("backup", [self.output])
            self.assertEqual(result.returncode, 0, self._note(result))
            self.assertEqual(self._read_backup(self._published()[0]),
                             [(1, "before-wal", 0), (2, "committed-in-wal", 7)])
            self.assertTrue(Path(str(source) + "-wal").exists(), "LIVE_WAL_REMOVED")

    def test_backup_publishes_private_valid_object_without_raw_final_files(self):
        self._db(self.work / "net-identity.db", "private")
        result = self._script("backup", [self.output])
        self.assertEqual(result.returncode, 0, self._note(result))
        points = self._published()
        self.assertEqual(len(points), 1)
        self.assertEqual(stat.S_IMODE(points[0].stat().st_mode), 0o600, "BACKUP_NOT_PRIVATE")
        self.assertEqual(points[0].stat().st_nlink, 1)
        self.assertEqual(self._read_backup(points[0]), [(1, "private", 0)])
        self.assertEqual(list(self.output.glob("trueid-*.db")), [], "RAW_FINAL_FILE_LEAK")

    def test_backup_refuses_sqlite_corruption_even_when_copying_pages_can_succeed(self):
        source = self._db(self.work / "net-identity.db", "corrupt-index")
        with contextlib.closing(sqlite3.connect(source)) as connection, connection:
            connection.execute("CREATE INDEX fixture_value ON fixture(value)")
            page = connection.execute("SELECT rootpage FROM sqlite_schema WHERE name='fixture_value'").fetchone()[0]
            size = connection.execute("PRAGMA page_size").fetchone()[0]
        with source.open("r+b") as handle:
            handle.seek((page - 1) * size)
            handle.write(bytes(16))
        checked = self._invoke([self.tools["sqlite3"], "-readonly", str(source), "PRAGMA integrity_check;"])
        self.assertTrue(checked.returncode or checked.stdout.strip() != b"ok", "FIXTURE_CORRUPTION_NOT_REACHED")
        result = self._script("backup", [self.output])
        self.assertNotEqual(result.returncode, 0, "CORRUPT_SNAPSHOT_PUBLISHED: " + self._note(result))
        self.assertEqual(self._published(), [])

    def test_backup_write_failure_cleans_candidate_and_preserves_aged_point(self):
        self._db(self.work / "net-identity.db", "large", 131072)
        old = self.output / "trueid-old.db.gz"
        self._gz(self._db(self.inputs / "prior.db", "old-verified"), old)
        old_bytes = old.read_bytes()
        self.assertEqual(self._read_backup(old), [(1, "old-verified", 0)])
        os.utime(old, (time.time() - 90 * 86400,) * 2)
        result = self._script("backup", [self.output], limit=16384)
        self.assertNotEqual(result.returncode, 0, "WRITE_LIMIT_NOT_REACHED")
        self.assertEqual(old.read_bytes(), old_bytes)
        self.assertEqual(self._published(), [old])
        self.assertEqual(list(self.output.glob("trueid-*.db")), [], "PARTIAL_FINAL_DB_EXPOSED")

    def test_retention_runs_only_after_success_and_never_removes_new_point(self):
        source = self._db(self.work / "net-identity.db", "new-verified-point")
        old = self._gz(source, self.output / "trueid-old.db.gz")
        young = self._gz(source, self.output / "trueid-young.db.gz")
        os.utime(old, (time.time() - 90 * 86400,) * 2)
        young_bytes = young.read_bytes()
        result = self._script("backup", [self.output], env={"BACKUP_KEEP_DAYS": "30"})
        self.assertEqual(result.returncode, 0, self._note(result))
        self.assertFalse(old.exists(), "LEGACY_RETENTION_DISABLED")
        self.assertEqual(young.read_bytes(), young_bytes)
        new = [path for path in self._published() if path != young]
        self.assertEqual(len(new), 1, "NEW_VERIFIED_POINT_NOT_RETAINED")
        identity = new[0].stat()
        self.assertEqual(self._read_backup(new[0]), [(1, "new-verified-point", 0)])
        self.assertEqual((new[0].stat().st_dev, new[0].stat().st_ino),
                         (identity.st_dev, identity.st_ino))

    def test_retention_keep_zero_and_empty_default_preserve_expected_age_semantics(self):
        source = self._db(self.work / "net-identity.db", "retention")
        for index, keep in enumerate(("0", "", "7")):
            with self.subTest(keep=keep):
                out = self.output / str(index)
                out.mkdir(mode=0o700)
                old = self._gz(source, out / "trueid-old.db.gz")
                os.utime(old, (time.time() - 90 * 86400,) * 2)
                result = self._script("backup", [out], env={"BACKUP_KEEP_DAYS": keep})
                self.assertEqual(result.returncode, 0, self._note(result))
                self.assertFalse(old.exists(), "VALID_LOCAL_RETENTION_NOT_APPLIED")
                self.assertEqual(len(self._published(out)), 1, "NEW_POINT_PRUNED")

    def test_retention_preserves_symlink_hardlink_and_nonregular_objects(self):
        source = self._db(self.work / "net-identity.db", "retention-safety")
        outside = self._gz(source, self.inputs / "outside.gz")
        linked = self.output / "trueid-linked.db.gz"
        hard = self.output / "trueid-hard.db.gz"
        directory = self.output / "trueid-directory.db.gz"
        fifo = self.output / "trueid-fifo.db.gz"
        linked.symlink_to(outside)
        os.link(outside, hard)
        directory.mkdir(mode=0o700)
        os.mkfifo(fifo, 0o600)
        old_time = time.time() - 90 * 86400
        for path in (linked, hard, directory, fifo):
            os.utime(path, (old_time, old_time), follow_symlinks=False)
        before = outside.read_bytes()
        result = self._script("backup", [self.output])
        self.assertEqual(result.returncode, 0, self._note(result))
        self.assertTrue(linked.is_symlink(), "RETENTION_DELETED_UNSAFE_SYMLINK")
        self.assertTrue(hard.exists(), "RETENTION_DELETED_ALIASED_OBJECT")
        self.assertTrue(directory.is_dir(), "RETENTION_DELETED_NONREGULAR_DIRECTORY")
        self.assertTrue(stat.S_ISFIFO(fifo.lstat().st_mode), "RETENTION_DELETED_FIFO")
        self.assertEqual(outside.read_bytes(), before)

    def test_invalid_retention_fails_before_any_publication_or_deletion(self):
        self._db(self.work / "net-identity.db", "invalid-retention")
        old = self.output / "trueid-old.db.gz"
        self._gz(self.work / "net-identity.db", old)
        old_bytes = old.read_bytes()
        os.utime(old, (time.time() - 90 * 86400,) * 2)
        result = self._script("backup", [self.output], env={"BACKUP_KEEP_DAYS": "not-a-number"})
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(old.read_bytes(), old_bytes)
        self.assertEqual(self._published(), [old], "PUBLISHED_BEFORE_RETENTION_SETTING_VALIDATION")

    def test_backup_does_not_clobber_existing_timestamp_names(self):
        self._db(self.work / "net-identity.db", "collision")
        prior = self._gz(self._db(self.inputs / "collision-prior.db", "existing"),
                         self.inputs / "collision-prior.db.gz").read_bytes()
        now = datetime.datetime.now(datetime.timezone.utc)
        before = {}
        for offset in range(-30, 31):
            stamp = (now + datetime.timedelta(seconds=offset)).strftime("%Y%m%d-%H%M%S")
            path = self.output / ("trueid-" + stamp + ".db.gz")
            path.write_bytes(prior)
            path.chmod(0o600)
            before[path] = path.read_bytes()
        result = self._script("backup", [self.output])
        for path, data in before.items():
            self.assertEqual(path.read_bytes(), data, "EXISTING_POINT_CLOBBERED")
        self.assertEqual(list(self.output.glob("trueid-*.db")), [], "COLLISION_LEFT_RAW_FINAL_DB")
        if result.returncode == 0:
            self.assertEqual(len([p for p in self._published() if p not in before]), 1)

    def test_backup_unit_requires_actual_environment_and_private_umask(self):
        unit = (REPO / "deploy/systemd/trueid-backup.service").read_text(encoding="utf-8")
        self.assertIn("EnvironmentFile=/opt/trueid/.env", unit, "BACKUP_UNIT_OMITS_CONFIGURATION")
        self.assertIn("UMask=0077", unit, "BACKUP_UNIT_UMASK_NOT_PRIVATE")
        self.assertIn("User=trueid", unit)
        self.assertIn("WorkingDirectory=/opt/trueid", unit)

    def test_restore_refuses_active_unknown_failed_and_malformed_service_states(self):
        incoming, original, metadata = self._restore_fixture()
        for mode in ("active", "unknown", "not-found", "failed", "activating", "malformed"):
            with self.subTest(state=mode):
                self.target.write_bytes(original)
                self.target.chmod(metadata[2])
                self._control(mode)
                result = self._restore(incoming)
                self._assert_failed_unchanged(result, original, metadata)

    def test_restore_valid_raw_and_gzip_preserve_owner_and_private_mode(self):
        incoming, original, metadata = self._restore_fixture()
        compressed = self._gz(incoming, self.inputs / "incoming.db.gz")
        for source in (incoming, compressed):
            with self.subTest(compressed=source.suffix == ".gz"):
                self.target.write_bytes(original)
                self.target.chmod(0o644)
                self._control("inactive")
                result = self._restore(source)
                self.assertEqual(result.returncode, 0, self._note(result))
                self.assertEqual(self._rows(self.target), [(1, "replacement", 0)])
                current = self.target.stat()
                self.assertEqual((current.st_uid, current.st_gid), metadata[:2], "OWNER_CHANGED")
                self.assertEqual(stat.S_IMODE(current.st_mode), 0o600, "RESTORED_DB_NOT_PRIVATE")
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertTrue(calls, "OFFLINE_STATE_NOT_OBSERVED")
        self.assertTrue(all("show" in call or "is-active" in call for call in calls),
                        "RESTORE_CHANGED_SERVICE_STATE")

    def test_restore_cancel_preserves_legacy_no_change_exit(self):
        incoming, original, metadata = self._restore_fixture()
        result = self._restore(incoming, answer=b"n\n")
        self.assertEqual(result.returncode, 0, self._note(result))
        self.assertEqual(self.target.read_bytes(), original)
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), metadata[2])

    def test_restore_rejects_corrupt_gzip_and_non_sqlite_before_target_write(self):
        incoming, original, metadata = self._restore_fixture()
        good = self._gz(incoming, self.inputs / "complete.db.gz")
        truncated = self.inputs / "truncated.db.gz"
        truncated.write_bytes(good.read_bytes()[:-8])
        invalid = self.inputs / "invalid.db"
        invalid.write_bytes(b"not a SQLite database")
        empty = self.inputs / "empty.db"
        empty.write_bytes(b"")
        for path in (truncated, invalid, empty):
            with self.subTest(input=path.name):
                self.target.write_bytes(original)
                self.target.chmod(metadata[2])
                result = self._restore(path)
                self._assert_failed_unchanged(result, original, metadata)

    def test_restore_write_limit_does_not_truncate_original(self):
        incoming, original, metadata = self._restore_fixture(131072)
        compressed = self._gz(incoming, self.inputs / "large.db.gz")
        self.assertLess(len(original), 16384, "FIXTURE_OLD_DB_TOO_LARGE")
        result = self._restore(compressed, limit=16384)
        self._assert_failed_unchanged(result, original, metadata)

    def test_restore_preserves_target_and_input_sidecars(self):
        incoming, original, metadata = self._restore_fixture()
        for base in (self.target, incoming):
            for suffix in ("-wal", "-shm", "-journal"):
                with self.subTest(sidecar=(base.name, suffix)):
                    self.target.write_bytes(original)
                    self.target.chmod(metadata[2])
                    sidecar = Path(str(base) + suffix)
                    sidecar.write_bytes(b"sidecar-must-survive")
                    sidecar.chmod(0o600)
                    try:
                        result = self._restore(incoming)
                        self._assert_failed_unchanged(result, original, metadata)
                        self.assertEqual(sidecar.read_bytes(), b"sidecar-must-survive",
                                         "SIDECAR_DELETED_OR_MODIFIED")
                    finally:
                        sidecar.unlink(missing_ok=True)

    def test_restore_refuses_symlink_target_and_input(self):
        incoming, original, metadata = self._restore_fixture()
        protected = self.live / "protected.db"
        protected.write_bytes(original)
        protected.chmod(metadata[2])
        self.target.unlink()
        self.target.symlink_to(protected)
        result = self._restore(incoming)
        self.assertNotEqual(result.returncode, 0, "SYMLINK_TARGET_ACCEPTED")
        self.assertEqual(protected.read_bytes(), original, "SYMLINK_TARGET_FOLLOWED")
        self.assertTrue(self.target.is_symlink())
        self.target.unlink()
        self.target.write_bytes(original)
        self.target.chmod(metadata[2])
        linked = self.inputs / "linked.db"
        linked.symlink_to(incoming)
        result = self._restore(linked)
        self._assert_failed_unchanged(result, original, metadata)

    def test_restore_rechecks_offline_state_after_staging(self):
        incoming, original, metadata = self._restore_fixture()
        self._control("active_after_candidate")
        result = self._restore(incoming)
        self._assert_failed_unchanged(result, original, metadata)

    def test_restore_private_staging_precedes_atomic_activation(self):
        incoming, original, metadata = self._restore_fixture()
        self._control("pause_after_candidate")
        result = self._restore(incoming, barrier=("observe", original))
        self.assertEqual(result.returncode, 0, self._note(result))
        self.assertEqual(self._rows(self.target), [(1, "replacement", 0)])

    def test_restore_atomic_activation_failure_preserves_original(self):
        incoming, original, metadata = self._restore_fixture()
        self._control("pause_after_candidate")
        try:
            result = self._restore(incoming, barrier=("deny_replace", None))
        finally:
            self.live.chmod(0o700)
        self._assert_failed_unchanged(result, original, metadata)

    def test_restore_late_sidecar_change_refuses_without_deletion(self):
        incoming, original, metadata = self._restore_fixture()
        self._control("pause_after_candidate")
        sidecar = Path(str(self.target) + "-wal")
        result = self._restore(incoming, barrier=("sidecar", None))
        self._assert_failed_unchanged(result, original, metadata)
        self.assertEqual(sidecar.read_bytes(), b"late-writer-state")

    def test_restore_late_interruption_preserves_original_and_drains(self):
        incoming, original, metadata = self._restore_fixture()
        self._control("pause_after_candidate")
        result = self._restore(incoming, barrier=("interrupt", None))
        self._assert_failed_unchanged(result, original, metadata)

    def test_restore_retains_byte_verified_original_and_supports_rollback_cli(self):
        incoming, original, metadata = self._restore_fixture()
        result = self._restore(incoming)
        self.assertEqual(result.returncode, 0, self._note(result))
        saved = []
        for path in self.live.rglob("*"):
            if path != self.target and path.is_file() and not path.is_symlink():
                if path.read_bytes() == original:
                    saved.append(path)
        self.assertTrue(saved, "ORIGINAL_RECOVERY_POINT_NOT_RETAINED")
        point = saved[0]
        self.assertEqual(stat.S_IMODE(point.stat().st_mode), 0o600, "ROLLBACK_POINT_NOT_PRIVATE")
        self._control("inactive")
        result = self._restore(point)
        self.assertEqual(result.returncode, 0, self._note(result))
        self.assertEqual(self.target.read_bytes(), original, "ROLLBACK_BYTES_DIFFER")
        self.assertEqual(self._rows(self.target), [(1, "original", 0)])
        current = self.target.stat()
        self.assertEqual((current.st_uid, current.st_gid), metadata[:2])


    def test_restore_refuses_real_committed_wal_without_losing_it(self):
        incoming, _, _ = self._restore_fixture()
        with contextlib.closing(sqlite3.connect(self.target)) as connection:
            self.assertEqual(connection.execute("PRAGMA journal_mode=WAL").fetchone()[0], "wal")
            connection.execute("PRAGMA wal_autocheckpoint=0")
            connection.execute("INSERT INTO fixture VALUES (2, 'only-in-wal', zeroblob(9))")
            connection.commit()
            wal = Path(str(self.target) + "-wal")
            self.assertTrue(wal.is_file(), "FIXTURE_RESTORE_WAL_NOT_HELD")
            before = self.target.read_bytes()
            wal_before = wal.read_bytes()
            current = self.target.stat()
            metadata = (current.st_uid, current.st_gid, stat.S_IMODE(current.st_mode))
            result = self._restore(incoming)
            self._assert_failed_unchanged(result, before, metadata)
            self.assertEqual(wal.read_bytes(), wal_before, "COMMITTED_WAL_LOST")
            self.assertEqual(connection.execute("SELECT value FROM fixture WHERE id=2").fetchone(),
                             ("only-in-wal",))

    def test_restore_refuses_hardlink_target_and_symlink_parent(self):
        incoming, original, metadata = self._restore_fixture()
        alias = self.inputs / "protected-original.db"
        os.link(self.target, alias)
        result = self._restore(incoming)
        self._assert_failed_unchanged(result, original, metadata)
        self.assertEqual(alias.read_bytes(), original, "HARDLINK_ALIAS_CHANGED")
        alias.unlink()
        directory_alias = self.work / "live-alias"
        directory_alias.symlink_to(self.live, target_is_directory=True)
        self.target.write_bytes(original)
        self.target.chmod(metadata[2])
        result = self._script("restore", [incoming],
                              env={"DATABASE_URL": "sqlite:" + str(directory_alias / self.target.name)})
        self._assert_failed_unchanged(result, original, metadata)

    def test_backup_rejects_explicit_empty_memory_and_unknown_scheme(self):
        self._db(self.work / "net-identity.db", "must-not-be-silent-fallback")
        for index, value in enumerate(("", "sqlite::memory:", "unknown://database")):
            with self.subTest(input_kind=index):
                out = self.output / ("invalid-" + str(index))
                out.mkdir(mode=0o700)
                result = self._script("backup", [out], env={"DATABASE_URL": value})
                self.assertNotEqual(result.returncode, 0, "AMBIGUOUS_DB_SELECTION_ACCEPTED")
                self.assertEqual(self._published(out), [], "INVALID_SELECTION_PUBLISHED")


    def test_backup_output_quote_is_safe_or_refused_without_partial_publication(self):
        self._db(self.work / "net-identity.db", "quoted-output")
        out = self.output / "operator's snapshots"
        out.mkdir(mode=0o700)
        result = self._script("backup", [out])
        if result.returncode == 0:
            self.assertEqual(len(self._published(out)), 1)
            self.assertEqual(self._read_backup(self._published(out)[0]), [(1, "quoted-output", 0)])
        else:
            self.assertEqual(self._published(out), [], "REFUSED_PATH_PUBLISHED_OUTPUT")
            self.assertEqual(list(out.glob("trueid-*.db")), [], "REFUSED_PATH_LEAKED_PARTIAL_DB")


    def test_restore_refuses_mixed_unit_states_in_both_directions(self):
        incoming, original, metadata = self._restore_fixture()
        required = {"trueid-web.service", "trueid-engine.service"}
        for blocked in sorted(required):
            for state in ("active", "unknown", "failed", "activating", "deactivating", "reloading",
                          "active_after_candidate"):
                with self.subTest(blocked_unit=blocked, state=state):
                    self.live = Path(tempfile.mkdtemp(prefix="mixed-live-", dir=self.root))
                    self.target = self.live / "net-identity.db"
                    self.target.write_bytes(original)
                    self.target.chmod(metadata[2])
                    units = {unit: "inactive" for unit in required}
                    units[blocked] = state
                    self._control(units)
                    result = self._restore(incoming)
                    self._assert_failed_unchanged(result, original, metadata)


if __name__ == "__main__":
    unittest.main(verbosity=2)
