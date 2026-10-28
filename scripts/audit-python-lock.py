#!/usr/bin/env python3
"""Fail-closed frozen PyPI audit; Linux CLI supervisor and stdlib OSV transport."""
import datetime
import hashlib
import http.client
import io
import json
import math
import os
from pathlib import Path
import re
import select
import signal
import ssl
import stat
import sys
import time
import tomllib

RUN_SECONDS = 60.0
IO_SECONDS = 10.0
MAX_BYTES = 1048576
BATCH_SIZE = 1000
NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?", re.ASCII)
VERSION = re.compile(r"v?(?:[0-9]+!)?[0-9]+(?:\.[0-9]+)*"
    r"(?:[-_.]?(?:alpha|a|beta|b|preview|pre|c|rc)[-_.]?[0-9]*)?"
    r"(?:(?:-[0-9]+)|(?:[-_.]?(?:post|rev|r)[-_.]?[0-9]*))?"
    r"(?:[-_.]?dev[-_.]?[0-9]*)?(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?", re.I | re.ASCII)
TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt](?:[01][0-9]|2[0-3]):[0-5][0-9]:"
    r"(?:[0-5][0-9]|60)(?:\.[0-9]+)?(?:[Zz]|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])", re.ASCII)
FIELDS = {"status", "lock_sha256", "manifest_sha256", "inventory", "submitted", "completed", "batches", "advisories", "error"}
ERRORS = {"INPUT", "INPUT_CHANGED", "OSV_HTTP", "OSV_TRANSPORT", "OSV_SCHEMA", "REPORT", "WORKER",
    "DEADLINE", "INTERRUPTED", "DRAIN_UNPROVEN", "CLEANUP", "USAGE", "UNSUPPORTED", "INTERNAL"}


class AuditError(ValueError):
    """Only fixed categories cross the CLI boundary."""


def _require(ok, category):
    if not ok:
        raise AuditError(category)


def _dump(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _parse_json(raw, limit):
    """Bound before decoding; inspect decoded keys, strings and numeric overflow."""
    _require(type(raw) is bytes and 0 < len(raw) <= limit, "OSV_SCHEMA")
    text = raw.decode("utf-8", errors="strict")
    _require(not text.startswith("\ufeff") and "\0" not in text, "OSV_SCHEMA")
    depth, quoted, escaped = 0, False, False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            _require(depth <= 16, "OSV_SCHEMA")
        elif char in "]}":
            depth -= 1
            _require(depth >= 0, "OSV_SCHEMA")
    _require(depth == 0 and not quoted, "OSV_SCHEMA")
    def pairs(rows):
        result = {}
        for key, value in rows:
            _require(key not in result, "OSV_SCHEMA")
            result[key] = value
        return result
    def nonfinite(_value):
        raise AuditError("OSV_SCHEMA")
    value = json.loads(text, object_pairs_hook=pairs, parse_constant=nonfinite)
    def inspect(item):
        if type(item) is str:
            _require("\0" not in item and not any(0xD800 <= ord(c) <= 0xDFFF for c in item), "OSV_SCHEMA")
        elif type(item) is float:
            _require(math.isfinite(item), "OSV_SCHEMA")
        elif type(item) is list:
            for child in item:
                inspect(child)
        elif type(item) is dict:
            for key, child in item.items():
                inspect(key)
                inspect(child)
    inspect(value)
    return value


def strict_json(raw: bytes) -> object:
    return _parse_json(raw, MAX_BYTES)


def _name(value):
    _require(type(value) is str and NAME.fullmatch(value) is not None, "INPUT")
    return re.sub(r"[-_.]+", "-", value).lower()


def _version(value):
    _require(type(value) is str and VERSION.fullmatch(value) is not None, "INPUT")
    return value


def _read_regular(path):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        _require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= MAX_BYTES, "INPUT")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(MAX_BYTES + 1)
        after = os.fstat(fd)
        _require(len(raw) == before.st_size == after.st_size and len(raw) <= MAX_BYTES, "INPUT")
        return raw
    finally:
        os.close(fd)


def _inventory(lock, manifest):
    _require(type(lock) is dict and type(lock.get("version")) is int and lock["version"] == 1 and
        type(lock.get("revision")) is int and lock["revision"] == 3, "INPUT")
    project = manifest.get("project") if type(manifest) is dict else None
    _require(type(project) is dict, "INPUT")
    root = (_name(project.get("name")), _version(project.get("version")))
    packages = lock.get("package")
    _require(type(packages) is list and bool(packages), "INPUT")
    seen, roots, inventory = set(), 0, []
    for package in packages:
        _require(type(package) is dict, "INPUT")
        pair = (_name(package.get("name")), _version(package.get("version")))
        _require(pair not in seen, "INPUT")
        seen.add(pair)
        source = package.get("source")
        _require(type(source) is dict, "INPUT")
        if source == {"virtual": "."}:
            roots += 1
            _require(pair == root, "INPUT")
        else:
            _require(source == {"registry": "https://pypi.org/simple"}, "INPUT")
            inventory.append({"name": pair[0], "version": pair[1]})
    inventory.sort(key=lambda item: (item["name"], item["version"]))
    _require(roots == 1 and bool(inventory), "INPUT")
    return inventory


def _advisory_id(value):
    return type(value) is str and 0 < len(value) <= 256 and value.isprintable() and not value.isspace()


def _modified(value):
    _require(type(value) is str and len(value) <= 128 and TIMESTAMP.fullmatch(value) is not None, "OSV_SCHEMA")
    # RFC3339 permits a leap second; datetime validates the remaining calendar.
    ordinary = value[:17] + ("59" if value[17:19] == "60" else value[17:19]) + value[19:]
    parsed = datetime.datetime.fromisoformat(ordinary.replace("t", "T").replace("z", "+00:00").replace("Z", "+00:00"))
    _require(parsed.tzinfo is not None and parsed.utcoffset() is not None, "OSV_SCHEMA")
    if value[17:19] == "60":
        utc = parsed.astimezone(datetime.timezone.utc)
        _require((utc.hour, utc.minute, utc.second) == (23, 59, 59) and
            (utc + datetime.timedelta(seconds=1)).day == 1, "OSV_SCHEMA")


def _headers(response):
    rows = response.getheaders()
    _require(type(rows) is list and len(rows) <= 128, "OSV_HTTP")
    headers = {}
    for row in rows:
        _require(type(row) is tuple and len(row) == 2 and all(type(v) is str for v in row) and
            len(row[0]) + len(row[1]) <= 8192, "OSV_HTTP")
        key, value = row[0].lower(), row[1].strip(" \t")
        headers.setdefault(key, []).append(value)
    _require(sum(len(k) + sum(map(len, v)) for k, v in headers.items()) <= 32768, "OSV_HTTP")
    media = headers.get("content-type", [])
    _require(len(media) == 1 and re.fullmatch(r'application/json(?:[ \t]*;[ \t]*charset[ \t]*=[ \t]*(?:utf-8|"utf-8"))?',
        media[0], re.I | re.ASCII) is not None, "OSV_HTTP")
    _require("content-encoding" not in headers or [v.lower() for v in headers["content-encoding"]] == ["identity"], "OSV_HTTP")
    length = None
    if "content-length" in headers:
        values = headers["content-length"]
        _require(len(values) == 1 and re.fullmatch("[0-9]+", values[0], re.ASCII) is not None, "OSV_HTTP")
        length = int(values[0])
        _require(length <= MAX_BYTES, "OSV_HTTP")
    if "transfer-encoding" in headers:
        _require([v.lower() for v in headers["transfer-encoding"]] == ["chunked"] and length is None, "OSV_HTTP")
    return length


def _post(batch):
    body = _dump({"queries": [{"package": {"ecosystem": "PyPI", "name": p["name"]}, "version": p["version"]} for p in batch]})
    _require(len(body) <= MAX_BYTES, "OSV_SCHEMA")
    connection = response = None
    try:
        context = ssl.create_default_context()
        connection = http.client.HTTPSConnection("api.osv.dev", timeout=min(IO_SECONDS, 10.0), context=context)
        connection.request("POST", "/v1/querybatch", body=body, headers={"Content-Type": "application/json", "Accept": "application/json"})
        response = connection.getresponse()
        _require(type(response.status) is int and response.status == 200, "OSV_HTTP")
        expected = _headers(response)
        raw = bytearray()
        while True:
            chunk = response.read(min(65536, MAX_BYTES + 1 - len(raw)))
            _require(type(chunk) is bytes, "OSV_HTTP")
            if not chunk:
                break
            raw.extend(chunk)
            _require(len(raw) <= MAX_BYTES, "OSV_HTTP")
        _require(expected is None or len(raw) == expected, "OSV_HTTP")
    except AuditError:
        raise
    except Exception:
        raise AuditError("OSV_TRANSPORT") from None
    finally:
        failed_close = False
        for resource in (response, connection):
            if resource is not None:
                try:
                    resource.close()
                except BaseException:
                    failed_close = True
        if failed_close:
            raise AuditError("OSV_TRANSPORT")
    try:
        return strict_json(bytes(raw))
    except (ValueError, UnicodeError, RecursionError):
        raise AuditError("OSV_SCHEMA") from None


def _results(value, batch):
    _require(type(value) is dict and set(value) == {"results"} and type(value["results"]) is list and
        len(value["results"]) == len(batch), "OSV_SCHEMA")
    advisories = []
    for package, result in zip(batch, value["results"]):
        _require(type(result) is dict and not (set(result) - {"vulns", "next_page_token"}) and
            "next_page_token" not in result, "OSV_SCHEMA")
        vulns = result.get("vulns", [])
        _require(type(vulns) is list, "OSV_SCHEMA")
        ids = []
        for vuln in vulns:
            _require(type(vuln) is dict and _advisory_id(vuln.get("id")), "OSV_SCHEMA")
            if "modified" in vuln:
                try:
                    _modified(vuln["modified"])
                except (ValueError, OverflowError):
                    raise AuditError("OSV_SCHEMA") from None
            ids.append(vuln["id"])
        if ids:
            advisories.append({**package, "ids": sorted(set(ids))})
    return advisories


def _error(category):
    return {"status": "ERROR", "lock_sha256": None, "manifest_sha256": None, "inventory": [],
        "submitted": 0, "completed": 0, "batches": 0, "advisories": [], "error": category}


def _validate_report(report, code):
    _require(type(code) is int and code in (0, 1, 2) and type(report) is dict and set(report) == FIELDS, "REPORT")
    for field in ("lock_sha256", "manifest_sha256"):
        value = report[field]
        _require(value is None or (type(value) is str and re.fullmatch("[0-9a-f]{64}", value) is not None), "REPORT")
    inventory = report["inventory"]
    _require(type(inventory) is list, "REPORT")
    pairs = []
    for item in inventory:
        _require(type(item) is dict and set(item) == {"name", "version"}, "REPORT")
        _require(_name(item["name"]) == item["name"] and _version(item["version"]) == item["version"], "REPORT")
        pairs.append((item["name"], item["version"]))
    _require(pairs == sorted(set(pairs)), "REPORT")
    n = len(pairs)
    _require(not n or all(report[k] is not None for k in ("lock_sha256", "manifest_sha256")), "REPORT")
    submitted, completed, batches = (report[k] for k in ("submitted", "completed", "batches"))
    _require(all(type(v) is int for v in (submitted, completed, batches)) and 0 <= completed <= submitted <= n and
        batches == (submitted + BATCH_SIZE - 1) // BATCH_SIZE and
        (submitted == n or submitted % BATCH_SIZE == 0) and (completed == n or completed % BATCH_SIZE == 0), "REPORT")
    advisories = report["advisories"]
    _require(type(advisories) is list, "REPORT")
    keys = []
    for item in advisories:
        _require(type(item) is dict and set(item) == {"name", "version", "ids"}, "REPORT")
        pair = (item["name"], item["version"])
        _require(all(type(v) is str for v in pair), "REPORT")
        _require(pair in pairs[:completed] and type(item["ids"]) is list and bool(item["ids"]) and
            all(_advisory_id(i) for i in item["ids"]) and item["ids"] == sorted(set(item["ids"])), "REPORT")
        keys.append(pair)
    _require(keys == sorted(set(keys)), "REPORT")
    if code == 2:
        _require(report["status"] == "ERROR" and type(report["error"]) is str and report["error"] in ERRORS, "REPORT")
    else:
        _require(n > 0 and all(report[k] is not None for k in ("lock_sha256", "manifest_sha256")) and
            submitted == completed == n and report["error"] is None and
            ((code == 0 and report["status"] == "CLEAN" and not advisories) or
             (code == 1 and report["status"] == "FINDINGS" and bool(advisories))), "REPORT")
    _require(len(_dump(report)) <= MAX_BYTES - 1, "REPORT")
    return report


def scan(lock_path: Path) -> tuple[int, dict]:
    """Perform all input, network and final recheck work inside the owned worker."""
    report, originals = _error("INPUT"), []
    manifest_path = lock_path.parent / "pyproject.toml"
    try:
        raw = _read_regular(lock_path)
        report["lock_sha256"] = _sha(raw)
        originals.append((lock_path, report["lock_sha256"]))
        manifest_raw = _read_regular(manifest_path)
        report["manifest_sha256"] = _sha(manifest_raw)
        originals.append((manifest_path, report["manifest_sha256"]))
        report["inventory"] = _inventory(tomllib.loads(raw.decode("utf-8", errors="strict")),
            tomllib.loads(manifest_raw.decode("utf-8", errors="strict")))
        report["error"] = None
        _require(len(_dump(report)) <= MAX_BYTES - 1, "REPORT")
        for offset in range(0, len(report["inventory"]), BATCH_SIZE):
            batch = report["inventory"][offset:offset + BATCH_SIZE]
            report["submitted"] += len(batch)
            report["batches"] += 1
            findings = _results(_post(batch), batch)
            report["completed"] += len(batch)
            report["advisories"].extend(findings)
            _require(len(_dump(report)) <= MAX_BYTES - 1, "REPORT")
    except AuditError as error:
        report["error"] = str(error) if str(error) in ERRORS else "INTERNAL"
    except (OSError, ValueError, UnicodeError, TypeError):
        report["error"] = "INPUT"
    except BaseException as error:
        report["error"] = "INTERRUPTED" if isinstance(error, KeyboardInterrupt) else "INTERNAL"
    finally:
        changed = False
        for path, expected in originals:
            try:
                changed |= _sha(_read_regular(path)) != expected
            except BaseException:
                changed = True
        if changed:
            report["error"] = "INPUT_CHANGED"
    code = 2 if report["error"] else (1 if report["advisories"] else 0)
    report["status"] = ("CLEAN", "FINDINGS", "ERROR")[code]
    try:
        return code, _validate_report(report, code)
    except (ValueError, TypeError, KeyError, OverflowError):
        report["status"], report["error"], report["advisories"] = "ERROR", "REPORT", []
        if len(_dump(report)) > MAX_BYTES - 1:
            report = {**_error("REPORT"), "lock_sha256": report["lock_sha256"], "manifest_sha256": report["manifest_sha256"]}
        return 2, _validate_report(report, 2)


class _Child:
    """The sole reaper clears ownership before report parsing or any later signal."""
    def __init__(self, pid):
        self.pid, self.status = pid, None

    def poll(self):
        if self.pid is None:
            return True
        try:
            observed, status = os.waitpid(self.pid, os.WNOHANG)
        except ChildProcessError:
            self.pid = None
            raise AuditError("DRAIN_UNPROVEN") from None
        if observed:
            self.pid = None
            self.status = status
            return True
        return False

    def send(self, number):
        if not self.poll():
            try:
                os.kill(self.pid, number)
            except ProcessLookupError:
                pass

    def drain(self, deadline, reserve):
        if self.poll():
            return True
        self.send(signal.SIGTERM)
        grace = min(deadline - reserve / 2, time.monotonic() + reserve / 3)
        while time.monotonic() < grace and not self.poll():
            time.sleep(min(0.01, max(0, grace - time.monotonic())))
        if not self.poll():
            self.send(signal.SIGKILL)
        until = deadline - reserve / 3
        while time.monotonic() < until and not self.poll():
            time.sleep(min(0.005, max(0, until - time.monotonic())))
        return self.poll()


def _worker(fd, lock_path):
    try:
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        code, report = scan(lock_path)
        _validate_report(report, code)
        raw = _dump({"code": code, "report": report, "inventory_sha256": _sha(_dump(report["inventory"])),
            "report_sha256": _sha(_dump(report))})
        _require(len(raw) <= MAX_BYTES + 256, "REPORT")
        os.ftruncate(fd, 0)
        os.lseek(fd, 0, os.SEEK_SET)
        offset = 0
        while offset < len(raw):
            count = os.write(fd, raw[offset:])
            _require(count > 0, "REPORT")
            offset += count
    except BaseException:
        code = 2
    try:
        os.close(fd)
    except OSError:
        code = 2
    os._exit(code)


def _read_worker_report(fd, identity, status):
    info = os.fstat(fd)
    _require(stat.S_ISREG(info.st_mode) and (info.st_dev, info.st_ino) == identity and
        stat.S_IMODE(info.st_mode) == 0o600 and 0 < info.st_size <= MAX_BYTES + 256 and
        os.WIFEXITED(status) and os.WEXITSTATUS(status) in (0, 1, 2), "REPORT")
    raw = os.pread(fd, info.st_size + 1, 0)
    _require(len(raw) == info.st_size, "REPORT")
    value = _parse_json(raw, MAX_BYTES + 256)
    _require(type(value) is dict and set(value) == {"code", "report", "inventory_sha256", "report_sha256"}, "REPORT")
    code = os.WEXITSTATUS(status)
    _require(type(value["code"]) is int and value["code"] == code and
        value["inventory_sha256"] == _sha(_dump(value["report"]["inventory"])) and
        value["report_sha256"] == _sha(_dump(value["report"])), "REPORT")
    return code, _validate_report(value["report"], code)


def _emit(report, deadline, interrupted):
    """One bounded attempt; never append JSON after a partial/broken write."""
    raw = _dump(report) + b"\n"
    _require(len(raw) <= MAX_BYTES, "REPORT")
    if time.monotonic() >= deadline or interrupted():
        return False
    if type(sys.stdout) is io.StringIO:
        sys.stdout.write(raw.decode("utf-8"))
        return time.monotonic() < deadline
    if type(sys.stdout) is not io.TextIOWrapper:
        return False
    fd, previous = sys.stdout.fileno(), None
    try:
        mode = os.fstat(fd).st_mode
        if not (stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode) or (stat.S_ISCHR(mode) and os.isatty(fd))):
            return False
        previous = os.get_blocking(fd)
        os.set_blocking(fd, False)
        offset = 0
        while offset < len(raw):
            remaining = deadline - time.monotonic()
            if remaining <= 0 or interrupted():
                return False
            if not select.select([], [fd], [], remaining)[1]:
                return False
            try:
                count = os.write(fd, raw[offset:])
            except (BlockingIOError, InterruptedError):
                continue
            if count <= 0:
                return False
            offset += count
        return True
    except (OSError, ValueError):
        return False
    finally:
        if previous is not None:
            os.set_blocking(fd, previous)


def _arguments(argv):
    args = sys.argv[1:] if argv is None else argv
    _require(type(args) in (list, tuple) and all(type(v) is str for v in args), "USAGE")
    if not args:
        return Path(__file__).parent.parent / "integrations/sycope/uv.lock"
    if len(args) == 1 and args[0].startswith("--lock="):
        value = args[0][7:]
    else:
        _require(len(args) == 2 and args[0] == "--lock", "USAGE")
        value = args[1]
    _require(0 < len(value) <= 4096 and "\0" not in value, "USAGE")
    return Path(value)


def main(argv=None) -> int:
    started = time.monotonic()
    seconds = 60.0
    deadline = started + seconds
    reserve = min(2.0, seconds / 4)
    report, code, fd, child = _error("INTERNAL"), 2, None, None
    old_handlers, interrupted = {}, [0]
    def interrupted_now():
        return interrupted[0] > 0
    def stop(_number, _frame):
        interrupted[0] += 1
    try:
        _require(type(RUN_SECONDS) in (int, float) and math.isfinite(RUN_SECONDS) and RUN_SECONDS > 0, "UNSUPPORTED")
        seconds = min(float(RUN_SECONDS), 60.0)
        deadline, reserve = started + seconds, min(2.0, seconds / 4)
        _require(hasattr(os, "fork") and hasattr(os, "memfd_create") and
            signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL, "UNSUPPORTED")
        lock_path = _arguments(argv)
        for number in (signal.SIGINT, signal.SIGTERM):
            old_handlers[number] = signal.signal(number, stop)
        fd = os.memfd_create("trueid-osv-report", os.MFD_CLOEXEC)
        os.fchmod(fd, 0o600)
        info = os.fstat(fd)
        _require(stat.S_ISREG(info.st_mode), "REPORT")
        identity = (info.st_dev, info.st_ino)
        _require(time.monotonic() < deadline - reserve and not interrupted_now(), "DEADLINE")
        pid = os.fork()
        if pid == 0:
            _worker(fd, lock_path)
        child = _Child(pid)
        while not child.poll():
            if interrupted_now():
                raise AuditError("INTERRUPTED")
            _require(time.monotonic() < deadline - reserve, "DEADLINE")
            time.sleep(min(0.01, max(0, deadline - reserve - time.monotonic())))
        _require(not interrupted_now(), "INTERRUPTED")
        _require(time.monotonic() < deadline - reserve / 3, "DEADLINE")
        try:
            code, report = _read_worker_report(fd, identity, child.status)
        except (ValueError, TypeError, KeyError, OSError, UnicodeError):
            raise AuditError("REPORT") from None
        _require(time.monotonic() < deadline - reserve / 3, "DEADLINE")
    except BaseException as error:
        category = str(error) if type(error) is AuditError and str(error) in ERRORS else "INTERNAL"
        report, code = _error(category), 2
    finally:
        try:
            if child is not None and not child.drain(deadline, reserve):
                report, code = _error("DRAIN_UNPROVEN"), 2
        except BaseException:
            report, code = _error("DRAIN_UNPROVEN"), 2
        if fd is not None:
            closing, fd = fd, None
            try:
                os.close(closing)
            except OSError:
                report, code = _error("CLEANUP"), 2
    try:
        emit_snapshot = interrupted[0]
        if emit_snapshot:
            report, code = _error("INTERRUPTED"), 2
        if time.monotonic() >= deadline - reserve / 4:
            report, code = _error("DEADLINE"), 2
        return code if _emit(report, deadline, lambda: interrupted[0] != emit_snapshot) else 2
    except BaseException:
        return 2
    finally:
        for number, previous in old_handlers.items():
            signal.signal(number, previous)


if __name__ == "__main__":
    raise SystemExit(main())
