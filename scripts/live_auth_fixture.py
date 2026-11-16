"""C03-S1 fresh native HTTPS auth fixture (stdlib only, passive import).

This module builds and manages one isolated per-case fixture: a fresh private
CA + leaf certificate (IP 127.0.0.1 / DNS localhost), an owned SQLite database
path, an explicit native server environment, and a small HTTPS cookie client
used only for the bootstrap auth sequence. It never spawns or signals child
processes itself; the parent runner owns lifecycle and passes ``run_owned``.

No external/lab endpoints, no inherited credentials, no TLS bypass, no DB
seeding shortcut. Source implementation only: this file does not authorize
execution and does not assert runtime PASS.
"""

from __future__ import annotations

import functools
import hashlib
import http.client
import io
import math
import socket
import json
import os
import re
import secrets
import sqlite3
import ssl
import stat
import time
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar
from pathlib import Path

__all__ = [
    "FixtureError",
    "prepare_case",
    "bootstrap",
    "test_environment",
    "read_witnesses",
    "public_summary",
    "remove_case",
]

# Fixed allowlisted failure categories (FixtureError.code is always one of these).
_CODES = frozenset(
    {
        "invalid_case_root",
        "invalid_source_root",
        "invalid_port",
        "invalid_deadline",
        "invalid_fixture",
        "invalid_argument",
        "command_failed",
        "command_output_limit",
        "command_timeout",
        "openssl_unavailable",
        "certificate_build_failed",
        "trust_directory_failed",
        "environment_rejected",
        "env_rejected",
        "server_not_ready",
        "bootstrap_login_failed",
        "bootstrap_change_password_failed",
        "bootstrap_verification_failed",
        "bootstrap_csrf_missing",
        "bootstrap_logout_failed",
        "bootstrap_logout_not_confirmed",
        "untrusted_ca_not_rejected",
        "witness_db_unavailable",
        "witness_db_not_successful",
        "witness_mismatch",
        "witness_case_not_applicable",
        "cleanup_denied",
        "cleanup_failed",
    }
)


class FixtureError(Exception):
    """Fixture failure with a fixed, allowlisted category code.

    The raw underlying error text is deliberately never stored or exposed.
    """

    __slots__ = ("_code",)

    def __init__(self, code: str) -> None:
        if type(code) is not str or code not in _CODES:
            code = "invalid_argument"
        super().__init__(code)
        self._code = code

    @property
    def code(self) -> str:
        return self._code

    def __str__(self) -> str:  # noqa: D105
        return f"fixture error: {self._code}"

    def __repr__(self) -> str:  # noqa: D105
        return f"FixtureError({self._code!r})"


def _check_deadline(deadline: float) -> None:
    if type(deadline) not in (int, float):
        raise FixtureError("invalid_deadline")
    try:
        valid = math.isfinite(deadline) and deadline > 0
    except OverflowError:
        valid = False
    if not valid:
        raise FixtureError("invalid_deadline")


def _remaining(deadline: float) -> float:
    return deadline - time.monotonic()


def _deadline_guard(deadline: float) -> None:
    _check_deadline(deadline)
    if _remaining(deadline) <= 0:
        raise FixtureError("invalid_deadline")


def _sanitized(code):
    def decorate(function):
        @functools.wraps(function)
        def wrapped(*args, **kwargs):
            try:
                return function(*args, **kwargs)
            except FixtureError:
                raise
            except Exception:
                raise FixtureError(code) from None
        return wrapped
    return decorate


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid,
            stat.S_IMODE(info.st_mode))


def _ancestry(path):
    result = []
    for part in (path, *path.parents):
        info = part.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise FixtureError("invalid_case_root")
        result.append((str(part), _identity(info)))
    return tuple(result)


def _verify_owned(fixture):
    if (not isinstance(fixture, _Fixture) or fixture.removed or
            _ancestry(fixture.case_root) != fixture.owned_ancestry):
        raise FixtureError("invalid_fixture")
    info = fixture.case_root.lstat()
    if (info.st_uid != os.geteuid() or info.st_gid != os.getegid() or
            stat.S_IMODE(info.st_mode) != 0o700):
        raise FixtureError("invalid_fixture")


def _private_regular(path, *, nonempty=True):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid() or
            info.st_gid != os.getegid() or stat.S_IMODE(info.st_mode) != 0o600 or
            (nonempty and info.st_size <= 0)):
        raise FixtureError("invalid_fixture")
    return info


def _is_within(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
    except ValueError:
        return False
    return True


def _no_symlink_components(path: Path) -> bool:
    """True when no component of *path* (below and including itself) is a symlink."""
    cur = path
    while True:
        if cur.is_symlink():
            return False
        parent = cur.parent
        if parent == cur:
            return True
        cur = parent


def _new_password() -> str:
    alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(24))
        if (
            any(c.islower() for c in pw)
            and any(c.isupper() for c in pw)
            and any(c.isdigit() for c in pw)
            and any(not c.isalnum() for c in pw)
        ):
            return pw


def _new_hex(nbytes: int) -> str:
    return secrets.token_hex(nbytes)


def _new_token() -> str:
    return secrets.token_urlsafe(48)


def _write_private(path: Path, data: bytes) -> None:
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def _openssl_env(home: Path, tmpdir: Path) -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": str(home),
        "TMPDIR": str(tmpdir),
        "LC_ALL": "C",
        "LANG": "C",
        "OPENSSL_CONF": "",
    }


# --------------------------------------------------------------------------- #
# Fixture container
# --------------------------------------------------------------------------- #


class _Fixture:
    """Internal fixture state.  ``repr``/``str`` never leak private details."""

    __slots__ = (
        "case_root",
        "source_root",
        "port",
        "run_owned",
        "deadline",
        "bin_dir",
        "home_dir",
        "tmp_dir",
        "trust_dir",
        "db_path",
        "ca_cert",
        "ca_key",
        "ca_hash",
        "leaf_cert",
        "leaf_key",
        "leaf_hash",
        "server_env",
        "bootstrap_password",
        "new_password",
        "observations",
        "closed",
        "removed",
        "owned_ancestry",
        "db_identity",
    )

    def __repr__(self) -> str:  # noqa: D105
        return "<auth-fixture:prepared>" if not self.removed else "<auth-fixture:removed>"

    __str__ = __repr__


def _reject_env_file(case_root: Path) -> None:
    """Reject any ``.env`` in the case root or its ancestors."""
    for candidate in (case_root, *case_root.parents):
        if os.path.lexists(candidate / ".env"):
            raise FixtureError("env_rejected")


def _build_environment(fixture: _Fixture) -> None:
    src = fixture.source_root
    migrations = src / "crates" / "common" / "migrations"
    assets = src / "apps" / "web" / "assets"
    if not migrations.is_dir():
        raise FixtureError("invalid_source_root")
    if not assets.is_dir():
        raise FixtureError("invalid_source_root")
    db_url = "sqlite://" + str(fixture.db_path) + "?mode=rwc"
    bind = f"127.0.0.1:{fixture.port}"
    env: dict[str, str] = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(fixture.home_dir),
        "TMPDIR": str(fixture.tmp_dir),
        "TRUEID_DEV_MODE": "false",
        "HTTP_BIND": bind,
        "DATABASE_URL": db_url,
        "TRUEID_ADMIN_USER": "admin",
        "TRUEID_ADMIN_PASS": fixture.bootstrap_password,
        "JWT_SECRET": _new_token(),
        "ENGINE_SERVICE_TOKEN": _new_token(),
        "CONFIG_ENCRYPTION_KEY": _new_hex(32),
        "ARGON2_PEPPER": _new_hex(32),
        "TRUEID_MIGRATIONS_DIR": str(migrations),
        "ASSETS_DIR": str(assets),
        "TLS_CERT": str(fixture.leaf_cert),
        "TLS_KEY": str(fixture.leaf_key),
        "TRUSTED_PROXIES": "",
        "ENGINE_API_URL": "http://127.0.0.1:9",
        "TOKIO_WORKER_THREADS": "2",
        "RUST_LOG": "info",
        "NO_PROXY": "*",
        "no_proxy": "*",
    }
    # Explicitly strip anything inherited that could leak in via os.environ use.
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        env.pop(key, None)
    fixture.server_env = env


def _validate_server_env(env: dict[str, str]) -> None:
    required_min = ("JWT_SECRET", "ENGINE_SERVICE_TOKEN")
    for key in required_min:
        if len(env.get(key, "")) < 32:
            raise FixtureError("environment_rejected")
    if len(env.get("CONFIG_ENCRYPTION_KEY", "")) != 64:
        raise FixtureError("environment_rejected")
    if env.get("TRUEID_DEV_MODE") != "false":
        raise FixtureError("environment_rejected")
    if env.get("TRUSTED_PROXIES") != "":
        raise FixtureError("environment_rejected")


# --------------------------------------------------------------------------- #
# prepare_case
# --------------------------------------------------------------------------- #


@_sanitized('certificate_build_failed')
def prepare_case(
    case_root: Path,
    source_root: Path,
    port: int,
    *,
    run_owned,
    deadline: float,
) -> _Fixture:
    """Create a fresh, fully owned fixture directory tree and metadata."""
    _check_deadline(deadline)
    _deadline_guard(deadline)
    if not callable(run_owned):
        raise FixtureError("invalid_argument")
    if not isinstance(port, int) or isinstance(port, bool) or not (0 < port < 65536):
        raise FixtureError("invalid_port")
    if isinstance(case_root, str):
        case_root = Path(case_root)
    if not isinstance(case_root, Path) or not case_root.is_absolute():
        raise FixtureError("invalid_case_root")
    if isinstance(source_root, str):
        source_root = Path(source_root)
    if not isinstance(source_root, Path) or not source_root.is_absolute():
        raise FixtureError("invalid_source_root")

    if os.path.lexists(case_root):
        raise FixtureError("invalid_case_root")
    if not _no_symlink_components(case_root.parent):
        raise FixtureError("invalid_case_root")

    parent_info = case_root.parent.lstat()
    if (not stat.S_ISDIR(parent_info.st_mode) or
            parent_info.st_uid != os.geteuid() or parent_info.st_gid != os.getegid() or
            stat.S_IMODE(parent_info.st_mode) != 0o700):
        raise FixtureError("invalid_case_root")
    if not _no_symlink_components(source_root) or not source_root.is_dir():
        raise FixtureError("invalid_source_root")
    _reject_env_file(case_root)
    try:
        case_root.mkdir(mode=0o700, parents=False)
    except FileExistsError:
        raise FixtureError("invalid_case_root") from None
    except OSError:
        raise FixtureError("invalid_case_root") from None

    fixture = _Fixture()
    fixture.case_root = case_root
    fixture.source_root = source_root
    fixture.port = port
    fixture.run_owned = run_owned
    fixture.deadline = deadline
    fixture.observations = {}
    fixture.closed = False
    fixture.removed = False
    fixture.owned_ancestry = _ancestry(case_root)

    _reject_env_file(case_root)

    fixture.bin_dir = case_root / "bin"
    fixture.home_dir = case_root / "home"
    fixture.tmp_dir = case_root / "tmp"
    fixture.trust_dir = case_root / "trust"
    fixture.db_path = case_root / "state" / "trueid.db"
    fixture.bin_dir.mkdir(mode=0o700, parents=False)
    (fixture.bin_dir / "private").mkdir(mode=0o700, parents=False)
    (fixture.home_dir).mkdir(mode=0o700, parents=False)
    (fixture.tmp_dir).mkdir(mode=0o700, parents=False)
    fixture.trust_dir.mkdir(mode=0o700, parents=False)
    (fixture.db_path.parent).mkdir(mode=0o700, parents=False)
    os.chmod(case_root, 0o700)
    _write_private(fixture.db_path, b"")
    fixture.db_identity = _identity(_private_regular(fixture.db_path, nonempty=False))

    # Empty trust directory: the CA is deliberately NOT pre-installed there for
    # the negative check; the positive client builds its own in-memory store.
    for entry in fixture.trust_dir.iterdir():
        # Fresh dir: nothing expected; refuse anything present (defensive).
        raise FixtureError("trust_directory_failed")

    fixture.bootstrap_password = _new_password()
    fixture.new_password = _new_password()
    if fixture.bootstrap_password == fixture.new_password:
        raise FixtureError("certificate_build_failed")

    _generate_pki(fixture)
    _build_environment(fixture)
    _validate_server_env(fixture.server_env)

    # Only public certificate DER hashes are summary data.
    fixture.observations["leaf_sha256"] = fixture.leaf_hash
    fixture.observations["ca_sha256"] = fixture.ca_hash
    return fixture


def _generate_pki(fixture: _Fixture) -> None:
    env = _openssl_env(fixture.home_dir, fixture.tmp_dir)
    priv = fixture.bin_dir / "private"
    ca_key = priv / "ca.key"
    ca_cert = priv / "ca.crt"
    leaf_key = priv / "leaf.key"
    leaf_csr = priv / "leaf.csr"
    leaf_cert = priv / "leaf.crt"
    ext = priv / "leaf.ext"

    for p in (ca_key, ca_cert, leaf_key, leaf_csr, leaf_cert, ext):
        # Pre-check so we never clobber; files are created 0600 by _write_private
        # pattern; openssl writes them, we chmod after.
        if p.exists():
            raise FixtureError("certificate_build_failed")

    # Precreate every OpenSSL output privately; tools may only overwrite these.
    for p in (ca_key, ca_cert, leaf_key, leaf_csr, leaf_cert):
        _write_private(p, b"")

    # CA key
    _deadline_guard(fixture.deadline)
    fixture.run_owned(
        ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072",
         "-out", str(ca_key)],
        cwd=str(fixture.tmp_dir), env=env, deadline=fixture.deadline, output_limit=8192,
    )
    # CA self-signed cert (pathlen:0)
    _deadline_guard(fixture.deadline)
    fixture.run_owned(
        ["openssl", "req", "-new", "-x509", "-sha256", "-days", "2",
         "-subj", "/CN=trueid-case-ca/O=trueid-test",
         "-set_serial", "0x" + secrets.token_hex(8).upper(),
         "-key", str(ca_key), "-out", str(ca_cert),
         "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
         "-addext", "keyUsage=critical,keyCertSign,cRLSign"],
        cwd=str(fixture.tmp_dir), env=env, deadline=fixture.deadline, output_limit=8192,
    )
    # Leaf key
    _deadline_guard(fixture.deadline)
    fixture.run_owned(
        ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
         "-out", str(leaf_key)],
        cwd=str(fixture.tmp_dir), env=env, deadline=fixture.deadline, output_limit=8192,
    )
    # Leaf CSR
    _deadline_guard(fixture.deadline)
    fixture.run_owned(
        ["openssl", "req", "-new", "-sha256",
         "-subj", "/CN=localhost/O=trueid-test",
         "-key", str(leaf_key), "-out", str(leaf_csr)],
        cwd=str(fixture.tmp_dir), env=env, deadline=fixture.deadline, output_limit=8192,
    )
    # SAN extension file
    ext_text = (
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
        "subjectAltName=IP:127.0.0.1,DNS:localhost\n"
    )
    _write_private(ext, ext_text.encode("utf-8"))
    # Sign leaf with CA
    _deadline_guard(fixture.deadline)
    fixture.run_owned(
        ["openssl", "x509", "-req", "-sha256", "-days", "2",
         "-in", str(leaf_csr), "-CA", str(ca_cert), "-CAkey", str(ca_key),
         "-set_serial", "0x" + secrets.token_hex(16), "-out", str(leaf_cert),
         "-extfile", str(ext)],
        cwd=str(fixture.tmp_dir), env=env, deadline=fixture.deadline, output_limit=8192,
    )
    for p in (ca_key, ca_cert, leaf_key, leaf_csr, leaf_cert, ext):
        if not p.exists():
            raise FixtureError("certificate_build_failed")
        try:
            os.chmod(p, 0o600)
            _private_regular(p)
        except OSError:
            raise FixtureError("certificate_build_failed") from None

    fixture.ca_key = ca_key
    fixture.ca_cert = ca_cert
    fixture.leaf_key = leaf_key
    fixture.leaf_cert = leaf_cert
    fixture.ca_hash = _cert_sha256(ca_cert, fixture)
    fixture.leaf_hash = _cert_sha256(leaf_cert, fixture)
    if not fixture.ca_hash or not fixture.leaf_hash:
        raise FixtureError("certificate_build_failed")


def _cert_sha256(cert_path: Path, fixture: _Fixture) -> str:
    out = fixture.run_owned(
        ["openssl", "x509", "-in", str(cert_path), "-outform", "DER"],
        cwd=str(fixture.tmp_dir), env=_openssl_env(fixture.home_dir, fixture.tmp_dir),
        deadline=fixture.deadline, output_limit=65536,
    )
    # Hash actual bounded DER bytes, not an empty -noout response.
    if type(out) is not bytes or not 0 < len(out) <= 65536:
        raise FixtureError("certificate_build_failed")
    return hashlib.sha256(out).hexdigest()


# --------------------------------------------------------------------------- #
# Minimal HTTPS cookie client
# --------------------------------------------------------------------------- #


class _DeadlineReader(io.RawIOBase):
    def __init__(self, sock, deadline):
        super().__init__()
        self.sock, self.deadline = sock, deadline
        # Keep the socket makefile reference alive when urllib closes its
        # connection handle after receiving headers.
        self.raw = sock.makefile("rb", buffering=0)

    def close(self):
        try:
            self.raw.close()
        finally:
            super().close()

    def readable(self):
        return True

    def readinto(self, buffer):
        _deadline_guard(self.deadline)
        self.sock.settimeout(_remaining(self.deadline))
        count = self.raw.readinto(buffer)
        _deadline_guard(self.deadline)
        return count


class _DeadlineSocket:
    def __init__(self, sock, deadline):
        self.sock, self.deadline = sock, deadline

    def __getattr__(self, name):
        return getattr(self.sock, name)

    def makefile(self, mode, *args, **kwargs):
        if mode != "rb":
            raise FixtureError("bootstrap_verification_failed")
        # Buffered header parsing can make many raw reads. Every such read
        # recomputes the same absolute deadline, including slow header trickles.
        return io.BufferedReader(_DeadlineReader(self.sock, self.deadline))

    def sendall(self, data):
        _deadline_guard(self.deadline)
        self.sock.settimeout(_remaining(self.deadline))
        self.sock.sendall(data)
        _deadline_guard(self.deadline)


class _DeadlineHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, *args, deadline, **kwargs):
        self.deadline = deadline
        super().__init__(*args, **kwargs)

    def connect(self):
        if self.host != "127.0.0.1" or self._tunnel_host:
            raise FixtureError("bootstrap_verification_failed")
        _deadline_guard(self.deadline)
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tls = None
        try:
            raw.settimeout(_remaining(self.deadline))
            raw.connect((self.host, self.port))
            _deadline_guard(self.deadline)
            tls = self._context.wrap_socket(raw, server_hostname=self.host,
                                            do_handshake_on_connect=False)
            tls.settimeout(_remaining(self.deadline))
            tls.do_handshake()
            _deadline_guard(self.deadline)
            self.sock = _DeadlineSocket(tls, self.deadline)
        except BaseException:
            if tls is not None:
                tls.close()
            raw.close()
            raise


class _DeadlineHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, context, deadline):
        super().__init__(context=context)
        self.deadline = deadline

    def https_open(self, request):
        def connection(*args, **kwargs):
            return _DeadlineHTTPSConnection(*args, deadline=self.deadline, **kwargs)
        return self.do_open(connection, request, context=self._context)


class _HttpsClient:
    """No-proxy/no-redirect cookie client using only the exact private CA."""

    def __init__(self, ca_pem: bytes, deadline: float) -> None:
        _deadline_guard(deadline)
        self.jar = CookieJar()
        self.deadline = deadline
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.context.load_verify_locations(cadata=ca_pem.decode("ascii"))
        self.context.check_hostname = True
        self.context.verify_mode = ssl.CERT_REQUIRED
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.opener = urllib.request.build_opener(
            _DeadlineHTTPSHandler(self.context, deadline),
            urllib.request.HTTPCookieProcessor(self.jar), _NoRedirect(),
            urllib.request.ProxyHandler({}))

    def request(self, method: str, url: str, *, body: bytes = b"",
                headers: dict[str, str] | None = None,
                timeout: float = 10.0) -> tuple[int, bytes, dict[str, str]]:
        _deadline_guard(self.deadline)
        parsed = urllib.parse.urlsplit(url)
        if (parsed.scheme != "https" or parsed.hostname != "127.0.0.1" or
                parsed.username is not None or parsed.password is not None):
            raise FixtureError("bootstrap_verification_failed")
        hdrs = {"Accept": "application/json", "Connection": "close",
                "User-Agent": "trueid-private-auth-fixture/1"}
        if headers:
            hdrs.update(headers)
        req = urllib.request.Request(url, data=body if body else None,
                                     method=method, headers=hdrs)
        response = None
        try:
            try:
                response = self.opener.open(req, timeout=min(timeout, _remaining(self.deadline)))
            except urllib.error.HTTPError as error:
                response = error
            _deadline_guard(self.deadline)
            cap = 1 << 20
            lengths = response.headers.get_all("Content-Length", [])
            if len(lengths) > 1 or (lengths and
                    (not re.fullmatch(r"[0-9]+", lengths[0]) or int(lengths[0]) > cap)):
                raise FixtureError("bootstrap_verification_failed")
            payload = bytearray()
            while True:
                _deadline_guard(self.deadline)
                chunk = response.read(min(65536, cap + 1 - len(payload)))
                _deadline_guard(self.deadline)
                if not chunk:
                    break
                payload.extend(chunk)
                if len(payload) > cap:
                    raise FixtureError("bootstrap_verification_failed")
            if lengths and len(payload) != int(lengths[0]):
                raise FixtureError("bootstrap_verification_failed")
            return response.code, bytes(payload), {k.lower(): v for k, v in response.headers.items()}
        finally:
            if response is not None:
                response.close()

    def cookies(self) -> dict[str, str]:
        result = {}
        for cookie in self.jar:
            if cookie.name in result:
                raise FixtureError("bootstrap_verification_failed")
            result[cookie.name] = cookie.value or ""
        return result

    def close(self) -> None:
        self.jar.clear()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


CSRF_COOKIE = "trueid_csrf_token"
_ACCESS_COOKIE = "trueid_access_token"
_REFRESH_COOKIE = "trueid_refresh_token"


def _validate_auth_cookies(client):
    cookies = client.cookies()
    names = (_ACCESS_COOKIE, _REFRESH_COOKIE, CSRF_COOKIE)
    for name in names:
        rows = [cookie for cookie in client.jar if cookie.name == name]
        if (len(rows) != 1 or not cookies.get(name) or not rows[0].secure or
                rows[0].path != "/" or (name != CSRF_COOKIE and
                not rows[0].has_nonstandard_attr("HttpOnly"))):
            raise FixtureError("bootstrap_verification_failed")
    return cookies


def _login(client: _HttpsClient, base: str, user: str, password: str, *, expect_force: bool) -> dict:
    payload = json.dumps({"username": user, "password": password}).encode("utf-8")
    status, body, _hdrs = client.request(
        "POST", base + "/api/auth/login",
        body=payload, headers={"Content-Type": "application/json",
                               "X-Forwarded-For": "203.0.113.9"},
        timeout=15.0,
    )
    if status != 200:
        raise FixtureError("bootstrap_login_failed")
    try:
        doc = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise FixtureError("bootstrap_login_failed") from None
    if not isinstance(doc, dict):
        raise FixtureError("bootstrap_login_failed")
    user_obj = doc.get("user")
    if not isinstance(user_obj, dict) or user_obj.get("role") != "Admin":
        raise FixtureError("bootstrap_login_failed")
    if doc.get("force_password_change") is not expect_force:
        raise FixtureError("bootstrap_login_failed")
    if doc.get("requires_2fa") is not False:
        raise FixtureError("bootstrap_login_failed")
    ck = _validate_auth_cookies(client)
    for name in (_ACCESS_COOKIE, _REFRESH_COOKIE, CSRF_COOKIE):
        if name not in ck or not ck[name]:
            raise FixtureError("bootstrap_csrf_missing")
    return doc


def _change_password(client: _HttpsClient, base: str, current: str, new: str) -> None:
    before = client.cookies()
    csrf = before.get(CSRF_COOKIE, "")
    if not csrf:
        raise FixtureError("bootstrap_csrf_missing")
    payload = json.dumps({"current_password": current, "new_password": new}).encode("utf-8")
    status, body, _hdrs = client.request(
        "POST", base + "/api/auth/change-password",
        body=payload,
        headers={"Content-Type": "application/json", "X-CSRF-Token": csrf},
        timeout=15.0,
    )
    if status != 200:
        raise FixtureError("bootstrap_change_password_failed")
    if body:
        # Route spec: require 200 and empty body.
        raise FixtureError("bootstrap_change_password_failed")
    ck = _validate_auth_cookies(client)
    new_csrf = ck.get(CSRF_COOKIE, "")
    if not new_csrf or new_csrf == csrf:
        # All three cookie values must rotate.
        raise FixtureError("bootstrap_change_password_failed")
    for name in (_ACCESS_COOKIE, _REFRESH_COOKIE):
        if not ck.get(name) or ck[name] == before.get(name):
            raise FixtureError("bootstrap_change_password_failed")


def _me(client: _HttpsClient, base: str, expect_force_change: bool) -> dict:
    status, body, _hdrs = client.request("GET", base + "/api/auth/me", timeout=15.0)
    if status != 200:
        raise FixtureError("bootstrap_verification_failed")
    try:
        doc = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise FixtureError("bootstrap_verification_failed") from None
    if not isinstance(doc, dict):
        raise FixtureError("bootstrap_verification_failed")
    if doc.get("force_password_change") is not expect_force_change:
        raise FixtureError("bootstrap_verification_failed")
    return doc


def _logout_all(client: _HttpsClient, base: str) -> None:
    csrf = client.cookies().get(CSRF_COOKIE, "")
    if not csrf:
        raise FixtureError("bootstrap_csrf_missing")
    status, _body, _hdrs = client.request(
        "POST", base + "/api/auth/logout-all",
        body=b"", headers={"X-CSRF-Token": csrf}, timeout=15.0,
    )
    if status != 200:
        raise FixtureError("bootstrap_logout_failed")


def _untrusted_ca_rejected(port: int, deadline: float) -> bool:
    """Only actual certificate-verification failure is the negative TLS proof."""
    _deadline_guard(deadline)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    wrapped = None
    try:
        raw.settimeout(_remaining(deadline))
        raw.connect(("127.0.0.1", port))
        _deadline_guard(deadline)
        wrapped = context.wrap_socket(raw, server_hostname="localhost",
                                      do_handshake_on_connect=False)
        wrapped.settimeout(_remaining(deadline))
        wrapped.do_handshake()
        _deadline_guard(deadline)
        return False
    except ssl.SSLCertVerificationError:
        _deadline_guard(deadline)
        return True
    except (ssl.SSLError, OSError):
        raise FixtureError("untrusted_ca_not_rejected") from None
    finally:
        if wrapped is not None:
            wrapped.close()
        raw.close()








# --------------------------------------------------------------------------- #
# bootstrap
# --------------------------------------------------------------------------- #


@_sanitized('bootstrap_verification_failed')
def bootstrap(fixture: _Fixture, deadline: float) -> None:
    """Verify native HTTPS and complete the real Admin/session sequence."""
    _verify_owned(fixture)
    if fixture.closed:
        raise FixtureError("invalid_fixture")
    _deadline_guard(deadline)
    deadline = min(deadline, fixture.deadline)
    _private_regular(fixture.ca_cert)
    with fixture.ca_cert.open("rb") as stream:
        ca_pem = stream.read(65537)
    if not 0 < len(ca_pem) <= 65536:
        raise FixtureError("certificate_build_failed")
    base = f"https://127.0.0.1:{fixture.port}"
    while True:
        _deadline_guard(deadline)
        probe = _HttpsClient(ca_pem, deadline)
        try:
            status, _, _ = probe.request("GET", base + "/health", timeout=5.0)
            if status != 200:
                raise FixtureError("server_not_ready")
            break
        except (OSError, urllib.error.URLError, http.client.HTTPException):
            _deadline_guard(deadline)
            time.sleep(min(0.1, _remaining(deadline)))
        finally:
            probe.close()
    fixture.observations["verified_tls_ready"] = True
    if not _untrusted_ca_rejected(fixture.port, deadline):
        raise FixtureError("untrusted_ca_not_rejected")
    fixture.observations["untrusted_ca_rejected"] = True
    clients = []
    try:
        client = _HttpsClient(ca_pem, deadline)
        clients.append(client)
        _login(client, base, "admin", fixture.bootstrap_password, expect_force=True)
        _change_password(client, base, fixture.bootstrap_password, fixture.new_password)
        _me(client, base, expect_force_change=False)
        fresh = _HttpsClient(ca_pem, deadline)
        clients.append(fresh)
        _login(fresh, base, "admin", fixture.new_password, expect_force=False)
        _me(fresh, base, expect_force_change=False)
        # One authenticated revocation invalidates both clients. A second
        # authenticated logout would correctly fail because both are revoked.
        caller_cookies = list(client.jar)
        _logout_all(client, base)
        # Probe the caller's revoked credentials as well, rather than only
        # observing401 because logout cleared its local cookie jar.
        for cookie in caller_cookies:
            client.jar.set_cookie(cookie)
        for wrapper in clients:
            status, _, _ = wrapper.request("GET", base + "/api/auth/me")
            if status != 401:
                raise FixtureError("bootstrap_logout_not_confirmed")
        fixture.closed = True
        fixture.observations["wrapper_sessions_revoked"] = True
        fixture.observations["bootstrap_complete"] = True
    finally:
        for wrapper in clients:
            wrapper.close()


# --------------------------------------------------------------------------- #
# test_environment
# --------------------------------------------------------------------------- #


@_sanitized('environment_rejected')
def test_environment(fixture: _Fixture) -> dict[str, str]:
    """Private environment for the unchanged Rust case, never a public report."""
    _verify_owned(fixture)
    if fixture.observations.get("bootstrap_complete") is not True or not fixture.closed:
        raise FixtureError("invalid_fixture")
    _deadline_guard(fixture.deadline)
    _private_regular(fixture.ca_cert)
    if any(fixture.trust_dir.iterdir()):
        raise FixtureError("trust_directory_failed")
    # Actual Rust TLS feature/trust support remains a Linux build/runtime gate.
    # There is no TRUEID_TEST_CA variable in the unchanged Rust source.
    return {"PATH": "/usr/bin:/bin", "HOME": str(fixture.home_dir),
            "TMPDIR": str(fixture.tmp_dir),
            "TRUEID_TEST_URL": f"https://127.0.0.1:{fixture.port}",
            "TRUEID_TEST_ADMIN_PASS": fixture.new_password,
            "SSL_CERT_FILE": str(fixture.ca_cert),
            "SSL_CERT_DIR": str(fixture.trust_dir),
            "TOKIO_WORKER_THREADS": "2", "RUST_LOG": "warn"}


# --------------------------------------------------------------------------- #
# read_witnesses
# --------------------------------------------------------------------------- #


_WITNESS_CASES = {
    "rbac_matrix/test_csrf_protection",
    "rbac_matrix/test_rbac_matrix",
}


def _open_ro(db_path: Path, deadline: float) -> sqlite3.Connection:
    _deadline_guard(deadline)
    uri = "file:" + urllib.parse.quote(str(db_path), safe="/") + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=min(0.25, _remaining(deadline)))
    try:
        conn.set_progress_handler(lambda: int(_remaining(deadline) <= 0), 100)
        _deadline_guard(deadline)
        return conn
    except BaseException:
        conn.close()
        raise


@_sanitized('witness_db_unavailable')
def read_witnesses(fixture: _Fixture, suite: str, case: str, deadline: float) -> dict:
    """Read bounded aggregate witnesses only, from the exact private DB."""
    _verify_owned(fixture)
    _deadline_guard(deadline)
    deadline = min(deadline, fixture.deadline)
    if type(suite) is not str or type(case) is not str:
        raise FixtureError("invalid_argument")
    info = _private_regular(fixture.db_path, nonempty=False)
    if _identity(info) != fixture.db_identity:
        raise FixtureError("witness_db_unavailable")
    connection = None
    try:
        connection = _open_ro(fixture.db_path, deadline)
        def one(sql, parameters=()):
            _deadline_guard(deadline)
            cursor = connection.execute(sql, parameters)
            try:
                row = cursor.fetchone()
                if row is None or cursor.fetchone() is not None:
                    raise FixtureError("witness_mismatch")
                _deadline_guard(deadline)
                return row
            finally:
                cursor.close()
        count, failed = one("SELECT COUNT(*), COALESCE(SUM(CASE WHEN success=1 THEN 0 ELSE 1 END),0) FROM _sqlx_migrations")
        if type(count) is not int or count <= 0 or failed != 0:
            raise FixtureError("witness_db_not_successful")
        result = {"migrations_successful": count,
                  "csrf_witness": {"applicable": False},
                  "rbac_witness": {"applicable": False}}
        key = f"{suite}/{case}"
        if key == "rbac_matrix/test_csrf_protection":
            counts = [one("SELECT COUNT(*) FROM api_keys WHERE description=?", (name,))[0]
                      for name in ("csrf-test-key", "nested-key")]
            if any(type(n) is not int or n != 1 for n in counts):
                raise FixtureError("witness_mismatch")
            result["csrf_witness"] = {"applicable": True,
                "api_keys_csrf_test_key": counts[0], "api_keys_nested_key": counts[1]}
        elif key == "rbac_matrix/test_rbac_matrix":
            for username, role in (("rbac_operator", "Operator"), ("rbac_viewer", "Viewer")):
                total, correct = one("SELECT COUNT(*), COALESCE(SUM(CASE WHEN role=? THEN 1 ELSE 0 END),0) FROM users WHERE username=?", (role, username))
                if type(total) is not int or type(correct) is not int or total != 1 or correct != 1:
                    raise FixtureError("witness_mismatch")
            result["rbac_witness"] = {"applicable": True,
                "users_rbac_operator": 1, "users_rbac_viewer": 1, "wrong_roles": 0}
        _deadline_guard(deadline)
        return result
    except sqlite3.Error:
        raise FixtureError("witness_db_unavailable") from None
    finally:
        if connection is not None:
            connection.close()


# --------------------------------------------------------------------------- #
# public_summary
# --------------------------------------------------------------------------- #


@_sanitized('invalid_fixture')
def public_summary(fixture: _Fixture) -> dict:
    """Fixed booleans and public certificate SHA256 values only."""
    if not isinstance(fixture, _Fixture):
        raise FixtureError("invalid_fixture")
    obs = fixture.observations
    if (not all(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value)
                for value in (fixture.ca_hash, fixture.leaf_hash)) or
            obs.get("ca_sha256") != fixture.ca_hash or
            obs.get("leaf_sha256") != fixture.leaf_hash):
        raise FixtureError("invalid_fixture")
    return {
        "case_prepared": True,
        "bootstrap_complete": obs.get("bootstrap_complete") is True,
        "verified_tls_ready": obs.get("verified_tls_ready") is True,
        "untrusted_ca_rejected": obs.get("untrusted_ca_rejected") is True,
        "wrapper_sessions_revoked": obs.get("wrapper_sessions_revoked") is True,
        "leaf_sha256": fixture.leaf_hash,
        "ca_sha256": fixture.ca_hash,
        "removed": fixture.removed is True,
    }


# --------------------------------------------------------------------------- #
# remove_case
# --------------------------------------------------------------------------- #


@_sanitized('cleanup_failed')
def remove_case(fixture: _Fixture, *, drain_confirmed: bool) -> bool:
    """Remove only exact recorded owned inodes, after exact caller drain True."""
    if not isinstance(fixture, _Fixture) or fixture.removed:
        raise FixtureError("invalid_fixture")
    if drain_confirmed is not True:
        return False
    _verify_owned(fixture)
    parent = fixture.case_root.parent
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    root_fd = None
    try:
        if _identity(os.fstat(parent_fd)) != fixture.owned_ancestry[1][1]:
            raise FixtureError("cleanup_denied")
        root_fd = os.open(fixture.case_root.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                          dir_fd=parent_fd)
        if _identity(os.fstat(root_fd)) != fixture.owned_ancestry[0][1]:
            raise FixtureError("cleanup_denied")
        _inspect_private_tree(root_fd)
        _rmtree(root_fd)
        _verify_owned(fixture)
        current = os.stat(fixture.case_root.name, dir_fd=parent_fd, follow_symlinks=False)
        if _identity(current) != fixture.owned_ancestry[0][1]:
            raise FixtureError("cleanup_denied")
        os.rmdir(fixture.case_root.name, dir_fd=parent_fd)
    finally:
        if root_fd is not None:
            os.close(root_fd)
        os.close(parent_fd)
    fixture.removed = True
    return True


def _inspect_private_tree(directory_fd):
    with os.scandir(directory_fd) as entries:
        for entry in entries:
            info = entry.stat(follow_symlinks=False)
            directory = stat.S_ISDIR(info.st_mode)
            if (info.st_uid != os.geteuid() or info.st_gid != os.getegid() or
                    (not directory and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1)) or
                    stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600)):
                raise FixtureError("cleanup_denied")
            if directory:
                fd = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                             dir_fd=directory_fd)
                try:
                    if _identity(os.fstat(fd)) != _identity(info):
                        raise FixtureError("cleanup_denied")
                    _inspect_private_tree(fd)
                finally:
                    os.close(fd)


def _rmtree(directory_fd):
    # Descriptor-relative traversal never follows a replacement ancestor/link.
    with os.scandir(directory_fd) as entries:
        for entry in entries:
            info = entry.stat(follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                fd = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                             dir_fd=directory_fd)
                try:
                    if _identity(os.fstat(fd)) != _identity(info):
                        raise FixtureError("cleanup_denied")
                    _rmtree(fd)
                finally:
                    os.close(fd)
                current = os.stat(entry.name, dir_fd=directory_fd, follow_symlinks=False)
                if _identity(current) != _identity(info):
                    raise FixtureError("cleanup_denied")
                os.rmdir(entry.name, dir_fd=directory_fd)
            elif stat.S_ISREG(info.st_mode):
                os.unlink(entry.name, dir_fd=directory_fd)
            else:
                raise FixtureError("cleanup_denied")
