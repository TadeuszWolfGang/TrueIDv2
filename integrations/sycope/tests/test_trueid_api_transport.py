"""Offline transport regressions; TLS keys and sync state stay outside source."""

from contextlib import contextmanager, ExitStack
import importlib.util
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

import requests


REPO_ROOT = Path(__file__).resolve().parents[3]
SYNC_DIR = REPO_ROOT / "integrations" / "sycope"
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(SYNC_DIR))

from trueid_api import TrueIdApi


OPERATIONS = ("mappings", "events")
CANARIES = {
    kind: "transport-fixture-" + kind
    for kind in ("user", "password", "key", "location", "reason", "exception", "data", "since")
}
ISOLATED_PROXY_ENV = {
    "HTTP_PROXY": "", "HTTPS_PROXY": "", "ALL_PROXY": "",
    "NO_PROXY": "127.0.0.1,localhost,::1",
}


def read(api, operation, since=1712148627):
    if operation == "mappings":
        return api.get_active_mappings()
    return api.get_events_since(since)


def response(status=200, payload=None):
    result = requests.Response()
    result.status_code = status
    result.url = "https://transport-fixture-url.example.test/api/v1/fixture"
    result.reason = CANARIES["reason"]
    result.headers["Location"] = "https://" + CANARIES["location"] + ".example.test/"
    result.encoding = "utf-8"
    result._content = json.dumps(payload if payload is not None else {"data": []}).encode()
    return result


def stub_session(result=None):
    connection = requests.Session()
    connection.headers["Content-Type"] = "application/json"
    connection.get = mock.Mock(return_value=result if result is not None else response())
    return connection


def load_isolated_sync(directory):
    """Load a separate module without creating its source-adjacent state dir."""
    spec = importlib.util.spec_from_file_location(
        "_trueid_sync_transport_fixture", SYNC_DIR / "trueid_sync.py"
    )
    module = importlib.util.module_from_spec(spec)
    with mock.patch("os.makedirs") as mkdir:
        spec.loader.exec_module(module)
    mkdir.assert_called_once_with(str(SYNC_DIR / "state"), exist_ok=True)
    module.STATE_DIR = str(directory)
    module.LAST_TIMESTAMP_FILE = str(Path(directory) / "last_event_timestamp.txt")
    return module


class TrueIdUrlValidationTests(unittest.TestCase):
    forbidden_hosts = (
        None, 1, [], "", "trueid.example.test", "//trueid.example.test", "https://",
        "https:///missing", "ftp://trueid.example.test", "http://trueid.example.test",
        "http://localhost.example.test", "http://localhost.", "http://127.1",
        "http://2130706433", "http://0177.0.0.1", "http://0x7f000001",
        "http://192.0.2.1", "http://[2001:db8::1]",
        "https://" + CANARIES["user"] + ":" + CANARIES["password"] + "@example.test",
        "https://user@example.test", "https://@example.test", "https://example.test:",
        "https://example.test:0", "https://example.test:65536", "https://example.test:-1",
        "https://example.test:port", "https://example.test:１２３", "https://%65xample.test",
        "https://.example.test", "https://*example.test", "https://bad_label.example.test",
        "https://xn--a.example.test", "https://😀.example.test",
        "https://-bad.example.test", "https://bad-.example.test", "https://bad..example.test",
        "https://" + "a" * 64 + ".test", "https://" + ".".join(["a" * 63] * 4),
        "https://[::1]suffix", "https://[::1]:", "https://[::1]:65536",
        "https://[::1", "https://[not-an-ip]", "https://[fe80::1%25eth0]",
        "https://example.test\\@other.test", "https://exam ple.test",
        "https://example.test/\npath", "https://example.test/\tpath",
        "https://example.test/\rpath", "https://example.test/\x00path",
        "https://example.test/\x7fpath", "https://example.test/\x80path",
        "https://example.test/\x81path", "https://example.test/\u0085path",
        "https://example.test/\u00a0path", "https://example.test?query",
        "https://example.test#fragment", "https://example.test?", "https://example.test#",
    )
    forbidden_bases = (
        None, 0, [], "api/v1", "@foreign.example.test", "https://foreign.example.test",
        "//foreign.example.test", "/api?query", "/api#fragment", "/api?", "/api#",
        "/api\\path", "/api\npath", "/api\x80path", "/api\x81path", "/api path",
    )

    def test_invalid_hosts_are_rejected_before_credential_assignment_or_send(self):
        for host in self.forbidden_hosts:
            with self.subTest(host=host):
                connection = mock.Mock()
                caught = None
                try:
                    TrueIdApi(connection, host, api_key=CANARIES["key"])
                except Exception as error:
                    caught = error
                self.assertIsInstance(caught, ValueError)
                connection.headers.update.assert_not_called()
                connection.get.assert_not_called()
                for sentinel in CANARIES.values():
                    self.assertNotIn(sentinel, str(caught))

    def test_invalid_api_bases_are_rejected_before_credential_assignment_or_send(self):
        for api_base in self.forbidden_bases:
            with self.subTest(api_base=api_base):
                connection = mock.Mock()
                with self.assertRaises(ValueError):
                    TrueIdApi(connection, "https://trueid.example.test", api_base, CANARIES["key"])
                connection.headers.update.assert_not_called()
                connection.get.assert_not_called()

    def test_mutated_fields_are_validated_before_both_methods_send(self):
        for operation in OPERATIONS:
            for field, values in (("host", self.forbidden_hosts), ("api_base", self.forbidden_bases)):
                for value in values:
                    with self.subTest(operation=operation, field=field, value=value):
                        connection = stub_session()
                        api = TrueIdApi(connection, "https://trueid.example.test", api_key=CANARIES["key"])
                        setattr(api, field, value)
                        with self.assertRaises(ValueError):
                            read(api, operation)
                        connection.get.assert_not_called()

    def test_loopback_https_idna_ipv6_and_default_ports_remain_valid(self):
        hosts = (
            "http://localhost", "http://LOCALHOST:3000", "http://127.0.0.1",
            "http://127.255.255.255:80", "http://[::1]", "http://[0:0:0:0:0:0:0:1]:3000",
            "https://example.test", "https://example.test:443", "https://example.test.:443",
            "https://192.0.2.1", "https://[2001:db8::1]", "https://[2001:db8::1]:443",
            "https://bücher.example", "https://xn--bcher-kva.example",
            "https://faß.example", "https://xn--fa-hia.example",
        )
        for host in hosts:
            for operation in OPERATIONS:
                with self.subTest(host=host, operation=operation):
                    connection = stub_session()
                    api = TrueIdApi(connection, host)
                    self.assertEqual(read(api, operation), [])
                    connection.get.assert_called_once()
                    self.assertEqual(connection.get.call_args.args[0], host + "/api/v1/" + operation)

    def test_valid_public_host_and_path_mutations_preserve_dispatch(self):
        for api_base in ("", "/api/v2", "/api/v2/"):
            for operation in OPERATIONS:
                with self.subTest(api_base=api_base, operation=operation):
                    connection = stub_session()
                    api = TrueIdApi(connection, "https://first.example.test")
                    api.host = "https://second.example.test:443/prefix"
                    api.api_base = api_base
                    read(api, operation)
                    self.assertEqual(
                        connection.get.call_args.args[0], api.host + api_base + "/" + operation
                    )


class TrueIdResponseAndLogTests(unittest.TestCase):
    def assert_no_canaries(self, captured):
        logged = "\n".join(captured.output)
        for sentinel in CANARIES.values():
            self.assertNotIn(sentinel, logged)
        self.assertNotIn("transport-fixture-url", logged)

    def test_every_3xx_is_rejected_before_status_check_or_json_for_both_methods(self):
        for status in range(300, 400):
            for operation in OPERATIONS:
                with self.subTest(status=status, operation=operation):
                    result = response(status)
                    result.json = mock.Mock(side_effect=AssertionError("must not decode redirects"))
                    result.raise_for_status = mock.Mock()
                    connection = stub_session(result)
                    api = TrueIdApi(connection, "https://trueid.example.test", api_key=CANARIES["key"])
                    with self.assertLogs("trueid_api", level="DEBUG") as captured:
                        with self.assertRaises(ValueError) as caught:
                            read(api, operation)
                    self.assertIn(str(status), str(caught.exception))
                    self.assert_no_canaries(captured)
                    for sentinel in CANARIES.values():
                        self.assertNotIn(sentinel, str(caught.exception))
                    result.json.assert_not_called()
                    result.raise_for_status.assert_not_called()
                    connection.get.assert_called_once()
                    self.assertFalse(connection.get.call_args.kwargs["allow_redirects"])

    def test_headers_json_formats_since_timeout_and_success_logs_are_preserved(self):
        rows = [{"user": CANARIES["data"], "raw_data": CANARIES["password"]}]
        for operation in OPERATIONS:
            for payload in (rows, {"data": rows}):
                with self.subTest(operation=operation, envelope=isinstance(payload, dict)):
                    connection = stub_session(response(payload=payload))
                    connection.headers["Accept"] = "application/json"
                    with self.assertLogs("trueid_api", level="DEBUG") as captured:
                        api = TrueIdApi(connection, "https://transport-fixture-url.example.test", api_key=CANARIES["key"])
                        result = read(api, operation, since=CANARIES["since"])
                    self.assertEqual(result, rows)
                    self.assert_no_canaries(captured)
                    self.assertEqual(connection.headers["X-API-Key"], CANARIES["key"])
                    self.assertEqual(connection.headers["Content-Type"], "application/json")
                    self.assertEqual(connection.headers["Accept"], "application/json")
                    self.assertNotIn("Authorization", connection.headers)
                    kwargs = connection.get.call_args.kwargs
                    self.assertEqual(kwargs["timeout"], 30)
                    self.assertFalse(kwargs["allow_redirects"])
                    if operation == "events":
                        self.assertEqual(kwargs["params"], {"since": CANARIES["since"]})
                    else:
                        self.assertNotIn("params", kwargs)

    def test_http_error_contract_and_failure_logs_remain_safe(self):
        for operation in OPERATIONS:
            for status in (400, 401, 403, 404, 500, 503):
                with self.subTest(operation=operation, status=status):
                    result = response(status, {"data": CANARIES["data"]})
                    result.json = mock.Mock(side_effect=AssertionError("must check HTTP error first"))
                    connection = stub_session(result)
                    api = TrueIdApi(connection, "https://trueid.example.test")
                    with self.assertLogs("trueid_api", level="DEBUG") as captured:
                        with self.assertRaises(requests.HTTPError) as caught:
                            read(api, operation)
                    self.assertIs(caught.exception.response, result)
                    result.json.assert_not_called()
                    self.assert_no_canaries(captured)

    def test_request_exception_and_invalid_json_are_not_logged_raw(self):
        for operation in OPERATIONS:
            for failure in (requests.ConnectionError, ValueError):
                with self.subTest(operation=operation, failure=failure.__name__):
                    connection = stub_session()
                    error = failure(" ".join(CANARIES.values()))
                    if failure is ValueError:
                        connection.get.return_value.json = mock.Mock(side_effect=error)
                    else:
                        connection.get.side_effect = error
                    api = TrueIdApi(connection, "https://trueid.example.test")
                    with self.assertLogs("trueid_api", level="DEBUG") as captured:
                        with self.assertRaises(failure) as caught:
                            read(api, operation)
                    self.assertIs(caught.exception, error)
                    self.assert_no_canaries(captured)

    def test_validation_never_logs_or_raises_embedded_userinfo(self):
        connection = stub_session()
        host = "https://" + CANARIES["user"] + ":" + CANARIES["password"] + "@example.test"
        with self.assertLogs("trueid_api", level="DEBUG") as captured:
            TrueIdApi(connection, "https://safe.example.test")
            with self.assertRaises(ValueError) as caught:
                TrueIdApi(connection, host, api_key=CANARIES["key"])
        self.assert_no_canaries(captured)
        for sentinel in CANARIES.values():
            self.assertNotIn(sentinel, str(caught.exception))
        connection.get.assert_not_called()
        self.assertNotIn("X-API-Key", connection.headers)

    def test_both_sync_fetch_catches_exclude_exception_url_headers_and_data(self):
        raw = (
            "https://" + CANARIES["user"] + ":" + CANARIES["password"] + "@example.test "
            + " ".join(CANARIES.values())
        )
        with tempfile.TemporaryDirectory(prefix="trueid-sync-transport-", dir="/tmp") as directory:
            sync = load_isolated_sync(directory)
            self.assertFalse(Path(sync.LAST_TIMESTAMP_FILE).is_relative_to(SYNC_DIR))
            for operation in OPERATIONS:
                with self.subTest(operation=operation):
                    api = mock.Mock()
                    api.get_active_mappings.side_effect = requests.ConnectionError(raw)
                    api.get_events_since.side_effect = requests.ConnectionError(raw)
                    sycope = mock.Mock()
                    with self.assertLogs(level="DEBUG") as captured:
                        if operation == "mappings":
                            self.assertEqual(sync.fetch_trueid_mappings(api), [])
                        else:
                            sync.sync_events(sycope, api, {})
                    self.assert_no_canaries(captured)
                    self.assertIn("ConnectionError", "\n".join(captured.output))
                    sycope.inject_data.assert_not_called()
                    self.assertFalse(Path(sync.LAST_TIMESTAMP_FILE).exists())

    def test_sync_success_and_malformed_event_timestamp_do_not_log_identity_payload(self):
        with tempfile.TemporaryDirectory(prefix="trueid-sync-transport-", dir="/tmp") as directory:
            sync = load_isolated_sync(directory)
            api = mock.Mock()
            api.get_active_mappings.return_value = [{"user": CANARIES["data"]}]
            api.get_events_since.return_value = [{
                "timestamp": CANARIES["exception"], "raw_data": CANARIES["data"],
                "user": CANARIES["user"], "ip": "192.0.2.1",
            }]
            sycope = mock.Mock()
            with self.assertLogs(level="DEBUG") as captured:
                self.assertEqual(sync.fetch_trueid_mappings(api), api.get_active_mappings.return_value)
                sync.sync_events(sycope, api, {})
            self.assert_no_canaries(captured)
            sycope.inject_data.assert_called_once()
            self.assertEqual(Path(sync.LAST_TIMESTAMP_FILE).read_text(), "0")

    def test_sync_since_value_is_sent_unchanged_without_logging_it(self):
        with tempfile.TemporaryDirectory(prefix="trueid-sync-transport-", dir="/tmp") as directory:
            sync = load_isolated_sync(directory)
            api = mock.Mock()
            api.get_events_since.return_value = []
            with mock.patch.object(sync, "read_last_timestamp", return_value=CANARIES["since"]):
                with self.assertLogs(level="DEBUG") as captured:
                    sync.sync_events(mock.Mock(), api, {})
            api.get_events_since.assert_called_once_with(CANARIES["since"])
            self.assert_no_canaries(captured)

    def test_sync_injection_failure_does_not_log_raw_exception_or_advance_state(self):
        with tempfile.TemporaryDirectory(prefix="trueid-sync-transport-", dir="/tmp") as directory:
            sync = load_isolated_sync(directory)
            api = mock.Mock()
            api.get_events_since.return_value = [{"timestamp": 1712148627, "user": CANARIES["data"]}]
            sycope = mock.Mock()
            sycope.inject_data.side_effect = sync.SycopeError(" ".join(CANARIES.values()))
            with self.assertLogs(level="DEBUG") as captured:
                sync.sync_events(sycope, api, {})
            self.assert_no_canaries(captured)
            self.assertIn("SycopeError", "\n".join(captured.output))
            self.assertFalse(Path(sync.LAST_TIMESTAMP_FILE).exists())

    def test_skipped_ipv6_mapping_does_not_log_its_payload(self):
        with tempfile.TemporaryDirectory(prefix="trueid-sync-transport-", dir="/tmp") as directory:
            sync = load_isolated_sync(directory)
            with self.assertLogs(level="DEBUG") as captured:
                lookup, summary = sync.merge_lookup_data(
                    {"file": {"rows": []}},
                    [{"ip": "2001:db8::" + CANARIES["data"], "user": CANARIES["user"]}],
                    {},
                )
            self.assertEqual(lookup["file"]["rows"], [])
            self.assertEqual(summary, {"added": 0, "modified": 0, "unchanged": 0})
            self.assert_no_canaries(captured)


class Recorder:
    def __init__(self):
        self.lock = threading.Lock()
        self.requests = []
        self.status = 200
        self.location = None

    def configure(self, status=200, location=None):
        with self.lock:
            self.requests.clear()
            self.status = status
            self.location = location

    def snapshot(self):
        with self.lock:
            return list(self.requests)


@contextmanager
def running_server(certificate=None, private_key=None):
    recorder = Recorder()
    context = None
    if certificate is not None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(certificate), str(private_key))

    class BoundedHTTPServer(HTTPServer):
        def get_request(self):
            connection, address = super().get_request()
            connection.settimeout(2)
            try:
                if context is not None:
                    connection = context.wrap_socket(connection, server_side=True)
            except Exception:
                connection.close()
                raise
            return connection, address

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            with recorder.lock:
                recorder.requests.append({"path": self.path, "key": self.headers.get("X-API-Key")})
                status = recorder.status
                location = recorder.location
            # A same-origin redirect has a successful terminal route, making
            # the old automatic-follow behavior observable without a loop.
            if self.path.startswith("/redirected-target"):
                status, location = 200, None
            body = json.dumps({"data": [{"fixture": CANARIES["data"]}]}).encode()
            self.send_response(status, CANARIES["reason"])
            if location is not None:
                self.send_header("Location", location)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            pass

    server = BoundedHTTPServer(("127.0.0.1", 0), Handler)
    try:
        scheme = "https" if certificate is not None else "http"
        recorder.url = f"{scheme}://127.0.0.1:{server.server_port}"
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        thread.start()
        try:
            yield recorder
        finally:
            server.shutdown()
            thread.join(timeout=3)
            if thread.is_alive():
                raise AssertionError("transport fixture server thread did not stop")
    finally:
        server.server_close()


def generate_tls_fixture(directory):
    """Generate a private ephemeral CA and a leaf valid for loopback only."""
    openssl = shutil.which("openssl")
    if openssl is None:
        raise RuntimeError("openssl is required for the offline TLS fixture")
    directory = Path(directory)
    ca = directory / "ca.pem"
    ca_key = directory / "ca-key.pem"
    key = directory / "server-key.pem"
    csr = directory / "server.csr"
    certificate = directory / "server.pem"
    extensions = directory / "server.ext"
    extensions.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
        "subjectAltName=IP:127.0.0.1,DNS:localhost\n",
        encoding="ascii",
    )
    commands = (
        [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "1",
         "-subj", "/CN=TrueID transport fixture CA", "-keyout", str(ca_key), "-out", str(ca),
         "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"],
        [openssl, "req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256",
         "-subj", "/CN=localhost", "-keyout", str(key), "-out", str(csr)],
        [openssl, "x509", "-req", "-in", str(csr), "-CA", str(ca), "-CAkey", str(ca_key),
         "-CAcreateserial", "-out", str(certificate), "-days", "1", "-sha256", "-extfile", str(extensions)],
    )
    for command in commands:
        subprocess.run(command, check=True, capture_output=True, timeout=30)
    return ca, certificate, key


class TrueIdRealTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        stack = ExitStack()
        cls.addClassCleanup(stack.close)
        directory = stack.enter_context(tempfile.TemporaryDirectory(prefix="trueid-tls-transport-", dir="/tmp"))
        cls.ca, certificate, key = generate_tls_fixture(directory)
        # Both HTTPS origins use the same CA, so old redirect following can
        # actually reach the foreign recorder rather than fail TLS first.
        cls.source = stack.enter_context(running_server(certificate, key))
        cls.https_recorder = stack.enter_context(running_server(certificate, key))
        cls.http_recorder = stack.enter_context(running_server())

    def setUp(self):
        self.source.configure()
        self.https_recorder.configure()
        self.http_recorder.configure()
        self.env = mock.patch.dict(os.environ, ISOLATED_PROXY_ENV, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        netrc = mock.patch("requests.sessions.get_netrc_auth", return_value=None)
        netrc.start()
        self.addCleanup(netrc.stop)

    def connection(self, verify=True, trust_env=True):
        connection = requests.Session()
        self.addCleanup(connection.close)
        connection.verify = verify
        connection.trust_env = trust_env
        connection.headers["Content-Type"] = "application/json"
        return connection

    def assert_dispatch(self, connection, sent, verify, trust_env):
        self.assertEqual(connection.verify, verify)
        self.assertIs(connection.trust_env, trust_env)
        self.assertEqual(sent.call_args.kwargs["timeout"], 30)
        self.assertFalse(sent.call_args.kwargs["allow_redirects"])

    def test_caller_ca_bundle_and_trust_env_are_preserved_with_verified_tls(self):
        for trust_env in (False, True):
            for operation in OPERATIONS:
                with self.subTest(trust_env=trust_env, operation=operation):
                    self.source.configure()
                    connection = self.connection(verify=str(self.ca), trust_env=trust_env)
                    api = TrueIdApi(connection, self.source.url, api_key=CANARIES["key"])
                    with mock.patch.object(connection, "send", wraps=connection.send) as sent:
                        self.assertEqual(read(api, operation), [{"fixture": CANARIES["data"]}])
                    records = self.source.snapshot()
                    self.assertEqual(len(records), 1)
                    self.assertEqual(records[0]["key"], CANARIES["key"])
                    self.assertEqual(connection.headers["Content-Type"], "application/json")
                    self.assertEqual(sent.call_args.kwargs["verify"], str(self.ca))
                    self.assert_dispatch(connection, sent, str(self.ca), trust_env)
                    sent.assert_called_once()

    def test_both_ca_environment_variables_work_through_requests_merging(self):
        for variable in ("REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
            for operation in OPERATIONS:
                with self.subTest(variable=variable, operation=operation):
                    self.source.configure()
                    connection = self.connection()
                    api = TrueIdApi(connection, self.source.url, api_key=CANARIES["key"])
                    with mock.patch.dict(os.environ, {variable: str(self.ca)}):
                        with mock.patch.object(connection, "send", wraps=connection.send) as sent:
                            self.assertEqual(read(api, operation), [{"fixture": CANARIES["data"]}])
                    self.assertEqual(len(self.source.snapshot()), 1)
                    self.assertEqual(sent.call_args.kwargs["verify"], str(self.ca))
                    self.assert_dispatch(connection, sent, True, True)
                    sent.assert_called_once()

    def test_untrusted_ca_fails_before_http_without_insecure_fallback(self):
        for operation in OPERATIONS:
            with self.subTest(operation=operation):
                self.source.configure()
                connection = self.connection()
                api = TrueIdApi(connection, self.source.url, api_key=CANARIES["key"])
                caught = None
                with mock.patch.object(connection, "send", wraps=connection.send) as sent:
                    try:
                        read(api, operation)
                    except Exception as error:
                        caught = error
                records = self.source.snapshot()
                key_count = sum(record["key"] is not None for record in records)
                self.assertEqual(len(records), 0)
                self.assertEqual(key_count, 0)
                self.assertIsInstance(caught, requests.exceptions.SSLError)
                self.assertTrue(sent.call_args.kwargs["verify"])
                self.assert_dispatch(connection, sent, True, True)
                sent.assert_called_once()

    def test_foreign_https_and_http_redirects_never_receive_requests_or_keys(self):
        for status in (301, 302, 303, 307, 308):
            for operation in OPERATIONS:
                for recorder in (self.https_recorder, self.http_recorder):
                    with self.subTest(status=status, operation=operation, destination=recorder.url):
                        self.source.configure(status, recorder.url + "/" + CANARIES["location"])
                        recorder.configure()
                        connection = self.connection(verify=str(self.ca))
                        api = TrueIdApi(connection, self.source.url, api_key=CANARIES["key"])
                        caught = None
                        try:
                            read(api, operation)
                        except Exception as error:
                            caught = error
                        source_records = self.source.snapshot()
                        records = recorder.snapshot()
                        key_count = sum(record["key"] is not None for record in records)
                        self.assertEqual(len(source_records), 1)
                        self.assertEqual(source_records[0]["key"], CANARIES["key"])
                        self.assertEqual(len(records), 0)
                        self.assertEqual(key_count, 0)
                        self.assertIsInstance(caught, ValueError)
                        self.assertIn(str(status), str(caught))
                        self.assertTrue(source_records[0]["path"].startswith("/api/v1/" + operation))

    def test_same_origin_redirects_are_also_never_followed(self):
        for operation in OPERATIONS:
            with self.subTest(operation=operation):
                self.source.configure(302, self.source.url + "/redirected-target")
                connection = self.connection(verify=str(self.ca))
                api = TrueIdApi(connection, self.source.url, api_key=CANARIES["key"])
                caught = None
                try:
                    read(api, operation)
                except Exception as error:
                    caught = error
                source_records = self.source.snapshot()
                forwarded = [record for record in source_records if record["path"].startswith("/redirected-target")]
                key_count = sum(record["key"] is not None for record in forwarded)
                self.assertEqual(len(source_records), 1)
                self.assertEqual(len(forwarded), 0)
                self.assertEqual(key_count, 0)
                self.assertIsInstance(caught, ValueError)


if __name__ == "__main__":
    unittest.main()
