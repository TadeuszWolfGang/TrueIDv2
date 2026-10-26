import json
import math
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

import requests


REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "integrations" / "sycope"))

from trueid_api import TrueIdApi
from sycope.api import SycopeApi
from sycope.config import get_config_value, load_config, validate_sycope_config
from sycope.exceptions import SycopeApiError, SycopeAuthError


HOST = "https://sycope.example.test"
FAKE_PASSWORD = "fixture-password-not-a-real-secret"
FAKE_SESSION = "fixture-session-not-a-real-secret"


def response(status=200, payload=None):
    result = requests.Response()
    result.status_code = status
    result.url = HOST + "/npm/api/v1/login"
    result.headers["Set-Cookie"] = "sid=" + FAKE_SESSION
    result.encoding = "utf-8"
    result._content = json.dumps(
        payload if payload is not None else {"status": 200, "session": FAKE_SESSION}
    ).encode()
    return result


def session(verify=True):
    result = requests.Session()
    result.trust_env = False
    result.verify = verify
    result.cookies.set("sid", FAKE_SESSION)
    result.send = mock.Mock(return_value=response())
    return result


class SycopeTransportSecurityTests(unittest.TestCase):
    def assert_transport(self, request_session, expected_verify):
        kwargs = request_session.send.call_args.kwargs
        self.assertEqual(kwargs["verify"], expected_verify)
        self.assertFalse(kwargs["allow_redirects"])
        timeout = kwargs["timeout"]
        self.assertIsInstance(timeout, tuple)
        self.assertEqual(len(timeout), 2)
        for bound in timeout:
            self.assertIsInstance(bound, (float, int))
            self.assertTrue(math.isfinite(bound))
            self.assertGreater(bound, 0)
            self.assertLessEqual(bound, 60)

    def test_login_preserves_custom_session_ca_and_has_bounded_timeouts(self):
        connection = session(verify="/fixture/private-ca.pem")

        SycopeApi(connection, HOST, "fixture-user", FAKE_PASSWORD)

        self.assert_transport(connection, "/fixture/private-ca.pem")
        prepared = connection.send.call_args.args[0]
        self.assertEqual(prepared.method, "POST")
        self.assertEqual(json.loads(prepared.body)["password"], FAKE_PASSWORD)

    def test_all_request_methods_preserve_ca_and_have_bounded_timeouts(self):
        connection = session(verify="/fixture/private-ca.pem")
        api = SycopeApi(connection, HOST, "fixture-user", FAKE_PASSWORD)

        for method in ("GET", "POST", "PUT", "DELETE"):
            with self.subTest(method=method):
                connection.send.reset_mock()
                api._make_request(method, HOST + "/npm/api/v1/fixture", {"name": "fixture"})

                connection.send.assert_called_once()
                self.assert_transport(connection, "/fixture/private-ca.pem")
                self.assertEqual(connection.send.call_args.args[0].method, method)

    def test_default_session_keeps_certificate_verification_enabled(self):
        connection = session()

        api = SycopeApi(connection, HOST, "fixture-user", FAKE_PASSWORD)
        self.assert_transport(connection, True)
        api._make_request("GET", HOST + "/npm/api/v1/fixture")
        self.assert_transport(connection, True)

    def test_requests_ca_bundle_is_honored_for_login_and_all_methods(self):
        connection = session()
        connection.trust_env = True
        with mock.patch.dict(os.environ, {"REQUESTS_CA_BUNDLE": "/fixture/environment-ca.pem"}, clear=True), \
                mock.patch("requests.sessions.get_netrc_auth", return_value=None):
            api = SycopeApi(connection, HOST, "fixture-user", FAKE_PASSWORD)
            self.assert_transport(connection, "/fixture/environment-ca.pem")
            for method in ("GET", "POST", "PUT", "DELETE"):
                with self.subTest(method=method):
                    api._make_request(method, HOST + "/npm/api/v1/fixture")
                    self.assert_transport(connection, "/fixture/environment-ca.pem")

    def test_non_https_hosts_are_rejected_before_credentials_are_sent(self):
        for host in ("http://sycope.example.test", "ftp://sycope.example.test", "sycope.example.test"):
            with self.subTest(host=host):
                connection = session()
                with self.assertRaises(SycopeAuthError):
                    SycopeApi(connection, host, "fixture-user", FAKE_PASSWORD)
                connection.send.assert_not_called()

    def test_non_https_request_is_rejected_before_any_send(self):
        connection = session()
        api = SycopeApi(connection, HOST, "fixture-user", FAKE_PASSWORD)
        connection.send.reset_mock()

        with self.assertRaises(SycopeApiError):
            api._make_request("POST", "http://sycope.example.test/fixture", {"password": FAKE_PASSWORD})

        connection.send.assert_not_called()

    def test_login_redirect_is_rejected_without_following_it(self):
        connection = session()
        connection.send.return_value = response(status=307)
        connection.send.return_value.headers["Location"] = "http://sycope.example.test/fixture"

        with self.assertRaises(SycopeAuthError):
            SycopeApi(connection, HOST, "fixture-user", FAKE_PASSWORD)

        connection.send.assert_called_once()
        self.assertFalse(connection.send.call_args.kwargs["allow_redirects"])

    def test_request_redirects_are_rejected_for_all_methods(self):
        connection = session()
        api = SycopeApi(connection, HOST, "fixture-user", FAKE_PASSWORD)
        connection.send.return_value = response(status=307)
        connection.send.return_value.headers["Location"] = "http://sycope.example.test/fixture"

        for method in ("GET", "POST", "PUT", "DELETE"):
            with self.subTest(method=method):
                connection.send.reset_mock()
                with self.assertRaises(SycopeApiError):
                    api._make_request(method, HOST + "/npm/api/v1/fixture")
                connection.send.assert_called_once()
                self.assertFalse(connection.send.call_args.kwargs["allow_redirects"])


class SycopeLogSecurityTests(unittest.TestCase):
    def assert_no_secrets(self, captured):
        logged = "\n".join(captured.output)
        self.assertNotIn(FAKE_PASSWORD, logged)
        self.assertNotIn(FAKE_SESSION, logged)

    def test_successful_login_does_not_log_auth_body_headers_or_cookies(self):
        connection = session()
        with self.assertLogs("sycope.api", level="DEBUG") as captured:
            SycopeApi(connection, HOST, "fixture-user", FAKE_PASSWORD)
        self.assert_no_secrets(captured)

    def test_invalid_login_json_does_not_log_raw_body(self):
        connection = session()
        connection.send.return_value._content = ("not-json-" + FAKE_SESSION).encode()
        with self.assertLogs("sycope.api", level="DEBUG") as captured:
            with self.assertRaises(SycopeAuthError) as error:
                SycopeApi(connection, HOST, "fixture-user", FAKE_PASSWORD)
        self.assert_no_secrets(captured)
        self.assertNotIn(FAKE_SESSION, str(error.exception))

    def test_rejected_login_does_not_expose_server_supplied_secret(self):
        connection = session()
        connection.send.return_value = response(payload={"status": 403, "message": FAKE_SESSION})
        with self.assertLogs("sycope.api", level="DEBUG") as captured:
            with self.assertRaises(SycopeAuthError) as error:
                SycopeApi(connection, HOST, "fixture-user", FAKE_PASSWORD)
        self.assert_no_secrets(captured)
        self.assertNotIn(FAKE_SESSION, str(error.exception))

    def test_requests_do_not_log_payload_response_headers_or_body(self):
        connection = session()
        api = SycopeApi(connection, HOST, "fixture-user", FAKE_PASSWORD)
        with self.assertLogs("sycope.api", level="DEBUG") as captured:
            api._make_request("POST", HOST + "/fixture", {"password": FAKE_PASSWORD})
        self.assert_no_secrets(captured)

    def test_trueid_mapping_reads_do_not_log_identity_row_contents(self):
        connection = session()
        rows = [{"ip": FAKE_PASSWORD, "current_users": [FAKE_SESSION]}]
        connection.send.return_value = response(payload={"data": rows})
        api = TrueIdApi(connection, HOST, api_key=FAKE_SESSION)
        with self.assertLogs("trueid_api", level="DEBUG") as captured:
            result = api.get_active_mappings()
        self.assertEqual(result, rows)
        self.assert_no_secrets(captured)

    def operation_cases(self, api):
        api.get_user_indicies = mock.Mock(return_value=[{
            "id": "fixture-id", "config": {"name": "fixture"}, "hidden": FAKE_SESSION,
        }])
        api.get_lookup = mock.Mock(return_value=("fixture-id", {}))
        api.privacy_check_lookup = mock.Mock(return_value="Private")
        return {
            "create_lookup": lambda: api.create_lookup("fixture", {"password": FAKE_PASSWORD}),
            "edit_lookup": lambda: api.edit_lookup("fixture-id", {"password": FAKE_PASSWORD}),
            "privacy_edit": lambda: api.privacy_edit_lookup("fixture-id", "Public"),
            "create_index": lambda: api.create_index("fixture", [{"hidden": FAKE_PASSWORD}], "daily"),
            "remove_index": lambda: api.remove_index("fixture"),
            "delete_lookup": lambda: api.delete_lookup("fixture"),
            "inject": lambda: api.inject_data("fixture", ["value"], [[FAKE_PASSWORD]]),
            "query": lambda: api.run_query("src fixture | where user=" + FAKE_PASSWORD, "@start", "@end"),
            "results": lambda: api.get_query_results("fixture-job"),
        }

    def test_operational_successes_do_not_log_payloads_rows_or_response_bodies(self):
        for name in (
            "create_lookup", "edit_lookup", "privacy_edit", "create_index", "remove_index",
            "delete_lookup", "inject", "query", "results",
        ):
            with self.subTest(operation=name):
                connection = session()
                api = SycopeApi(connection, HOST, "fixture-user", FAKE_PASSWORD)
                operations = self.operation_cases(api)
                connection.send.return_value = response(payload={
                    "status": 200, "id": "fixture-id", "jobId": "fixture-job",
                    "sidPerms": [{"sid": "ROLE_USER", "perms": ["VIEW"]}],
                    "data": [{"hidden": FAKE_SESSION}], "hidden": FAKE_PASSWORD,
                } if name != "query" else {
                    "jobId": "fixture-job", "data": {"total": 1, "columns": [FAKE_SESSION]},
                    "hidden": FAKE_PASSWORD,
                })
                with self.assertLogs("sycope.api", level="DEBUG") as captured:
                    operations[name]()
                self.assert_no_secrets(captured)

    def test_operational_errors_do_not_log_or_rethrow_server_body_secrets(self):
        for status in (403, FAKE_SESSION):
            for name in (
                "create_lookup", "edit_lookup", "privacy_edit", "create_index", "remove_index",
                "delete_lookup", "inject", "query", "results",
            ):
                with self.subTest(operation=name, status_type=type(status).__name__):
                    connection = session()
                    api = SycopeApi(connection, HOST, "fixture-user", FAKE_PASSWORD)
                    operations = self.operation_cases(api)
                    connection.send.return_value = response(payload={
                        "status": status, "message": FAKE_SESSION, "hidden": FAKE_PASSWORD,
                    })
                    with self.assertLogs("sycope.api", level="DEBUG") as captured:
                        with self.assertRaises(SycopeApiError) as error:
                            operations[name]()
                    self.assert_no_secrets(captured)
                    self.assertNotIn(FAKE_SESSION, str(error.exception))
                    self.assertNotIn(FAKE_PASSWORD, str(error.exception))
                    self.assertIsNone(error.exception.response)

    def test_config_loader_redacts_credential_aliases_case_insensitively(self):
        config = {
            "sycope_host": HOST,
            "trueid_api_key": FAKE_SESSION,
            "SYCOPE_PASS": FAKE_PASSWORD,
            "AccessToken": FAKE_SESSION,
            "client_secret": FAKE_PASSWORD,
            "PRIVATE_KEY": FAKE_PASSWORD,
            "session_cookie": FAKE_SESSION,
            "Authorization": FAKE_SESSION,
            "nested": {"API_KEY": FAKE_SESSION, "label": "visible-label"},
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            with self.assertLogs("sycope.config", level="DEBUG") as captured:
                loaded = load_config(str(path))
        self.assertEqual(loaded, config)
        self.assert_no_secrets(captured)
        self.assertIn("visible-label", "\n".join(captured.output))

    def test_config_accessor_redacts_existing_and_default_credentials(self):
        with self.assertLogs("sycope.config", level="DEBUG") as captured:
            stored = get_config_value({"TRUEID_API_KEY": FAKE_SESSION}, "TRUEID_API_KEY", FAKE_PASSWORD)
            default = get_config_value({}, "clientSecret", FAKE_PASSWORD)
        self.assertEqual(stored, FAKE_SESSION)
        self.assertEqual(default, FAKE_PASSWORD)
        self.assert_no_secrets(captured)

    def test_config_url_userinfo_is_not_logged_during_normalization_or_access(self):
        credential_url = "https://fixture-user:" + FAKE_PASSWORD + "@sycope.example.test"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps({"sycope_host": credential_url}), encoding="utf-8")
            with self.assertLogs("sycope.config", level="DEBUG") as captured:
                loaded = load_config(str(path))
                validate_sycope_config({**loaded, "sycope_login": "fixture-user", "sycope_pass": FAKE_PASSWORD})
                stored = get_config_value(loaded, "sycope_host")
                default = get_config_value({}, "sycope_host", credential_url)
        self.assertEqual(stored, credential_url)
        self.assertEqual(default, credential_url)
        self.assert_no_secrets(captured)


if __name__ == "__main__":
    unittest.main()
