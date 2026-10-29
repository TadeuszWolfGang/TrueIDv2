"""Synthetic DATA controls for the real live-auth report policy, not native proof.

Import only defines tests. Standard unittest setup loads the explicit repository
runner path; no runner main, helper, application, network or external DB is used.
"""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest


_DELETE = object()
_IDENTITY_KEYS = (
    "source_sha256", "helper_sha256", "runner_sha256", "build_manifest_sha256",
    "web_sha256", "auth_sha256", "rbac_sha256", "runtime_sha256", "build_capture_sha256",
)
_AUTH_KEYS = (
    "verified_tls", "untrusted_ca_rejected", "initial_force_change", "three_cookie_rotation",
    "changed_password_new_login", "both_sessions_revoked",
)


def _hash(label):
    return hashlib.sha256(("public-synthetic:" + label).encode("ascii")).hexdigest()


def _inventory():
    return {"auth_integration": ["test_login_alpha", "test_login_beta"],
            "rbac_matrix": ["test_csrf_protection", "test_rbac_matrix", "test_z_other"]}


def _expected():
    # Independently supplied expectations, never obtained from the runner/report.
    return {"identities": {key: _hash(key) for key in _IDENTITY_KEYS},
            "inventory": _inventory(),
            "ignored_inventory": {"auth_integration": ["test_login_beta"], "rbac_matrix": []},
            "timeout": 900.0, "case_timeout": 40.0}


def _witness(suite, case_id):
    result = {"migrations_successful": 2, "csrf_witness": {"applicable": False},
              "rbac_witness": {"applicable": False}}
    if suite == "rbac_matrix" and case_id == "test_csrf_protection":
        result["csrf_witness"] = {"applicable": True, "api_keys_csrf_test_key": 1, "api_keys_nested_key": 1}
    if suite == "rbac_matrix" and case_id == "test_rbac_matrix":
        result["rbac_witness"] = {"applicable": True, "users_rbac_operator": 1,
                                  "users_rbac_viewer": 1, "wrong_roles": 0}
    return result


def _pass_report():
    inventory = _inventory()
    selected = [{"suite": suite, "id": case_id} for suite in ("auth_integration", "rbac_matrix")
                for case_id in inventory[suite]]
    rows = []
    for index, choice in enumerate(selected):
        suite, case_id = choice["suite"], choice["id"]
        rows.append({**choice, "status": "PASS", "phase": "complete", "category": "ok",
            "presence": {"fixture": True, "libtest": True, "witness": True}, "exit": 0,
            "timed_out": False, "elapsed_s": 0.5,
            "result": {"id": case_id, "passed": 1, "failed": 0, "ignored": 0, "measured": 0,
                       "filtered_out": len(inventory[suite]) - 1},
            "auth": {key: True for key in _AUTH_KEYS},
            "fixture": {"case_prepared": True, "bootstrap_complete": True, "verified_tls_ready": True,
                "untrusted_ca_rejected": True, "wrapper_sessions_revoked": True,
                "leaf_sha256": _hash("leaf-%d" % index), "ca_sha256": _hash("ca-%d" % index), "removed": True},
            "witness": _witness(suite, case_id), "openssl_commands": 3,
            "owned_drain": True, "private_data_removed": True})
    return {"schemaVersion": 1, "status": "PASS", "phase": "complete", "category": "ok",
        "presence": {"identities": True, "discovery": True, "cases": True},
        "identities": {key: _hash(key) for key in _IDENTITY_KEYS},
        "build_evidence": {"root_owned_inputs": True, "cargo_records_validated": True,
            "producer_scope": "ROOT_OWNED_CAPTURE_NOT_CRYPTOGRAPHIC_ATTESTATION"},
        "discovery": inventory, "ignored_inventory": {"auth_integration": ["test_login_beta"], "rbac_matrix": []},
        "selected": selected, "per_case": rows,
        "counts": {"discovered": 5, "selected": 5, "attempted": 5, "passed": 5, "failed": 0, "not_run": 0},
        "elapsed_s": 12.5, "owned_drain": True, "private_data_removed": True}


def _terminal_fail(category="timeout"):
    report = _pass_report()
    report.update(status="FAIL", phase="cleanup", category=category, elapsed_s=950.0)
    report["per_case"][-1].update(status="FAIL", phase="cleanup", category=category,
                                  timed_out=category == "timeout", elapsed_s=50.0)
    report["counts"].update(passed=4, failed=1)
    return report


def _not_run(choice):
    return {**choice, "status": "NOT_RUN", "phase": "case", "category": "not_run",
        "presence": {"fixture": False, "libtest": False, "witness": False}, "exit": None,
        "timed_out": False, "elapsed_s": 0, "result": None, "auth": None, "fixture": None,
        "witness": None, "openssl_commands": 0, "owned_drain": None, "private_data_removed": None}


def _aborted_report():
    report = _pass_report()
    report.update(status="FAIL", phase="case", category="case_failed")
    report["per_case"][0].update(status="FAIL", phase="case", category="case_failed", exit=1,
                                 result=None, witness=None, presence={"fixture": True, "libtest": False, "witness": False})
    report["per_case"][1:] = [_not_run(choice) for choice in report["selected"][1:]]
    report["counts"].update(attempted=1, passed=0, failed=1, not_run=4)
    return report


def _encode(report):
    return json.dumps(report, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def _change(report, path, value):
    node = report
    for key in path[:-1]:
        node = node[key]
    if value is _DELETE:
        del node[path[-1]]
    else:
        node[path[-1]] = copy.deepcopy(value)


class TestLiveAuthReportPolicy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).resolve().parents[2] / "scripts" / "run-live-auth-acceptance.py"
        name = "_trueid_live_auth_policy_subject"
        if name in sys.modules:
            raise RuntimeError("policy subject name already loaded")
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise RuntimeError("policy subject loader unavailable")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        cls.addClassCleanup(sys.modules.pop, name, None)
        spec.loader.exec_module(module)
        cls.validate = staticmethod(module.validate_report)

    def check(self, raw, expected, actual_exit, valid, reason):
        result = self.validate(raw, expected=expected, actual_exit=actual_exit)
        self.assertIs(type(result), dict)
        self.assertEqual(set(result), {"valid", "reason", "report"})
        self.assertIs(result["valid"], valid)
        self.assertEqual(result["reason"], reason)
        if not valid:
            self.assertIsNone(result["report"])
        return result

    def accept(self, report, expected, actual_exit=0):
        result = self.check(_encode(report), expected, actual_exit, True, "ok")
        self.assertEqual(result["report"], report)

    def baseline(self):
        report, expected = _pass_report(), _expected()
        self.accept(report, expected)
        return report, expected

    def reject(self, path, value, reason):
        report, expected = self.baseline()
        _change(report, path, value)
        self.check(_encode(report), expected, 0, False, reason)

    def test_complete_pass_has_independent_exact_inventory_and_witnesses(self):
        report, expected = self.baseline()
        self.assertIsNot(report["identities"], expected["identities"])
        self.assertIsNot(report["discovery"], expected["inventory"])
        self.assertEqual([row["id"] for row in report["per_case"]], [row["id"] for row in report["selected"]])
        self.assertEqual([row["result"]["filtered_out"] for row in report["per_case"]], [1, 1, 2, 2, 2])
        hashes = [row["fixture"][key] for row in report["per_case"] for key in ("ca_sha256", "leaf_sha256")]
        self.assertEqual(len(hashes), len(set(hashes)))
        self.assertTrue(all(len(value) == 64 and set(value) <= set("0123456789abcdef") for value in hashes))

    def test_expected_dto_and_execution_budgets(self):
        changes = [(key, _DELETE, "expected") for key in _expected()]
        changes += [("extra", "public-marker", "expected")]
        changes += [("timeout", value, "expected") for value in (0, -1, True, "900", None, 1200.1)]
        changes += [("case_timeout", value, "expected") for value in (30, 45.1, True, None)]
        changes += [("timeout", float("inf"), "bounds"), ("case_timeout", float("nan"), "bounds")]
        for key, value, reason in changes:
            with self.subTest(field=key, value=repr(value)):
                report, expected = self.baseline()
                _change(expected, (key,), value)
                self.check(_encode(report), expected, 0, False, reason)
        for key, reason in (("identities", "identities"), ("inventory", "inventory"), ("ignored_inventory", "inventory")):
            with self.subTest(unobserved_expected=key):
                report, expected = self.baseline()
                expected[key] = None
                self.check(_encode(report), expected, 0, False, reason)
        for timeout, case_timeout in ((1200, 45), (900, 30.01)):
            with self.subTest(accepted_budget=(timeout, case_timeout)):
                report, expected = self.baseline()
                expected.update(timeout=timeout, case_timeout=case_timeout)
                self.accept(report, expected)

    def test_discovery_and_ignored_inventory(self):
        inv = _inventory()
        changes = [(('discovery',), {}, "inventory"), (('discovery', 'auth_integration'), [], "inventory"),
            (('discovery', 'auth_integration'), ['test_login_alpha'] * 2, "inventory"),
            (('discovery', 'auth_integration'), list(reversed(inv['auth_integration'])), "inventory"),
            (('discovery', 'rbac_matrix'), _DELETE, "inventory"),
            (('discovery', 'extra_suite'), ['test_public'], "inventory"),
            (('discovery', 'auth_integration'), ['test_login_alpha'], "inventory"),
            (('discovery',), None, "inventory"), (('ignored_inventory',), None, "inventory"),
            (('ignored_inventory', 'auth_integration'), [], "inventory"),
            (('ignored_inventory', 'rbac_matrix'), ['test_unknown'], "inventory"),
            (('ignored_inventory', 'auth_integration'), ['test_login_beta'] * 2, "inventory")]
        changes += [(('discovery', 'auth_integration'), [value], "inventory")
                    for value in ('', 'bad id', '../test', 'test\n', 'x' * 257)]
        for path, value, reason in changes:
            with self.subTest(path=path, mutation=repr(value)):
                self.reject(path, value, reason)

    def test_selection_results_and_exact_filter_counts(self):
        base = _pass_report()
        changes = [(('selected',), base['selected'][:-1], "selection"),
            (('selected',), base['selected'] + [{'suite': 'rbac_matrix', 'id': 'test_unknown'}], "selection"),
            (('selected',), list(reversed(base['selected'])), "selection"),
            (('selected', 0, 'id'), 'test_unknown', "selection"),
            (('selected', 0, 'suite'), 'unknown_suite', "selection"),
            (('per_case',), base['per_case'][:-1], "selection"),
            (('per_case', 0, 'id'), 'test_unknown', "selection"),
            (('per_case', 0, 'result', 'id'), 'test_unknown', "result")]
        changes += [(('per_case', 0, 'result', key), value, "result")
                    for key, value in [('passed', 0), ('failed', 1), ('ignored', 1), ('measured', 1),
                                       ('passed', True), ('passed', 1.0), ('filtered_out', 0)]]
        changes += [(('per_case', 2, 'result', 'filtered_out'), value, "result") for value in (1, True, 2.0)]
        for path, value, reason in changes:
            with self.subTest(path=path, mutation=repr(value)):
                self.reject(path, value, reason)

    def test_counts_and_schema_use_exact_integer_types(self):
        for key, original in _pass_report()['counts'].items():
            for value in (original + 1, True, float(original), None):
                with self.subTest(count=key, mutation=value):
                    self.reject(('counts', key), value, "counts")
        for value in (True, 1.0, 2, None):
            with self.subTest(schemaVersion=value):
                self.reject(('schemaVersion',), value, "schema")

    def test_observed_actual_exit_overrules_a_pass_claim(self):
        for exit_code in (1, 2, 255, -1, -15):
            with self.subTest(actual_exit=exit_code):
                report, expected = self.baseline()
                self.check(_encode(report), expected, exit_code, False, "pass")
        for exit_code in (True, False, 0.0, None, '0', -256, 256):
            with self.subTest(invalid_actual_exit=repr(exit_code)):
                report, expected = self.baseline()
                self.check(_encode(report), expected, exit_code, False, "exit")
        for exit_code in (1, -15, None):
            with self.subTest(observed_child_exit=exit_code):
                self.reject(('per_case', 0, 'exit'), exit_code, "result")

    def test_elapsed_openssl_and_pass_timeout_fields(self):
        changes = [(('elapsed_s',), value, "elapsed") for value in (-1, 900.1, True)]
        changes += [(('per_case', 0, 'elapsed_s'), value, "case") for value in (-1, 40.1, True)]
        changes += [(('per_case', 0, 'openssl_commands'), value, "case") for value in (-1, 129, True, 3.0, None)]
        changes += [(('per_case', 0, 'openssl_commands'), 0, "pass"),
                    (('per_case', 0, 'timed_out'), True, "pass")]
        for path, value, reason in changes:
            with self.subTest(path=path, mutation=value):
                self.reject(path, value, reason)

    def test_all_source_helper_build_elf_and_runtime_identities(self):
        for key in _IDENTITY_KEYS:
            with self.subTest(identity=key):
                self.reject(('identities', key), _hash('wrong-' + key), "identities")
        for value in ('g' * 64, 'A' * 64, 'a' * 63, 'a' * 65, 'a' * 64 + '\n', True, None):
            with self.subTest(hash_shape=repr(value)):
                self.reject(('identities', 'web_sha256'), value, "identities")

    def test_recorded_build_provenance_is_closed_and_exact(self):
        for key, value in (('root_owned_inputs', False), ('cargo_records_validated', False),
                           ('root_owned_inputs', 1), ('producer_scope', 'PUBLIC_FAKE_ATTESTATION')):
            with self.subTest(build_field=key, mutation=value):
                self.reject(('build_evidence', key), value, "build_evidence")

    def test_every_auth_observation_is_required_and_true(self):
        for key in _AUTH_KEYS:
            for value in (False, 1, None, _DELETE):
                with self.subTest(auth_field=key, mutation=repr(value)):
                    self.reject(('per_case', 0, 'auth', key), value, "auth")
        self.reject(('per_case', 0, 'auth'), None, "auth")

    def test_fixture_certificates_cleanup_and_presence(self):
        base = _pass_report()
        changes = [(('per_case', 1, 'fixture', key), base['per_case'][0]['fixture'][other], "fixture")
                   for key, other in [('leaf_sha256', 'leaf_sha256'), ('ca_sha256', 'ca_sha256'),
                                      ('leaf_sha256', 'ca_sha256'), ('ca_sha256', 'leaf_sha256')]]
        changes += [(('per_case', 0, 'fixture', 'leaf_sha256'), base['per_case'][0]['fixture']['ca_sha256'], "fixture"),
            (('per_case', 0, 'fixture', 'leaf_sha256'), 'not-hex', "fixture"),
            (('per_case', 0, 'fixture', 'case_prepared'), False, "fixture"),
            (('per_case', 0, 'fixture', 'removed'), False, "cleanup")]
        changes += [(('per_case', 0, 'fixture', key), False, "auth") for key in
                    ('bootstrap_complete', 'verified_tls_ready', 'untrusted_ca_rejected', 'wrapper_sessions_revoked')]
        changes += [(('per_case', 0, 'fixture', 'case_prepared'), 1, "fixture"),
                    (('per_case', 0, 'fixture', 'ca_sha256'), None, "fixture")]
        changes += [((key,), value, "cleanup") for key in ('owned_drain', 'private_data_removed') for value in (None, 1)]
        changes += [(('owned_drain',), False, "cleanup"), (('private_data_removed',), False, "pass")]
        changes += [(('per_case', 0, key), value, "cleanup") for key in ('owned_drain', 'private_data_removed') for value in (None, 1)]
        changes += [(('per_case', 0, 'owned_drain'), False, "cleanup"),
                    (('per_case', 0, 'private_data_removed'), False, "pass")]
        changes += [(('presence', key), False, "presence") for key in ('identities', 'discovery', 'cases')]
        changes += [(('per_case', 0, 'presence', key), 1, "presence") for key in ('fixture', 'libtest', 'witness')]
        for path, value, reason in changes:
            with self.subTest(path=path, mutation=repr(value)):
                self.reject(path, value, reason)

    def test_full_migrations_and_conditional_csrf_rbac_witnesses(self):
        for value in (0, 10001, True, 2.0, None):
            with self.subTest(migrations=value):
                self.reject(('per_case', 0, 'witness', 'migrations_successful'), value, "witness")
        for row, branch, keys in ((2, 'csrf_witness', ('api_keys_csrf_test_key', 'api_keys_nested_key')),
                                  (3, 'rbac_witness', ('users_rbac_operator', 'users_rbac_viewer'))):
            for key in keys:
                for value in (_DELETE, 0, 2, True, 1.0, None):
                    with self.subTest(case=row, witness=key, mutation=repr(value)):
                        self.reject(('per_case', row, 'witness', branch, key), value, "witness")
            self.reject(('per_case', row, 'witness', branch), {'applicable': False}, "witness")
        for value in (1, True, 0.0, 'Admin'):
            with self.subTest(wrong_roles=value):
                self.reject(('per_case', 3, 'witness', 'rbac_witness', 'wrong_roles'), value, "witness")
        for row in (0, 4):
            for branch, value in [('csrf_witness', _witness('rbac_matrix', 'test_csrf_protection')['csrf_witness']),
                                  ('rbac_witness', _witness('rbac_matrix', 'test_rbac_matrix')['rbac_witness'])]:
                with self.subTest(nonapplicable_case=row, branch=branch):
                    self.reject(('per_case', row, 'witness', branch), value, "witness")

    def test_closed_objects_reject_unknown_or_missing_fields(self):
        objects = [((), 'status', 'schema'), (('presence',), 'cases', 'presence'),
            (('identities',), 'web_sha256', 'identities'), (('build_evidence',), 'root_owned_inputs', 'build_evidence'),
            (('discovery',), 'auth_integration', 'inventory'), (('ignored_inventory',), 'rbac_matrix', 'inventory'),
            (('selected', 0), 'id', 'selection'), (('per_case', 0), 'status', 'case'),
            (('per_case', 0, 'presence'), 'fixture', 'presence'), (('per_case', 0, 'result'), 'passed', 'result'),
            (('per_case', 0, 'auth'), 'initial_force_change', 'auth'),
            (('per_case', 0, 'fixture'), 'case_prepared', 'fixture'),
            (('per_case', 0, 'witness'), 'migrations_successful', 'witness'),
            (('per_case', 2, 'witness', 'csrf_witness'), 'api_keys_nested_key', 'witness'),
            (('per_case', 3, 'witness', 'rbac_witness'), 'users_rbac_viewer', 'witness'),
            (('counts',), 'passed', 'counts')]
        for path, key, reason in objects:
            for field, value in ((key, _DELETE), ('public_extra', 'public-synthetic-secret-marker')):
                with self.subTest(object=path, field=field):
                    self.reject((*path, field), value, reason)

    def test_valid_terminal_fail_overtime_and_late_child_zero(self):
        self.baseline()
        for category in ('timeout', 'interrupted', 'cleanup_failed'):
            with self.subTest(terminal_category=category):
                report, expected = _terminal_fail(category), _expected()
                self.accept(report, expected, 2)
                self.assertEqual(report['per_case'][-1]['exit'], 0)
                self.assertEqual(report['per_case'][-1]['result']['passed'], 1)
                self.check(_encode(report), expected, 0, False, 'fail')
        report, expected = _terminal_fail(), _expected()
        report['elapsed_s'] = report['per_case'][-1]['elapsed_s'] = 86400
        self.accept(report, expected, 2)
        for path, reason in [(('elapsed_s',), 'elapsed'), (('per_case', 4, 'elapsed_s'), 'case')]:
            with self.subTest(terminal_cap=path):
                changed = copy.deepcopy(report)
                self.accept(changed, expected, 2)
                _change(changed, path, 86400.1)
                self.check(_encode(changed), expected, 2, False, reason)

    def test_incomplete_fail_uses_null_instead_of_fabricated_observations(self):
        self.baseline()
        report = _pass_report()
        report.update(status='FAIL', phase='inputs', category='input_invalid',
            presence={'identities': False, 'discovery': False, 'cases': False}, identities=None,
            build_evidence=None, discovery=None, ignored_inventory=None, selected=[], per_case=[])
        report['counts'] = {key: 0 for key in report['counts']}
        expected = _expected()
        expected.update(identities=None, inventory=None, ignored_inventory=None)
        self.accept(report, expected, 2)
        for path, value, reason in [(('identities',), 0, 'identities'), (('discovery',), 0, 'inventory'),
                                    (('build_evidence',), {}, 'build_evidence'), (('presence', 'cases'), True, 'presence')]:
            with self.subTest(absent_observation=path):
                changed = copy.deepcopy(report)
                self.accept(changed, expected, 2)
                _change(changed, path, value)
                self.check(_encode(changed), expected, 2, False, reason)
        complete, _unused = self.baseline()
        self.check(_encode(complete), expected, 0, False, 'identities')

    def test_not_run_suffix_and_absent_case_values(self):
        self.baseline()
        for key, value, reason in [('exit', 0, 'not_run'), ('elapsed_s', 0.5, 'not_run'),
                ('openssl_commands', 1, 'not_run'), ('owned_drain', False, 'not_run'),
                ('private_data_removed', False, 'not_run'), ('auth', 0, 'not_run'),
                ('result', 0, 'presence'), ('fixture', 0, 'presence'), ('witness', 0, 'presence')]:
            with self.subTest(absent_case_field=key):
                report, expected = _aborted_report(), _expected()
                self.accept(report, expected, 2)
                report['per_case'][1][key] = value
                self.check(_encode(report), expected, 2, False, reason)
        report, expected = _aborted_report(), _expected()
        self.accept(report, expected, 2)
        report['per_case'][2] = _pass_report()['per_case'][2]
        report['counts'].update(attempted=2, passed=1, not_run=3)
        self.check(_encode(report), expected, 2, False, 'not_run')

    def test_failure_timeout_and_cleanup_observations_stay_consistent(self):
        self.baseline()
        changes = [(('per_case', 4, 'timed_out'), False, 'fail'),
                   (('per_case', 4, 'owned_drain'), None, 'cleanup'),
                   (('per_case', 4, 'private_data_removed'), None, 'cleanup')]
        for path, value, reason in changes:
            with self.subTest(terminal_field=path):
                report, expected = _terminal_fail(), _expected()
                self.accept(report, expected, 2)
                _change(report, path, value)
                self.check(_encode(report), expected, 2, False, reason)
        report, expected = _terminal_fail('unknown_drain'), _expected()
        report.update(owned_drain=False, private_data_removed=False)
        report['per_case'][-1].update(owned_drain=False, private_data_removed=False)
        report['per_case'][-1]['fixture']['removed'] = False
        self.accept(report, expected, 2)
        report['private_data_removed'] = True
        self.check(_encode(report), expected, 2, False, 'cleanup')

    def test_duplicate_keys_are_added_to_complete_valid_json(self):
        for old, new in [(b'"status":"PASS"', b'"status":"PASS","status":"PASS"'),
                         (b'"passed":1', b'"passed":1,"pa\\u0073sed":1')]:
            with self.subTest(duplicate=old):
                report, expected = self.baseline()
                raw = _encode(report)
                self.assertIn(old, raw)
                self.check(raw.replace(old, new, 1), expected, 0, False, 'json')

    def test_raw_json_and_exact_size_boundary(self):
        report, expected = self.baseline()
        raw = _encode(report)
        exact = raw + b' ' * (1048576 - len(raw))
        self.assertEqual(len(exact), 1048576)
        self.check(exact, expected, 0, True, 'ok')
        for name, changed, reason in [('over_cap', exact + b' ', 'raw'), ('empty', b'', 'raw'),
                ('wrong_byte_type', bytearray(raw), 'raw'), ('trailer', raw + b'{}', 'invalid'),
                ('truncated', raw[:-1], 'invalid'), ('bad_UTF8', raw + b'\x80', 'invalid'),
                ('BOM', b'\xef\xbb\xbf' + raw, 'invalid')]:
            with self.subTest(encoding=name):
                self.accept(report, expected)
                self.check(changed, expected, 0, False, reason)

    def test_nonfinite_numbers_depth_and_decoded_text_bounds(self):
        for token, reason in [(b'NaN', 'json'), (b'Infinity', 'json'), (b'-Infinity', 'json'), (b'1e99999', 'bounds')]:
            with self.subTest(numeric_literal=token):
                report, expected = self.baseline()
                raw = _encode(report)
                self.assertEqual(raw.count(b'"elapsed_s":12.5'), 1)
                self.check(raw.replace(b'"elapsed_s":12.5', b'"elapsed_s":' + token), expected, 0, False, reason)
        for value in ('complete\0', 'complete\ud800', 'complete\udfff', 'x' * 513, 10 ** 30):
            with self.subTest(decoded_value=repr(value)):
                self.reject(('phase',), value, 'json' if type(value) is int else 'bounds')
        report, expected = self.baseline()
        nested = 0
        for _ in range(17):
            nested = [nested]
        report['phase'] = nested
        self.check(_encode(report), expected, 0, False, 'bounds')

    def test_private_strings_and_unknown_statuses_never_escape(self):
        for path, value, reason in [(('phase',), 'public-synthetic-secret-marker', 'phase'),
                (('category',), 'public-synthetic-secret-marker', 'category'), (('status',), 'OK', 'schema'),
                (('per_case', 0, 'auth', 'initial_force_change'), 'public-synthetic-secret-marker', 'auth')]:
            with self.subTest(private_or_enum_field=path):
                report, expected = self.baseline()
                _change(report, path, value)
                result = self.check(_encode(report), expected, 0, False, reason)
                self.assertNotIn('public-synthetic-secret-marker', json.dumps(result))


if __name__ == '__main__':
    unittest.main()
