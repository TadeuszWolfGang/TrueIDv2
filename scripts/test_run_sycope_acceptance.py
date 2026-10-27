"""Regression contract for the C01 RED acceptance policy seam.

Loads the hyphenated runner module via importlib (no application
imports) and exercises it with synthetic unittest cases only.

Expected RED evidence: exactly one failing outer test,
test_rejects_real_unittest_skip, raising AssertionError containing
C01_RED_SKIP_ACCEPTED.
"""

import importlib.util
import unittest
from pathlib import Path


def _load_policy():
    path = Path(__file__).with_name("run-sycope-acceptance.py")
    spec = importlib.util.spec_from_file_location(
        "run_sycope_acceptance_policy", path
    )
    if spec is None or spec.loader is None:  # pragma: no cover
        raise ImportError("cannot load run-sycope-acceptance.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


policy = _load_policy()
AcceptanceResult = policy.AcceptanceResult
suite_ids = policy.suite_ids
validate_result = policy.validate_result


def _make_passing_case_factory(name="test_passes"):
    class _Inner(unittest.TestCase):
        def test_passes(self):
            self.assertTrue(True)

    _Inner.__name__ = name
    return _Inner


def _make_skip_pair_factory():
    class _SkipPair(unittest.TestCase):
        def test_ok(self):
            self.assertTrue(True)

        @unittest.skip("C01 synthetic skip")
        def test_skipped(self):
            self.fail("should be skipped")

    return _SkipPair


def _make_failing_case_factory():
    class _Failing(unittest.TestCase):
        def test_fails(self):
            self.fail("synthetic failure")

    return _Failing


def _make_error_case_factory():
    class _Erroring(unittest.TestCase):
        def test_errors(self):
            raise RuntimeError("synthetic error")

    return _Erroring


def _make_subtest_factory():
    class _SubTest(unittest.TestCase):
        def test_with_subtest(self):
            for i in (0, 1):
                with self.subTest(i=i):
                    if i == 1:
                        self.fail("failing subtest")

    return _SubTest


def _make_expected_failure_factory():
    class _ExpectedFailure(unittest.TestCase):
        @unittest.expectedFailure
        def test_expected_failure(self):
            self.fail("expected")

    return _ExpectedFailure


def _make_unexpected_success_factory():
    class _UnexpectedSuccess(unittest.TestCase):
        @unittest.expectedFailure
        def test_unexpected_success(self):
            pass

    return _UnexpectedSuccess


def _make_class_fixture_error_factory():
    class _ClassFixtureError(unittest.TestCase):
        @classmethod
        def setUpClass(cls):
            raise RuntimeError("synthetic setUpClass error")

        def test_never_runs(self):
            pass

    return _ClassFixtureError


def _run_case(case_cls):
    suite = unittest.TestSuite()
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(case_cls))
    suite._c01_ids = suite_ids(suite)
    result = AcceptanceResult()
    suite.run(result)
    return suite, result


def _ids_of(suite):
    # Snapshot precedes standard TestSuite leaf consumption.
    return suite._c01_ids


class AcceptancePolicyTests(unittest.TestCase):
    def test_accepts_complete_pass(self):
        case_cls = _make_passing_case_factory()
        suite, result = _run_case(case_cls)
        ids = _ids_of(suite)
        self.assertEqual(result.testsRun, 1)
        self.assertTrue(result.wasSuccessful())
        self.assertEqual(
            result.terminal_events, [("PASS", ids[0])]
        )
        self.assertTrue(
            validate_result(
                result,
                expected_ids=ids,
                discovered_ids=ids,
                selected_ids=ids,
            )
        )

    def test_rejects_real_unittest_skip(self):
        case_cls = _make_skip_pair_factory()
        suite, result = _run_case(case_cls)
        ids = _ids_of(suite)
        self.assertEqual(result.testsRun, 2)
        self.assertEqual(len(result.skipped), 1)
        self.assertTrue(result.wasSuccessful())
        self.assertEqual(len(result.terminal_events), 2)
        self.assertEqual(sorted(event_id for _, event_id in result.terminal_events), sorted(ids))
        statuses = sorted(status for status, _ in result.terminal_events)
        self.assertEqual(statuses, ["PASS", "SKIP"])
        self.assertEqual(
            sorted(result.started_ids), sorted(ids)
        )
        self.assertEqual(
            sorted(result.stopped_ids), sorted(ids)
        )
        self.assertFalse(
            validate_result(
                result,
                expected_ids=ids,
                discovered_ids=ids,
                selected_ids=ids,
            ),
            "C01_RED_SKIP_ACCEPTED",
        )

    def test_rejects_invalid_inventory(self):
        suite, result = _run_case(_make_passing_case_factory())
        ids = _ids_of(suite)
        invalid = [(), (ids[0], ids[0]), ("",), (None,), (1,),
                   (ids[0], "unknown-id"), ("unknown-id",)]
        for index in range(3):
            for value in invalid:
                with self.subTest(inventory=index, value=value):
                    inventories = [ids, ids, ids]
                    inventories[index] = value
                    self.assertFalse(validate_result(
                        result, expected_ids=inventories[0],
                        discovered_ids=inventories[1], selected_ids=inventories[2]))

    def test_rejects_incomplete_or_duplicate_events(self):
        suite, _ = _run_case(_make_passing_case_factory())
        ids = _ids_of(suite)
        mutations = []
        for attribute in ("started_ids", "stopped_ids"):
            for value in ([], [ids[0], ids[0]], ["unknown-id"], [None], [""], [1]):
                mutations.append((attribute, value))
        for value in ([], [("PASS", ids[0]), ("PASS", ids[0])],
                      [("PASS", "unknown-id")], [("PASS", None)],
                      [("PASS", "")], [("PASS", 1)], [("PASS",)], [None]):
            mutations.append(("terminal_events", value))
        for status in ("FAIL", "ERROR", "EXPECTED_FAILURE", "UNEXPECTED_SUCCESS", "UNKNOWN", [], None):
            mutations.append(("terminal_events", [(status, ids[0])]))
        for attribute, value in mutations:
            with self.subTest(attribute=attribute, value=value):
                _, changed = _run_case(_make_passing_case_factory())
                setattr(changed, attribute, value)
                self.assertFalse(validate_result(
                    changed, expected_ids=ids, discovered_ids=ids, selected_ids=ids))

    def test_rejects_tests_run_drift(self):
        suite, result = _run_case(_make_passing_case_factory())
        ids = _ids_of(suite)
        for count in (-1, 0, 2, True, "1"):
            with self.subTest(count=count):
                result.testsRun = count
                self.assertFalse(validate_result(
                    result, expected_ids=ids, discovered_ids=ids, selected_ids=ids))

    def test_rejects_failure_or_error(self):
        fail_suite, fail_result = _run_case(_make_failing_case_factory())
        fail_ids = _ids_of(fail_suite)
        self.assertFalse(
            validate_result(
                fail_result,
                expected_ids=fail_ids,
                discovered_ids=fail_ids,
                selected_ids=fail_ids,
            )
        )

        error_suite, error_result = _run_case(_make_error_case_factory())
        error_ids = _ids_of(error_suite)
        self.assertFalse(
            validate_result(
                error_result,
                expected_ids=error_ids,
                discovered_ids=error_ids,
                selected_ids=error_ids,
            )
        )

    def test_rejects_failing_subtest(self):
        suite, result = _run_case(_make_subtest_factory())
        ids = _ids_of(suite)
        self.assertGreater(result.failing_subtests, 0)
        self.assertFalse(
            validate_result(
                result,
                expected_ids=ids,
                discovered_ids=ids,
                selected_ids=ids,
            )
        )

    def test_rejects_expected_failure_or_unexpected_success(self):
        ef_suite, ef_result = _run_case(
            _make_expected_failure_factory()
        )
        ef_ids = _ids_of(ef_suite)
        self.assertFalse(
            validate_result(
                ef_result,
                expected_ids=ef_ids,
                discovered_ids=ef_ids,
                selected_ids=ef_ids,
            )
        )

        us_suite, us_result = _run_case(
            _make_unexpected_success_factory()
        )
        us_ids = _ids_of(us_suite)
        self.assertFalse(
            validate_result(
                us_result,
                expected_ids=us_ids,
                discovered_ids=us_ids,
                selected_ids=us_ids,
            )
        )

    def test_rejects_loader_or_class_fixture_error(self):
        suite, result = _run_case(_make_passing_case_factory())
        ids = _ids_of(suite)
        self.assertFalse(
            validate_result(
                result,
                expected_ids=ids,
                discovered_ids=ids,
                selected_ids=ids,
                loader_errors=("synthetic loader error",),
            )
        )

        fixture_suite, fixture_result = _run_case(
            _make_class_fixture_error_factory()
        )
        fixture_ids = _ids_of(fixture_suite)
        self.assertFalse(
            validate_result(
                fixture_result,
                expected_ids=fixture_ids,
                discovered_ids=fixture_ids,
                selected_ids=fixture_ids,
            )
        )

    def test_rejects_timeout_cleanup_or_abort(self):
        suite, result = _run_case(_make_passing_case_factory())
        ids = _ids_of(suite)
        self.assertFalse(
            validate_result(
                result,
                expected_ids=ids,
                discovered_ids=ids,
                selected_ids=ids,
                timed_out=True,
            )
        )
        self.assertFalse(
            validate_result(
                result,
                expected_ids=ids,
                discovered_ids=ids,
                selected_ids=ids,
                cleanup_failed=True,
            )
        )

        _, aborted = _run_case(_make_passing_case_factory())
        aborted.stop()
        self.assertTrue(aborted.shouldStop)
        self.assertFalse(
            validate_result(
                aborted,
                expected_ids=ids,
                discovered_ids=ids,
                selected_ids=ids,
            )
        )

    def test_suite_ids_is_recursive_and_non_consuming(self):
        case_cls = _make_passing_case_factory()
        inner = unittest.TestSuite()
        inner.addTests(
            unittest.defaultTestLoader.loadTestsFromTestCase(case_cls)
        )
        outer = unittest.TestSuite()
        outer.addTest(inner)
        before = list(inner._tests)
        ids = suite_ids(outer)
        self.assertEqual(len(ids), 1)
        self.assertEqual(ids, (before[0].id(),))
        after = list(inner._tests)
        self.assertEqual(before, after)
        with self.assertRaises(ValueError):
            suite_ids("not-a-suite")  # type: ignore[arg-type]
        duplicate = unittest.TestSuite([before[0], before[0]])
        self.assertEqual(suite_ids(duplicate), (before[0].id(), before[0].id()))
        unsupported = unittest.TestSuite()
        unsupported._tests.append(object())
        with self.assertRaises(ValueError):
            suite_ids(unsupported)


if __name__ == "__main__":
    unittest.main()
