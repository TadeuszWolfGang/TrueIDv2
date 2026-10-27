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
