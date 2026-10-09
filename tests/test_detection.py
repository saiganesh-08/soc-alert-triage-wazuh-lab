
import unittest
from datetime import datetime, timezone

from scripts.analyze_auth_logs import analyze_events


def make_event(username, source_ip, outcome, minute):
    return {
        "timestamp": datetime(2026, 10, 9, 9, minute, tzinfo=timezone.utc),
        "username": username,
        "source_ip": source_ip,
        "event_type": "authentication",
        "outcome": outcome,
    }


class TestAuthenticationDetection(unittest.TestCase):

    def test_detects_repeated_failures(self):
        events = [
            make_event("alex", "192.0.2.10", "failure", 0),
            make_event("alex", "192.0.2.10", "failure", 1),
            make_event("alex", "192.0.2.10", "failure", 2),
        ]
        report = analyze_events(events, threshold=3)
        self.assertEqual(len(report["findings"]), 1)

    def test_no_finding_below_threshold(self):
        events = [
            make_event("alex", "192.0.2.10", "failure", 0),
            make_event("alex", "192.0.2.10", "failure", 1),
        ]
        report = analyze_events(events, threshold=3)
        self.assertEqual(len(report["findings"]), 0)

    def test_different_ips_are_counted_separately(self):
        events = [
            make_event("alex", "192.0.2.10", "failure", 0),
            make_event("alex", "192.0.2.10", "failure", 1),
            make_event("alex", "192.0.2.25", "failure", 2),
        ]
        report = analyze_events(events, threshold=3)
        self.assertEqual(len(report["findings"]), 0)

    def test_successes_do_not_count_as_failures(self):
        events = [
            make_event("alex", "192.0.2.10", "success", 0),
            make_event("alex", "192.0.2.10", "success", 1),
            make_event("alex", "192.0.2.10", "failure", 2),
        ]
        report = analyze_events(events, threshold=3)
        self.assertEqual(len(report["findings"]), 0)


if __name__ == "__main__":
    unittest.main()