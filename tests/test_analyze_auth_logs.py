
import json
import tempfile
import unittest
from pathlib import Path

from scripts.analyze_auth_logs import load_events, analyze_events


class TestInputValidation(unittest.TestCase):

    def load_from_text(self, content):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.json"
            path.write_text(content, encoding="utf-8")
            return load_events(path)

    def test_valid_event_is_accepted(self):
        content = json.dumps([
            {
                "timestamp": "2026-10-09T09:00:00Z",
                "username": "alex",
                "source_ip": "192.0.2.10",
                "event_type": "authentication",
                "outcome": "failure"
            }
        ])

        events, rejected = self.load_from_text(content)

        self.assertEqual(len(events), 1)
        self.assertEqual(rejected, 0)

    def test_missing_field_is_rejected(self):
        content = json.dumps([
            {
                "timestamp": "2026-10-09T09:00:00Z",
                "username": "alex",
                "source_ip": "192.0.2.10",
                "event_type": "authentication"
            }
        ])

        events, rejected = self.load_from_text(content)

        self.assertEqual(len(events), 0)
        self.assertEqual(rejected, 1)

    def test_invalid_timestamp_is_rejected(self):
        content = json.dumps([
            {
                "timestamp": "not-a-timestamp",
                "username": "alex",
                "source_ip": "192.0.2.10",
                "event_type": "authentication",
                "outcome": "failure"
            }
        ])

        events, rejected = self.load_from_text(content)

        self.assertEqual(len(events), 0)
        self.assertEqual(rejected, 1)

    def test_invalid_json_raises_error(self):
        with self.assertRaises(ValueError):
            self.load_from_text("{invalid json")

    def test_non_list_json_raises_error(self):
        with self.assertRaises(ValueError):
            self.load_from_text('{"username": "alex"}')

    def test_threshold_must_be_positive(self):
        with self.assertRaises(ValueError):
            analyze_events([], threshold=0)


if __name__ == "__main__":
    unittest.main()