
import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path


DEFAULT_THRESHOLD = 3
VALID_OUTCOMES = {"success", "failure"}
REQUIRED_FIELDS = {
    "timestamp",
    "username",
    "source_ip",
    "event_type",
    "outcome",
}


def parse_timestamp(value):
    if isinstance(value, datetime):
        timestamp = value
    elif isinstance(value, str):
        timestamp = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )
    else:
        raise ValueError("Timestamp must be a string or datetime.")

    if timestamp.tzinfo is None:
        raise ValueError("Timestamp must include a timezone.")

    return timestamp


def load_events(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            data = json.load(file)
    except FileNotFoundError as exc:
        raise ValueError(f"Input file not found: {file_path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON: {exc}") from exc
    except OSError as exc:
        raise ValueError(f"Unable to read input file: {exc}") from exc

    if not isinstance(data, list):
        raise ValueError("Input must be a JSON list of event objects.")

    valid_events = []
    rejected = 0

    for index, event in enumerate(data, start=1):
        if not isinstance(event, dict):
            print(f"[INVALID] Event {index}: expected a JSON object.")
            rejected += 1
            continue

        missing = REQUIRED_FIELDS - event.keys()
        if missing:
            print(
                f"[INVALID] Event {index}: missing fields "
                f"{', '.join(sorted(missing))}."
            )
            rejected += 1
            continue

        if not all(
            isinstance(event[field], str) and event[field].strip()
            for field in REQUIRED_FIELDS
        ):
            print(
                f"[INVALID] Event {index}: required fields "
                "must be non-empty strings."
            )
            rejected += 1
            continue

        try:
            timestamp = parse_timestamp(event["timestamp"])
        except ValueError:
            print(f"[INVALID] Event {index}: invalid or timezone-free timestamp.")
            rejected += 1
            continue

        if event["event_type"].lower() != "authentication":
            print(f"[INVALID] Event {index}: unsupported event type.")
            rejected += 1
            continue

        outcome = event["outcome"].lower()
        if outcome not in VALID_OUTCOMES:
            print(f"[INVALID] Event {index}: unsupported outcome.")
            rejected += 1
            continue

        valid_events.append(
            {
                "timestamp": timestamp,
                "username": event["username"].strip(),
                "source_ip": event["source_ip"].strip(),
                "event_type": "authentication",
                "outcome": outcome,
            }
        )

    return valid_events, rejected


def analyze_events(events, threshold=DEFAULT_THRESHOLD):
    if threshold < 1:
        raise ValueError("Threshold must be at least 1.")

    failures = Counter()
    successes = Counter()
    failure_details = defaultdict(list)

    for event in events:
        key = (event["username"], event["source_ip"])
        timestamp = parse_timestamp(
            event.get("_timestamp", event["timestamp"])
        )

        if event["outcome"].lower() == "failure":
            failures[key] += 1
            failure_details[key].append(timestamp)
        elif event["outcome"].lower() == "success":
            successes[key] += 1

    findings = []

    for (username, source_ip), count in failures.items():
        if count >= threshold:
            timestamps = sorted(failure_details[(username, source_ip)])

            findings.append(
                {
                    "username": username,
                    "source_ip": source_ip,
                    "failed_attempts": count,
                    "first_seen": timestamps[0].isoformat(),
                    "last_seen": timestamps[-1].isoformat(),
                    "successful_logins": successes[(username, source_ip)],
                    "severity": "MEDIUM",
                }
            )

    findings.sort(
        key=lambda finding: finding["failed_attempts"],
        reverse=True,
    )

    return {
        "total_events": len(events),
        "successful_events": sum(successes.values()),
        "failed_events": sum(failures.values()),
        "findings": findings,
    }


def print_report(report, rejected, threshold):
    print("\n" + "=" * 60)
    print("SOC AUTHENTICATION LOG ANALYSIS REPORT")
    print("=" * 60)
    print(f"Events accepted:       {report['total_events']}")
    print(f"Events rejected:       {rejected}")
    print(f"Successful logins:     {report['successful_events']}")
    print(f"Failed logins:         {report['failed_events']}")
    print(f"Failure threshold:     {threshold}")

    findings = report["findings"]

    if not findings:
        print("\nNo repeated-failure patterns met the configured threshold.")
    else:
        print(f"\nFindings: {len(findings)}")

        for number, finding in enumerate(findings, start=1):
            print(f"\n[ALERT {number}] Repeated authentication failures")
            print(f"  Severity:              {finding['severity']}")
            print(f"  Username:              {finding['username']}")
            print(f"  Source IP:              {finding['source_ip']}")
            print(f"  Failed attempts:        {finding['failed_attempts']}")
            print(f"  Successful logins:      {finding['successful_logins']}")
            print(f"  First observed:         {finding['first_seen']}")
            print(f"  Last observed:          {finding['last_seen']}")
            print("  Recommended next steps:")
            print("    - Review account and source IP context.")
            print("    - Check surrounding authentication events.")
            print("    - Verify whether the activity is expected.")
            print("    - Escalate according to the approved playbook if suspicious.")
            print("  Assessment: Review required; compromise is not confirmed.")

    print("\nNote: This is a basic threshold-based detection.")
    print("Findings require analyst review before response.")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="Analyze authentication logs for repeated failed logins."
    )
    parser.add_argument(
        "--input",
        default="sample-data/sample_auth_events.json",
        help="Path to the JSON authentication event file.",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=DEFAULT_THRESHOLD,
        help="Minimum failed attempts for a finding (default: 3).",
    )

    args = parser.parse_args()

    if args.threshold < 1:
        parser.error("--threshold must be at least 1.")

    try:
        events, rejected = load_events(Path(args.input))
        report = analyze_events(events, args.threshold)
    except ValueError as exc:
        parser.error(str(exc))

    print_report(report, rejected, args.threshold)


if __name__ == "__main__":
    main()