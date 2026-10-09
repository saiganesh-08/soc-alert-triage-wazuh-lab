
# SOC Alert Triage & Security Monitoring Lab

A hands-on cybersecurity project demonstrating Python-based authentication log analysis, repeated failed-login detection, input validation, unit testing, and SOC alert triage documentation.

> **Project type:** Personal learning lab  
> **Data:** Synthetic authentication events  
> **Purpose:** Demonstrate entry-level Security Operations Center (SOC) analysis skills.

## Project Objectives

- Analyze structured authentication events using Python.
- Detect repeated failed logins by username and source IP.
- Validate event fields, timestamps, outcomes, and JSON input.
- Generate a readable security analysis report.
- Test detection behavior and invalid-input handling.
- Document investigation steps, evidence, uncertainty, and escalation recommendations.

## Project Structure

```text
soc-alert-triage-wazuh-lab/
├── README.md
├── sample-data/
│   └── sample_auth_events.json
├── scripts/
│   └── analyze_auth_logs.py
├── tests/
│   ├── test_analyze_auth_logs.py
│   └── test_detection.py
└── docs/
    ├── alert-triage-playbook.md
    └── incident-report-template.md
```

## Requirements

- Python 3.10 or later recommended
- No third-party Python packages required for the core script or unit tests

## Run the Analysis

From the repository root, run:

```bash
python scripts/analyze_auth_logs.py
```

The script reads the sample authentication events and reports the number of accepted events, successful logins, failed logins, and detected repeated-failure patterns.

### Change the Detection Threshold

The default threshold is three failed attempts. To use a threshold of four:

```bash
python scripts/analyze_auth_logs.py --threshold 4
```

### Specify an Input File

```bash
python scripts/analyze_auth_logs.py --input sample-data/sample_auth_events.json
```

## Run the Tests

Run the complete test suite with:

```bash
python -m unittest discover -s tests -v
```

The tests cover authentication detection behavior and input validation. Run the command locally and review the results before reporting the test count or status.

## Detection Logic

The lab groups authentication events by username and source IP address. It counts failed attempts for each group and generates a finding when the configured threshold is reached.

The report includes:

- Username and source IP
- Failed-attempt count
- First and last observed failure timestamps
- Successful login count for the same username and source IP
- Initial lab severity and recommended analyst review

A detection is an investigative lead, not proof of compromise. A successful login after repeated failures requires additional context and does not independently establish malicious activity.

## SOC Triage Workflow

1. Review the generated alert.
2. Validate event fields and timestamps.
3. Examine the authentication timeline.
4. Identify relevant evidence and missing context.
5. Assess possible benign explanations.
6. Decide whether further investigation or escalation is warranted.
7. Document observations, uncertainties, and next steps.

See the `docs/` directory for the alert triage playbook and incident report template.

## Skills Demonstrated

- Python scripting and JSON processing
- Authentication log analysis
- Threshold-based detection logic
- Input validation and error handling
- Unit testing with `unittest`
- Security alert triage and evidence documentation
- Incident-report writing and escalation reasoning

## Limitations

- The included authentication events are synthetic.
- The detection is a simple threshold-based example, not a production-grade SIEM rule.
- The project does not independently confirm account compromise.
- Results depend on the input data and configured threshold.
- Production use would require representative telemetry, tuning, access controls, and approved response procedures.

## Future Improvements

- Add time-window-based detection.
- Add tests for malformed event structures and additional edge cases.
- Integrate sample alerts from a local Wazuh lab.
- Add structured output for further investigation and reporting.
- Evaluate detection quality against labeled test data.

## Disclaimer

This repository is a personal training project. It does not represent a production SOC deployment or investigation of a real security incident.