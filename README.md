# SOC Alert Triage & Security Monitoring Lab

## Overview

This project demonstrates a hands-on Security Operations Center (SOC) learning lab focused on security event analysis, authentication monitoring, alert triage, and incident documentation.

The lab is designed to practice the initial investigation workflow used by security analysts when reviewing suspicious activity.

## Objectives

- Analyze authentication events and identify repeated failed login attempts.
- Review event timestamps, source IP addresses, usernames, and outcomes.
- Distinguish observed facts from assumptions during an investigation.
- Document alert severity, investigation steps, findings, and recommended actions.
- Practice structured escalation and evidence handling.
- Explore SIEM concepts and Windows endpoint monitoring with Wazuh.

## Tools and Technologies

- Wazuh SIEM
- Python
- JSON security event data
- Git and GitHub
- Windows and Linux security fundamentals
- TCP/IP and authentication concepts

## Project Structure

```text
soc-alert-triage-wazuh-lab/
├── README.md
├── sample-data/
│   └── sample_auth_events.json
├── scripts/
│   └── analyze_auth_logs.py
├── docs/
│   ├── alert-triage-playbook.md
│   └── incident-report-template.md
└── tests/
    └── test_analyze_auth_logs.py
```

## Planned Investigation Workflow

1. Collect sample authentication events.
2. Parse and validate the event records.
3. Identify repeated failed authentication attempts.
4. Review relevant context and establish an event timeline.
5. Document findings, uncertainties, and recommended next steps.
6. Prepare an investigation report for review or escalation.

## Responsible Testing

This repository uses synthetic security events for repeatable testing. It does not contain real user credentials, production logs, or private organizational data.

Any response or containment action in a real environment must follow approved procedures and authorization requirements.

## Project Status

Initial project setup. Detection logic, test results, investigation playbooks, and Wazuh evidence will be added and documented as each component is implemented and validated.
