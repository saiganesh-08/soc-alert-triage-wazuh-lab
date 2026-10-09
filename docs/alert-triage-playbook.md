
# SOC Alert Triage Playbook

## 1. Purpose

This playbook defines a repeatable first-line workflow for reviewing suspicious authentication activity in a security monitoring environment.

It is intended for learning and lab use. Real-world investigations must follow the organization's approved procedures and escalation requirements.

## 2. Alert Scenario

**Detection:** Repeated authentication failures from the same source IP for the same username.

**Example threshold:** Three or more failed attempts.

**Initial severity:** Medium for this lab rule. Severity must be adjusted according to organizational policy, asset criticality, threat context, and the detection's validated risk.

**Important:** Repeated failures alone do not confirm malicious activity or account compromise.

## 3. Initial Triage

When an alert is generated:

1. Record the alert identifier, detection name, and observation time.
2. Identify the affected username and source IP address.
3. Confirm the number of failed and successful authentication events.
4. Verify that timestamps and event fields are valid.
5. Identify the data source and the detection rule that produced the alert.
6. Record any missing information or limitations.

## 4. Evidence Collection

Collect the available information needed to understand the activity:

- Event timestamps and timezone.
- Username or account identifier.
- Source IP address.
- Authentication outcome.
- Number and frequency of failed attempts.
- Any successful login near the failed attempts.
- Relevant endpoint, identity, or authentication logs, when available.
- Detection rule and severity.
- Relevant asset or account context, if authorized.

Record the source of each observation. Do not invent missing evidence.

## 5. Investigation Questions

Review the following questions:

1. Are the failed attempts concentrated on one account or spread across several accounts?
2. Do the events originate from the same source IP?
3. Was there a successful login after repeated failures?
4. Is the source associated with expected user or application activity?
5. Are there unusual locations, devices, or login times in the available evidence?
6. Are there related alerts or events that may change the risk assessment?
7. Is there enough evidence to classify the alert, or is further investigation required?

A successful login after repeated failures is a useful investigative clue, not proof of account compromise.

## 6. False-Positive Review

Potential benign explanations may include:

- A user entering an incorrect password repeatedly.
- A service or application using an outdated password.
- An approved automated process retrying authentication.
- A test environment generating expected failures.

Validate explanations against available evidence. Do not close an alert solely because a benign explanation is possible.

## 7. Triage Decision

Choose one of the following outcomes based on the available evidence:

### Close as Benign

Use only when the evidence and applicable closure criteria support a benign explanation. Record the justification.

### Continue Investigation

Use when important context is missing or the activity remains unexplained. Identify the additional evidence required.

### Escalate

Escalate when evidence or approved criteria indicate potentially malicious activity, account compromise, or risk beyond the analyst's authority.

Include the facts, timeline, affected entities, evidence sources, uncertainties, and recommended next steps.

## 8. Response and Authorization

- Follow approved incident-response procedures.
- Preserve relevant evidence according to policy.
- Do not disable accounts, block IP addresses, isolate endpoints, or make other disruptive changes without the required authorization.
- Record actions taken, approvals, timestamps, and handoffs.
- Protect sensitive logs and personal information.

## 9. Incident Documentation Template

For every investigation, record:

- Alert ID:
- Detection name:
- Date and time:
- Affected account or endpoint:
- Source IP:
- Evidence reviewed:
- Event timeline:
- Confirmed observations:
- Unknowns and limitations:
- False-positive assessment:
- Triage decision:
- Escalation recipient:
- Recommended next steps:
- Analyst notes:

## 10. Lab Limitations

This playbook describes a training workflow using synthetic authentication data. It is not a validated production detection or an organization's official response policy.

Production use requires testing against representative telemetry, approved severity criteria, access controls, and documented response procedures.