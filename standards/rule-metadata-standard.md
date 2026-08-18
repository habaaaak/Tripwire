# Tripwire Rule Metadata Standard

## Purpose

This standard defines the required metadata for every detection rule in Tripwire.

Every rule must contain enough information to identify what it detects, what ATT&CK technique it represents, what telemetry it depends on, how it should be tested, and whether it has been validated.

## Required Fields

### Rule ID
A stable unique identifier for the rule.

Format:
`TRIPWIRE-<TACTIC>-<NUMBER>`

Example:
`TRIPWIRE-CRED-001`

### Title
A short description of what the rule detects.

### ATT&CK Technique
The MITRE ATT&CK technique or sub-technique ID.

Example:
`T1003.001`

### Tactic
The ATT&CK tactic associated with the technique.

Example:
`Credential Access`

### Data Source
The telemetry required by the rule.

Example:
`Sysmon Event ID 10 - ProcessAccess`

### Severity
The rule's severity.

Allowed values:
- low
- medium
- high
- critical

### Detection
The Sigma detection logic.

### False Positives
Known legitimate activity that could trigger the rule.

### True-Positive Fixture
Reference to the synthetic fixture that the rule must detect.

### Benign Fixture
Reference to the benign fixture/baseline that the rule must not detect.

### Validation Status
The current validation state of the rule.

Allowed values:
- untested
- passed
- failed

## Validation Requirements

A rule is considered validated only when:

1. It fires on its true-positive fixture.
2. It does not fire on the benign baseline.
3. Its ATT&CK technique mapping is present.
4. Its Sigma syntax is valid.

Rules that have not passed validation must not be counted as proven coverage.

## Rule Standard Example

```yaml
id: TRIPWIRE-CRED-001
title: Suspicious LSASS Process Access
attack:
  tactic: Credential Access
  technique: T1003.001
data_source:
  product: Sysmon
  service: Sysmon
  event_id: 10
severity: high
false_positives:
  - Legitimate security software accessing LSASS
true_positive_fixture: fixtures/malicious/TRIPWIRE-CRED-001.yml
benign_fixture: fixtures/benign/baseline.yml
validation_status: untested