# ADR-001: Detection Rule Authoring Standard

## Status

Accepted

## Context

Tripwire needs a consistent way to author, validate, and maintain Sigma
detection rules.

Rules should map clearly to MITRE ATT&CK techniques and use consistent
metadata, log sources, detection logic, and testing practices.

## Decision

Tripwire detection rules will:

- Use Sigma YAML format.
- Include the relevant MITRE ATT&CK technique ID.
- Use the appropriate log source for the telemetry being detected.
- Include a clear detection name and description.
- Include severity and other required metadata.
- Be paired with malicious and benign test fixtures.
- Be validated with Sigma CLI before being merged.
- Be tested through the Tripwire validation harness.
- Include research notes explaining the detection hypothesis and
  false-positive considerations.

## Validation Requirements

A rule is considered ready for merge when:

1. Sigma validation passes with no errors.
2. A malicious fixture triggers the detection.
3. A benign fixture does not trigger the detection.
4. The rule maps to a valid MITRE ATT&CK technique.
5. False-positive considerations have been documented.

## Consequences

This standard makes Tripwire rules more consistent and easier to review,
test, and maintain.

It also ensures that detection coverage is based on validated rules rather
than rules that only exist on paper.