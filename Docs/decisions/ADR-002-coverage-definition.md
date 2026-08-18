# ADR-002: Detection Coverage Definition

## Status

Accepted

## Context

Tripwire needs to report honest MITRE ATT&CK coverage.

A detection rule existing in the repository does not prove that the technique is detected. A rule must successfully identify its malicious test fixture and remain silent on the benign baseline before it can count as validated coverage.

## Decision

Tripwire will count an ATT&CK technique as proven coverage only when:

1. The Sigma rule maps to a valid MITRE ATT&CK technique ID.
2. The rule passes Sigma validation.
3. A malicious fixture successfully triggers the detection.
4. A benign fixture does not trigger the detection.
5. The validation tests pass.

Rules that exist but have not passed these requirements will not count toward proven coverage.

## Coverage States

### Proven

The rule has passed all validation requirements and counts toward ATT&CK coverage.

### Untested

The rule exists and is mapped to ATT&CK but has not completed validation.

Untested rules do not count toward coverage.

### Failed

The rule or its validation failed.

Failed rules do not count toward coverage.

## Consequences

This approach prevents Tripwire from overstating its detection capabilities.

Coverage reports will distinguish between:

- Proven coverage
- Untested rules
- Failed rules

Only proven coverage will be included in the validated ATT&CK coverage calculation.