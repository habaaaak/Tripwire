from tripwire.fixtures import load_fixture, matches_lsass_rule


def validate_lsass():
    """Validate the LSASS rule against malicious and benign fixtures."""

    malicious = load_fixture(
        "fixtures/malicious/t1003.001_lsass_memory.yml"
    )

    benign = load_fixture(
        "fixtures/benign/baseline.yml"
    )

    malicious_match = matches_lsass_rule(malicious)
    benign_match = matches_lsass_rule(benign)

    malicious_pass = malicious_match is True
    benign_pass = benign_match is False

    print("LSASS Detection Validation")
    print("--------------------------")

    print(
        f"Malicious fixture: "
        f"{'PASS' if malicious_pass else 'FAIL'}"
    )

    print(
        f"Benign fixture:    "
        f"{'PASS' if benign_pass else 'FAIL'}"
    )

    return malicious_pass and benign_pass