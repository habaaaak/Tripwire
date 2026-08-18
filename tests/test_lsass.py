from tripwire.fixtures import load_fixture, matches_lsass_rule


def test_lsass_malicious_fixture_matches():
    event = load_fixture(
        "fixtures/malicious/t1003.001_lsass_memory.yml"
    )

    assert matches_lsass_rule(event) is True


def test_lsass_benign_fixture_does_not_match():
    event = load_fixture(
        "fixtures/benign/baseline.yml"
    )

    assert matches_lsass_rule(event) is False