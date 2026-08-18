from tripwire.fixtures import load_fixture, matches_ntds_rule


def test_ntds_malicious_fixture_matches():
    event = load_fixture(
        "fixtures/malicious/t1003.003_ntds.yml"
    )

    assert matches_ntds_rule(event) is True


def test_ntds_benign_fixture_does_not_match():
    event = load_fixture(
        "fixtures/benign/t1003.003_ntds.yml"
    )

    assert matches_ntds_rule(event) is False