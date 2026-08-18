from tripwire.fixtures import load_fixture, matches_powershell_rule


def test_powershell_malicious_fixture_matches():
    event = load_fixture(
        "fixtures/malicious/t1059.001_powershell.yml"
    )

    assert matches_powershell_rule(event) is True


def test_powershell_benign_fixture_does_not_match():
    event = load_fixture(
        "fixtures/benign/t1059.001_powershell.yml"
    )

    assert matches_powershell_rule(event) is False