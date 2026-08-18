from tripwire.fixtures import load_fixture, matches_windows_service_rule


def test_windows_service_malicious_fixture_matches():
    event = load_fixture(
        "fixtures/malicious/t1543.003_windows_service.yml"
    )

    assert matches_windows_service_rule(event) is True


def test_windows_service_benign_fixture_does_not_match():
    event = load_fixture(
        "fixtures/benign/t1543.003_windows_service.yml"
    )

    assert matches_windows_service_rule(event) is False