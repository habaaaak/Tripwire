from tripwire.fixtures import (
    load_fixture,
    matches_event_log_clearing_rule,
)


def test_event_log_clearing_malicious_fixture_matches():
    event = load_fixture(
        "fixtures/malicious/t1685.005_event_log_clearing.yml"
    )

    assert matches_event_log_clearing_rule(event) is True


def test_event_log_clearing_benign_fixture_does_not_match():
    event = load_fixture(
        "fixtures/benign/t1685.005_event_log_clearing.yml"
    )

    assert matches_event_log_clearing_rule(event) is False