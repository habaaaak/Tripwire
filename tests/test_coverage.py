from tripwire.coverage import (
    get_rule_techniques,
    validate_technique,
    get_proven_coverage,
)


def test_all_rules_have_attack_techniques():
    coverage = get_rule_techniques()

    assert "T1003.001" in coverage
    assert "T1053.005" in coverage
    assert "T1059.001" in coverage
    assert "T1543.003" in coverage
    assert "T1685.005" in coverage


def test_all_current_techniques_are_proven():
    assert validate_technique("T1003.001") is True
    assert validate_technique("T1053.005") is True
    assert validate_technique("T1059.001") is True
    assert validate_technique("T1543.003") is True
    assert validate_technique("T1685.005") is True


def test_proven_coverage_contains_current_techniques():
    proven = get_proven_coverage()

    assert proven == [
        "T1003.001",
        "T1053.005",
        "T1059.001",
        "T1543.003",
        "T1685.005",
    ]
