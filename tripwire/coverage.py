from pathlib import Path
import yaml

from tripwire.fixtures import (
    load_fixture,
    matches_lsass_rule,
    matches_scheduled_task_rule,
    matches_powershell_rule,
    matches_windows_service_rule,
    matches_event_log_clearing_rule,
    matches_ntds_rule,
)


RULE_MATCHERS = {
    "T1003.001": matches_lsass_rule,
    "T1053.005": matches_scheduled_task_rule,
    "T1059.001": matches_powershell_rule,
    "T1543.003": matches_windows_service_rule,
    "T1685.005": matches_event_log_clearing_rule,
    "T1003.003": matches_ntds_rule, 
}


def get_rule_techniques(rules_directory="rules"):
    """Return ATT&CK techniques mapped to Sigma rules."""

    coverage = {}

    for rule_path in Path(rules_directory).rglob("*.yml"):
        with rule_path.open("r", encoding="utf-8") as file:
            rule = yaml.safe_load(file)

        techniques = []

        for tag in rule.get("tags", []):
            if tag.startswith("attack.t"):
                techniques.append(tag.replace("attack.", "").upper())

        for technique in techniques:
            coverage.setdefault(technique, []).append(str(rule_path))

    return coverage


def validate_technique(technique):
    """Return True when malicious and benign fixtures validate."""

    matcher = RULE_MATCHERS.get(technique)

    fixture_map = {
        "T1003.001": "t1003.001_lsass_memory.yml",
        "T1053.005": "t1053.005_scheduled_task.yml",
        "T1059.001": "t1059.001_powershell.yml",
        "T1543.003": "t1543.003_windows_service.yml",
        "T1685.005": "t1685.005_event_log_clearing.yml",
        "T1003.003": "t1003.003_ntds.yml",
    }

    if matcher is None or technique not in fixture_map:
        return False

    fixture_name = fixture_map[technique]

    malicious = load_fixture(
        f"fixtures/malicious/{fixture_name}"
    )

    if technique == "T1003.001":
        benign_path = "fixtures/benign/baseline.yml"
    else:
        benign_path = f"fixtures/benign/{fixture_name}"

    benign = load_fixture(benign_path)

    return (
        matcher(malicious) is True
        and matcher(benign) is False
    )

def get_proven_coverage():
    """Return ATT&CK techniques that pass validation."""

    techniques = get_rule_techniques()
    proven = []

    for technique in techniques:
        if validate_technique(technique):
            proven.append(technique)

    return sorted(proven)

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


def test_all_current_techniques_are_proven():
    assert validate_technique("T1003.001") is True
    assert validate_technique("T1053.005") is True
    assert validate_technique("T1059.001") is True
    assert validate_technique("T1543.003") is True


def test_proven_coverage_contains_current_techniques():
    proven = get_proven_coverage()

    assert proven == [
        "T1003.001",
        "T1053.005",
        "T1059.001",
        "T1543.003",
    ]
