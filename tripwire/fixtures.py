from pathlib import Path
import yaml


def load_fixture(path):
    """Load a YAML fixture and return it as a Python dictionary."""
    fixture_path = Path(path)

    with fixture_path.open("r", encoding="utf-8") as file:
        return yaml.safe_load(file)

def matches_lsass_rule(event):
    """Return True when an event matches the LSASS detection conditions."""
    return (
        event.get("EventID") == 10
        and event.get("TargetImage", "").lower().endswith(r"\lsass.exe")
        and event.get("GrantedAccess") in {
            "0x1010",
            "0x1038",
            "0x1438",
            "0x143a",
            "0x1fffff",
        }
    )    

def matches_scheduled_task_rule(event):
    """Return True for suspicious scheduled task creation."""

    if event.get("EventID") != 4698:
        return False

    task_content = event.get("TaskContent", "")

    suspicious_indicators = [
        r"C:\Users\Public\\",
        r"update.exe",
    ]

    return any(
        indicator.lower() in task_content.lower()
        for indicator in suspicious_indicators
    )

def matches_powershell_rule(event):
    """Return True for suspicious PowerShell execution."""

    if event.get("EventID") != 1:
        return False

    image = event.get("Image", "").lower()
    command_line = event.get("CommandLine", "").lower()

    if not (image.endswith("\\powershell.exe") or image.endswith("\\pwsh.exe")):
        return False

    suspicious_indicators = [
        "-enc",
        "-encodedcommand",
        "-nop",
        "-noprofile",
        "-hidden",
        "-windowstyle hidden",
    ]

    return any(
        indicator in command_line
        for indicator in suspicious_indicators
    )