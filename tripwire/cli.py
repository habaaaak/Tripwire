import sys

from tripwire.validator import validate_lsass
from tripwire.coverage import get_proven_coverage


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 -m tripwire [validate|coverage]")
        return 1

    command = sys.argv[1]

    if command == "validate":
        passed = validate_lsass()

        if passed:
            print("\nTripwire validation: PASS")
            return 0

        print("\nTripwire validation: FAIL")
        return 1

    if command == "coverage":
        proven = get_proven_coverage()

        print("\nTripwire ATT&CK Coverage")
        print("------------------------")

        for technique in proven:
            print(f"[PROVEN] {technique}")

        print(f"\nTotal proven techniques: {len(proven)}")

        return 0

    print("Usage: python3 -m tripwire [validate|coverage]")
    return 1


if __name__ == "__main__":
    sys.exit(main())