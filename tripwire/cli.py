import sys

from tripwire.validator import validate_lsass


def main():
    if len(sys.argv) != 2 or sys.argv[1] != "validate":
        print("Usage: python3 -m tripwire validate")
        return 1

    passed = validate_lsass()

    if passed:
        print("\nTripwire validation: PASS")
        return 0

    print("\nTripwire validation: FAIL")
    return 1


if __name__ == "__main__":
    sys.exit(main())