"""Verify an explicitly provisioned liboqs shared library."""

import json

from pqclab.backend import doctor


def main() -> int:
    report = doctor()
    print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    return 0 if report.status == "ready" else 1


if __name__ == "__main__":
    raise SystemExit(main())
