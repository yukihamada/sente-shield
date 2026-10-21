"""Run dummy-only checks and produce the same offline snapshot for both clients."""
import datetime
import hashlib
import json
from pathlib import Path
import sys
import unittest

import test_boundary


class Result(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.checks = []

    def record(self, test, status):
        self.checks.append({"id": test.id().split(".")[-1], "status": status})

    def addSuccess(self, test):
        super().addSuccess(test)
        self.record(test, "passed")

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.record(test, "failed")

    def addError(self, test, err):
        super().addError(test, err)
        self.record(test, "failed")

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.record(test, "unavailable")


def main():
    root = Path(__file__).resolve().parent
    sources = {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
               for name in ("boundary.py", "test_boundary.py", "verify.py")}
    result = unittest.TextTestRunner(verbosity=2, resultclass=Result).run(
        unittest.defaultTestLoader.loadTestsFromModule(test_boundary))
    snapshot = {"version": 1, "observedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "scope": "local-prototype-dummy-only", "integrated": False,
                "checks": result.checks, "sources": sources}
    destination = root / "viewer" / "snapshot.json"
    destination.write_text(json.dumps(snapshot, indent=2) + "\n")
    print("Snapshot: " + str(destination))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
