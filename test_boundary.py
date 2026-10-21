"""Exercise the actual macOS boundary with dummy data; no real credentials."""
import concurrent.futures
import http.client
import json
import os
from pathlib import Path
import shlex
import tempfile
import time
import unittest
from unittest.mock import patch

from boundary import Broker, Grants, Journal, keychain_catalog, run_job


class BoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sente-boundary-")
        self.root = Path(self.temp.name).resolve()
        self.journal = Journal(self.root / "control" / "events.jsonl")
        self.secret = self.root / "outside.txt"
        self.secret.write_text("DUMMY-OUTSIDE-SECRET")

    def tearDown(self):
        self.temp.cleanup()

    def run_command(self, command, **kwargs):
        result = run_job(command, self.root / "jobs", self.journal, **kwargs)
        directory = Path(result["directory"])
        return result, (directory / "stdout").read_text(), (directory / "stderr").read_text()

    def python(self, code, **kwargs):
        return self.run_command("/Library/Developer/CommandLineTools/usr/bin/python3 -c " + shlex.quote(code), **kwargs)

    def test_own_workspace(self):
        result, out, err = self.python("from pathlib import Path; p=Path('ok'); p.write_text('local-ok'); print(p.read_text())")
        self.assertEqual(result["exit_code"], 0, err)
        self.assertEqual(out.strip(), "local-ok")

    def test_outside_read(self):
        result, out, err = self.python("from pathlib import Path; print(Path(%r).read_text())" % str(self.secret))
        self.assertNotEqual(result["exit_code"], 0)
        self.assertIn("Operation not permitted", err)
        self.assertNotIn("DUMMY-OUTSIDE-SECRET", out)

    def test_child_outside_read(self):
        result, out, err = self.python("import subprocess; raise SystemExit(subprocess.call(['/bin/cat', %r]))" % str(self.secret))
        self.assertNotEqual(result["exit_code"], 0)
        self.assertIn("Operation not permitted", err)

    def test_symlink_escape(self):
        result, out, err = self.python("from pathlib import Path; p=Path('link'); p.symlink_to(%r); print(p.read_text())" % str(self.secret))
        self.assertNotEqual(result["exit_code"], 0)
        self.assertIn("Operation not permitted", err)

    def test_outside_write(self):
        result, _, err = self.python("from pathlib import Path; Path(%r).write_text('modified')" % str(self.secret))
        self.assertNotEqual(result["exit_code"], 0)
        self.assertEqual(self.secret.read_text(), "DUMMY-OUTSIDE-SECRET")

    def test_environment_not_inherited(self):
        with patch.dict(os.environ, {"SENTE_PARENT_DUMMY": "PRIVATE-PARENT-MARKER"}):
            result, out, err = self.python("import os; print(os.environ.get('SENTE_PARENT_DUMMY', 'absent'))")
        self.assertEqual(result["exit_code"], 0, err)
        self.assertEqual(out.strip(), "absent")

    def test_process_inspection(self):
        result, out, _ = self.run_command("/bin/ps eww -p %d" % os.getpid())
        self.assertNotEqual(result["exit_code"], 0)

    def test_keychain_service_denied(self):
        # A random nonexistent service: no real secrets are queried or printed.
        result, out, err = self.run_command("/usr/bin/security find-generic-password -s sente-boundary-dummy-nonexistent -w")
        self.assertNotEqual(result["exit_code"], 0)
        self.assertEqual(out, "")
        self.assertTrue(err)

    def test_ungranted_loopback_denied(self):
        with Broker(self.journal, catalog=lambda: {"data": []}) as controller:
            result, out, err = self.python("import socket; socket.create_connection(('127.0.0.1', %d), 2)" % controller.port)
        self.assertNotEqual(result["exit_code"], 0)
        self.assertIn("Operation not permitted", err)

    def test_direct_network_denied(self):
        result, out, err = self.python("import socket; socket.create_connection(('192.0.2.1', 443), 2)")
        self.assertNotEqual(result["exit_code"], 0)
        self.assertIn("Operation not permitted", err)

    def test_granted_broker_from_job(self):
        with Broker(self.journal, catalog=lambda: {"data": [{"id": "dummy-model"}]}) as broker:
            result, out, err = self.python("import os, urllib.request; r=urllib.request.Request(os.environ['SENTE_CATALOG_URL'], headers={'Authorization':'Bearer '+os.environ['SENTE_CATALOG_CAPABILITY']}); print(urllib.request.urlopen(r, timeout=3).read().decode())", broker=broker)
        self.assertEqual(result["exit_code"], 0, err)
        self.assertEqual(json.loads(out), {"data": [{"id": "dummy-model"}]})

    def test_broker_rejects_invalid_requests_and_replay(self):
        calls = []
        with Broker(self.journal, catalog=lambda: calls.append(1) or {"data": []}) as broker:
            token = broker.grants.issue("dummy-job")
            def request(path="/v1/models", bearer=token, method="GET", extra=None):
                conn = http.client.HTTPConnection("127.0.0.1", broker.port, timeout=3)
                try:
                    conn.request(method, path, headers={"Authorization": "Bearer " + bearer, **(extra or {})})
                    response = conn.getresponse()
                    response.read()
                    return response.status
                finally:
                    conn.close()
            self.assertEqual(request(bearer="invalid"), 403)
            self.assertEqual(request(path="https://example.com"), 403)
            self.assertEqual(request(path="/v1/models?url=evil"), 403)
            self.assertEqual(request(method="POST"), 403)
            self.assertEqual(request(extra={"Origin": "https://example.com"}), 403)
            self.assertEqual(request(), 200)
            self.assertEqual(request(), 403)
            self.assertEqual(calls, [1])

    def test_expired_revoked_and_atomic_grants(self):
        grants = Grants()
        expired = grants.issue("dummy", ttl=0.001)
        time.sleep(0.01)
        self.assertIsNone(grants.consume(expired))
        revoked = grants.issue("dummy")
        grants.revoke(revoked)
        self.assertIsNone(grants.consume(revoked))
        token = grants.issue("dummy")
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(grants.consume, [token] * 20))
        self.assertEqual(results.count("dummy"), 1)

    def test_timeout_and_revocation(self):
        with Broker(self.journal, catalog=lambda: {"data": []}) as broker:
            result, out, err = self.run_command("/bin/sleep 10", broker=broker, timeout=0.2)
            self.assertEqual(result["outcome"], "timeout")
            self.assertEqual(broker.grants.items, {})
        self.assertEqual(self.journal.read()[-1]["outcome"], "timeout")

    def test_ledger_tamper_and_no_command_content(self):
        self.run_command("/bin/echo DUMMY-COMMAND-CONTENT")
        content = self.journal.path.read_text()
        self.assertNotIn("DUMMY-COMMAND-CONTENT", content)
        self.journal.path.write_text(content.replace('"started"', '"denied"'))
        with self.assertRaises(ValueError):
            self.journal.read()

    def test_upstream_redirect_refused(self):
        import subprocess
        with patch("boundary.subprocess.run", return_value=subprocess.CompletedProcess([], 0, b"DUMMY-KEY", b"")), patch("boundary.http.client.HTTPSConnection") as connection:
            connection.return_value.getresponse.return_value.status = 302
            with self.assertRaisesRegex(RuntimeError, "upstream rejected"):
                keychain_catalog()
            self.assertEqual(connection.return_value.request.call_count, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
