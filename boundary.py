"""Local Sente execution boundary. Python 3.9+, macOS; no third-party packages."""
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


class Journal:
    """Metadata only. Private storage; hash chain is not an external trust anchor."""
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.lock = threading.Lock()

    def read(self):
        if not self.path.exists():
            return []
        result, previous = [], "0" * 64
        for line in self.path.read_bytes().splitlines():
            record = json.loads(line)
            digest = record.pop("hash")
            if record.get("previous") != previous or hashlib.sha256(canonical(record)).hexdigest() != digest:
                raise ValueError("journal integrity failure")
            record["hash"] = digest
            result.append(record)
            previous = digest
        return result

    def add(self, job, operation, outcome):
        if operation not in {"job.run", "model.catalog", "grant.revoke"}:
            raise ValueError("unknown journal operation")
        if outcome not in {"started", "ok", "failed", "timeout", "denied", "revoked"}:
            raise ValueError("unknown journal outcome")
        with self.lock:
            records = self.read()
            record = dict(version=1, sequence=len(records) + 1, time=time.time(), job=job,
                          operation=operation, outcome=outcome,
                          previous=records[-1]["hash"] if records else "0" * 64)
            record["hash"] = hashlib.sha256(canonical(record)).hexdigest()
            fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "ab") as stream:
                stream.write(canonical(record) + b"\n")
                stream.flush()
                os.fsync(stream.fileno())
            return record


class Grants:
    def __init__(self):
        self.lock = threading.Lock()
        self.items = {}

    def issue(self, job, ttl=60, uses=1):
        if not 0 < ttl <= 300 or not 0 < uses <= 3:
            raise ValueError("invalid grant bounds")
        token = secrets.token_urlsafe(32)
        with self.lock:
            self.items[hashlib.sha256(token.encode()).digest()] = [job, time.monotonic() + ttl, uses]
        return token

    def consume(self, token):
        with self.lock:
            item = self.items.get(hashlib.sha256(token.encode()).digest())
            if not item or item[1] <= time.monotonic() or item[2] <= 0:
                return None
            item[2] -= 1
            return item[0]

    def revoke(self, token):
        with self.lock:
            self.items.pop(hashlib.sha256(token.encode()).digest(), None)


def keychain_catalog():
    # The provider key never enters the job environment or argv. No redirects,
    # proxy environment, caller-supplied URL, or arbitrary provider operations.
    result = subprocess.run(["/usr/bin/security", "find-generic-password", "-a", "yukihamada",
                             "-s", "TEAI_API_KEY", "-w"], capture_output=True, timeout=10,
                            env={"PATH": "/usr/bin:/bin"})
    key = result.stdout.decode().strip()
    if result.returncode or not key or key.startswith("{env:") or "\n" in key or "\r" in key:
        raise RuntimeError("credential unavailable")
    conn = http.client.HTTPSConnection("api.teai.io", timeout=15)
    try:
        conn.request("GET", "/v1/models", headers={"Authorization": "Bearer " + key,
                                                   "User-Agent": "sente-boundary/1"})
        response = conn.getresponse()
        if response.status != 200:
            raise RuntimeError("upstream rejected")
        raw = response.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise RuntimeError("upstream oversized")
        data = json.loads(raw)
        # Return only the catalogue schema. Never reflect arbitrary headers or errors.
        models = data.get("data")
        if not isinstance(models, list):
            raise RuntimeError("upstream schema")
        return {"data": [{"id": model["id"]} for model in models[:500]
                         if isinstance(model, dict) and isinstance(model.get("id"), str)
                         and len(model["id"]) <= 160 and key not in model["id"]]}
    finally:
        conn.close()


class Broker:
    def __init__(self, journal, catalog=keychain_catalog):
        self.grants = Grants()
        broker = self

        class Handler(BaseHTTPRequestHandler):
            def setup(self):
                super().setup()
                self.connection.settimeout(5)

            def log_message(self, *args):
                pass  # bearer and request text are never logged

            def do_GET(self):
                if self.path != "/v1/models" or self.headers.get("Origin") or self.headers.get("Transfer-Encoding"):
                    return self.reply(403, {"error": "denied"})
                if self.headers.get("Content-Length", "0") != "0":
                    return self.reply(403, {"error": "denied"})
                auth = self.headers.get("Authorization", "")
                job = broker.grants.consume(auth[7:]) if auth.startswith("Bearer ") else None
                if not job:
                    return self.reply(403, {"error": "denied"})
                # Audit must be durable before any credential-backed operation.
                try:
                    journal.add(job, "model.catalog", "started")
                    value = catalog()
                    journal.add(job, "model.catalog", "ok")
                except Exception:
                    return self.reply(502, {"error": "operation unavailable"})
                self.reply(200, value)

            def do_POST(self):
                self.reply(403, {"error": "denied"})

            def reply(self, status, value):
                body = canonical(value)
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def port(self):
        return self.server.server_address[1]

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


def profile(directory, broker_port=None):
    # Literal paths are escaped as Scheme strings using JSON; the caller cannot
    # inject sandbox forms through filenames. realpath prevents symlink grants.
    root = json.dumps(str(Path(directory).resolve()))
    network = ""
    if broker_port is not None:
        if type(broker_port) is not int or not 1024 <= broker_port <= 65535:
            raise ValueError("invalid broker port")
        network = '(allow network-outbound (remote ip "localhost:%d"))' % broker_port
    return '''(version 1)
(deny default)
(allow process-exec process-fork)
(allow signal (target self))
(allow sysctl-read)
(allow file-read-metadata)
(allow file-read-data (literal "/"))
(allow file-read* (subpath "/System") (subpath "/usr/lib") (subpath "/usr/share")
 (subpath "/bin") (subpath "/sbin") (subpath "/usr/bin")
 (subpath "/Library/Apple") (subpath "/Library/Developer/CommandLineTools")
 (literal "/dev/null") (literal "/dev/urandom") (literal "/dev/random"))
(allow file-read* file-write* (subpath %s))
(allow file-write-data (literal "/dev/null"))
%s
''' % (root, network)


def run_job(command, root, journal, broker=None, timeout=15):
    if not isinstance(command, str) or not command or len(command) > 32000:
        raise ValueError("invalid command")
    if not 0 < timeout <= 300:
        raise ValueError("invalid timeout")
    if not Path("/usr/bin/sandbox-exec").exists():
        raise RuntimeError("OS sandbox unavailable; refusing execution")
    root = Path(root).resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix="job-", dir=str(root)))
    job = directory.name
    token = broker.grants.issue(job, ttl=min(timeout + 5, 300)) if broker else None
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(directory),
           "TMPDIR": str(directory), "LANG": "en_US.UTF-8"}
    if token:
        env.update(SENTE_CATALOG_CAPABILITY=token, SENTE_CATALOG_URL="http://127.0.0.1:%d/v1/models" % broker.port)
    journal.add(job, "job.run", "started")
    start = time.monotonic()
    outcome, rc = "failed", None
    try:
        # Files, not pipes: a malicious command cannot exhaust controller RAM.
        with open(directory / "stdout", "xb") as stdout, open(directory / "stderr", "xb") as stderr:
            os.chmod(directory / "stdout", 0o600)
            os.chmod(directory / "stderr", 0o600)
            process = subprocess.Popen(["/usr/bin/sandbox-exec", "-p", profile(directory, broker.port if broker else None),
                                        "/bin/sh", "-c", command], cwd=str(directory), env=env,
                                       stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, start_new_session=True)
            try:
                rc = process.wait(timeout=timeout)
                outcome = "ok" if rc == 0 else "failed"
            except subprocess.TimeoutExpired:
                outcome = "timeout"
            finally:
                # Reap descendants even when their parent exits early.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
    finally:
        if token:
            broker.grants.revoke(token)
            journal.add(job, "grant.revoke", "revoked")
        journal.add(job, "job.run", outcome)
    return {"job": job, "outcome": outcome, "exit_code": rc,
            "elapsed_ms": round((time.monotonic() - start) * 1000), "directory": str(directory)}
