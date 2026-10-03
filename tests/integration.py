"""Real-process integration test: Go daemon, Python and compiled TypeScript SDKs.

Uses only disposable localhost credentials. Builds in a temporary directory,
renews beyond the original TTL, restarts the daemon, and reuses persisted state.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk/python"))
from galleton import Galleton, GalletonError


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def eventually(check, seconds=8):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            result = check()
            if result:
                return result
        except (OSError, GalletonError):
            pass
        time.sleep(0.05)
    raise AssertionError("condition did not become true")


def stop(proc):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def main():
    checks = []
    with tempfile.TemporaryDirectory(prefix="galleton-integration-") as temp:
        base = Path(temp)
        suffix = ".exe" if os.name == "nt" else ""
        daemon_exe = base / ("galleton" + suffix)
        provider_exe = base / ("provider" + suffix)
        for target, package in [(daemon_exe, "./cmd/galleton"), (provider_exe, "./cmd/demo-provider")]:
            subprocess.run(["go", "build", "-o", str(target), package], cwd=ROOT, check=True)
        provider_url = f"http://127.0.0.1:{free_port()}"
        api_url = f"http://127.0.0.1:{free_port()}"
        config = {"providers": [
            {"name": "oauth", "kind": "oauth2", "origins": [provider_url],
             "refresh_url": provider_url + "/oauth/token", "refresh_interval_seconds": 1, "allow_http_loopback": True},
            {"name": "cookie", "kind": "http", "origins": [provider_url],
             "refresh_url": provider_url + "/cookie/session", "refresh_method": "GET",
             "response": {"require_set_cookie": True}, "refresh_interval_seconds": 1, "allow_http_loopback": True},
        ]}
        config_file = base / "adapters.json"
        config_file.write_text(json.dumps(config))
        state_dir = base / "state"
        subprocess.run([str(daemon_exe), "init", "--dir", str(state_dir)], check=True, capture_output=True)
        provider = subprocess.Popen([str(provider_exe), "--listen", provider_url.removeprefix("http://"), "--ttl", "4s"], stderr=subprocess.DEVNULL)
        processes = [provider]
        try:
            eventually(lambda: urlopen(provider_url + "/health", timeout=1).status == 200)
            daemon_args = [str(daemon_exe), "serve", "--dir", str(state_dir), "--config", str(config_file), "--listen", api_url.removeprefix("http://")]
            daemon = subprocess.Popen(daemon_args, stderr=subprocess.DEVNULL)
            processes.append(daemon)
            client = Galleton.from_dir(state_dir, api_url)
            eventually(lambda: client.list() == [])
            client.connect("oauth-account", {"provider": "oauth", "refresh_token": "demo-refresh-0"})
            client.connect("cookie-account", {"provider": "cookie", "cookie_origin": provider_url, "cookie_header": "sid=demo-cookie-0"})
            checks.append("one-time import of OAuth and cookie credentials")
            for account in ["oauth-account", "cookie-account"]:
                assert client.request(account, provider_url + "/me").json()["ok"]
            checks.append("Python SDK managed requests authenticate")
            script = '''
import { Galleton } from "./sdk/typescript/dist/index.js";
const client = new Galleton({ token: process.env.LOCAL_TEST_TOKEN, baseURL: process.env.LOCAL_TEST_API });
for (const id of ["oauth-account", "cookie-account"]) {
  const r = await client.request(id, process.env.LOCAL_TEST_PROVIDER + "/me");
  if (!r.ok || !r.json().ok) throw new Error("Node authentication failed");
}
'''
            env = os.environ.copy()
            env.update(LOCAL_TEST_TOKEN=(state_dir / "api.token").read_text().strip(), LOCAL_TEST_API=api_url, LOCAL_TEST_PROVIDER=provider_url)
            subprocess.run(["node", "--input-type=module", "-e", script], cwd=ROOT, env=env, check=True)
            checks.append("compiled TypeScript SDK shares the same sessions")
            time.sleep(13)  # Beyond the original refresh/cookie lifetimes (12s), not just the 4s access TTL.
            for account in ["oauth-account", "cookie-account"]:
                data = client.request(account, provider_url + "/me").json()
                assert data["ok"] and data["oauth_renewals"] >= 2 and data["cookie_renewals"] >= 2
            checks.append("scheduler renews beyond original refresh-token/cookie lifetimes without resubmission")
            shutdown = subprocess.run(
                [str(daemon_exe), "shutdown", "--dir", str(state_dir), "--api", api_url],
                capture_output=True, text=True, check=True,
            )
            assert json.loads(shutdown.stdout)["stopping"]
            daemon.wait(timeout=10)
            assert daemon.returncode == 0
            checks.append("authenticated CLI shutdown drains the daemon")
            daemon = subprocess.Popen(daemon_args, stderr=subprocess.DEVNULL)
            processes.append(daemon)
            eventually(lambda: len(client.list()) == 2)
            for account in ["oauth-account", "cookie-account"]:
                assert client.request(account, provider_url + "/me").json()["ok"]
            checks.append("daemon restart preserves both rotated credential types")
            try:
                client.headers("oauth-account", "https://not-allowed.example/")
                raise AssertionError("unapproved origin accepted")
            except GalletonError as exc:
                assert exc.code == "origin_not_allowed"
            checks.append("origin allowlist prevents credential release")
            result = subprocess.run([str(daemon_exe), "status", "--dir", str(state_dir), "--api", api_url, "oauth-account"], capture_output=True, text=True, check=True)
            assert json.loads(result.stdout)["status"] == "ready"
            assert "demo-refresh" not in result.stdout
            checks.append("CLI status works and does not print credentials")
            for path in state_dir.glob("*.session-v2"):
                blob = path.read_bytes()
                assert b"demo-refresh" not in blob and b"demo-cookie" not in blob
            checks.append("on-disk session entries contain no plaintext demo credentials")
        finally:
            for proc in reversed(processes):
                stop(proc)
    print(json.dumps({"passed": len(checks), "checks": checks}, indent=2))


if __name__ == "__main__":
    main()
