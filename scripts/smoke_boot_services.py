"""Boot both services in subprocesses and confirm they're healthy.

This is the deployment smoke test — it exercises the same path that
docker-compose / k8s would use to start the services.
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx


def _is_port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _http_livez(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with httpx.Client() as c:
            r = c.get(f"http://{host}:{port}/livez", timeout=timeout)
            return r.status_code == 200
    except Exception:  # noqa: BLE001
        return False


def main() -> int:
    repo = Path(__file__).resolve().parents[1]
    vuln_intel_src = repo / "agents" / "roles" / "security" / "vuln-intel" / "src"
    dep_intel_src = repo / "agents" / "roles" / "security" / "dependency-intel" / "src"
    vuln_intel_port = 15008
    dep_intel_port = 15009
    env = os.environ.copy()
    py_sep = ";" if sys.platform == "win32" else ":"
    env["PYTHONPATH"] = py_sep.join([str(vuln_intel_src), str(dep_intel_src), env.get("PYTHONPATH", "")])
    env["VULN_INTEL_PORT"] = str(vuln_intel_port)
    env["VULN_INTEL_DATA_DIR"] = str(Path("/tmp/vuln-intel-svc-smoke"))
    env["VULN_INTEL_AUTH_REQUIRED"] = "false"
    env["DEP_INTEL_PORT"] = str(dep_intel_port)
    env["DEP_INTEL_DATA_DIR"] = str(Path("/tmp/dep-intel-svc-smoke"))
    env["DEP_INTEL_AUTH_REQUIRED"] = "false"
    env["DEP_INTEL_VULN_INTEL_URL"] = f"http://127.0.0.1:{vuln_intel_port}"
    env["VULN_INTEL_HOST"] = "127.0.0.1"
    env["DEP_INTEL_HOST"] = "127.0.0.1"

    procs: list[subprocess.Popen] = []
    try:
        # Boot vuln-intel
        print(f"Starting vuln-intel on port {vuln_intel_port}...")
        procs.append(subprocess.Popen(
            [sys.executable, "-u", "-m", "vuln_intel"],
            cwd=str(vuln_intel_src),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        ))
        # Boot dependency-intel
        print(f"Starting dependency-intel on port {dep_intel_port}...")
        procs.append(subprocess.Popen(
            [sys.executable, "-u", "-m", "dependency_intel"],
            cwd=str(dep_intel_src),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        ))

        # Wait for both to respond on /livez (port open != uvicorn ready)
        deadline = time.monotonic() + 45
        last_v, last_d = False, False
        while time.monotonic() < deadline:
            last_v = _http_livez("127.0.0.1", vuln_intel_port, timeout=1.0)
            last_d = _http_livez("127.0.0.1", dep_intel_port, timeout=1.0)
            if last_v and last_d:
                break
            time.sleep(0.5)
        if not (last_v and last_d):
            print(f"ERROR: services did not become ready within 45s (vuln_intel={last_v}, dep_intel={last_d})")
            for i, p in enumerate(procs):
                p.terminate()
                try:
                    p.wait(timeout=3)
                except Exception:  # noqa: BLE001
                    p.kill()
                try:
                    out = p.stdout.read(8 * 1024).decode("utf-8", "replace")  # type: ignore[union-attr]
                    print(f"--- service {i} output ---\n{out}\n--- end ---")
                except Exception:  # noqa: BLE001
                    pass
            return 1
        print("Both services healthy.")

        # Hit /livez
        with httpx.Client() as client:
            r = client.get(f"http://127.0.0.1:{vuln_intel_port}/livez", timeout=5)
            assert r.status_code == 200, r.text
            print(f"vuln-intel /livez: {r.json()}")
            r = client.get(f"http://127.0.0.1:{vuln_intel_port}/metrics", timeout=5)
            assert r.status_code == 200, r.text
            assert "vuln_intel" in r.text
            print(f"vuln-intel /metrics: 200 OK ({len(r.text)} bytes)")

            r = client.get(f"http://127.0.0.1:{dep_intel_port}/livez", timeout=5)
            assert r.status_code == 200, r.text
            print(f"dependency-intel /livez: {r.json()}")
            r = client.get(f"http://127.0.0.1:{dep_intel_port}/metrics", timeout=5)
            assert r.status_code == 200, r.text
            assert "dep_intel" in r.text
            print(f"dependency-intel /metrics: 200 OK ({len(r.text)} bytes)")

            # OpenAPI docs
            r = client.get(f"http://127.0.0.1:{vuln_intel_port}/openapi.json", timeout=5)
            assert r.status_code == 200, r.text
            paths = sorted(r.json().get("paths", {}).keys())
            print(f"vuln-intel OpenAPI paths: {paths}")
            assert any("/vuln-intel/ingest" in p for p in paths)

            r = client.get(f"http://127.0.0.1:{dep_intel_port}/openapi.json", timeout=5)
            assert r.status_code == 200, r.text
            paths = sorted(r.json().get("paths", {}).keys())
            print(f"dependency-intel OpenAPI paths: {paths}")
            assert any("/dep-intel/graph/build" in p for p in paths)

        print("\nSERVICE BOOT SMOKE TEST: PASSED")
        return 0
    finally:
        for p in procs:
            try:
                p.terminate()
                p.wait(timeout=5)
            except Exception:  # noqa: BLE001
                try:
                    p.kill()
                except Exception:  # noqa: BLE001
                    pass


if __name__ == "__main__":
    sys.exit(main())
