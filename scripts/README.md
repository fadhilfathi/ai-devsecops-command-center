# Scripts

Local helper scripts. Run from the repository root.

| Script                   | Purpose                                                                                                     |
| ------------------------ | ----------------------------------------------------------------------------------------------------------- |
| `verify_compile.py`      | Byte-compile every Python module in `agents/` and `backend/`                                                |
| `smoke_boot_services.py` | Boot the `vuln-intel`/`dependency-intel` Python agents and hit `/livez`                                     |
| `smoke_e2e_security.py`  | End-to-end smoke of the Python security agents (SBOM -> vuln -> risk)                                       |
| `smoke_vuln_intel.py`    | Smoke test for the `vuln-intel` agent's pure-Python logic                                                   |
| `e2e-smoke.mjs`          | End-to-end smoke of the docker-compose stack (13 Node services + frontend); see `.github/workflows/e2e.yml` |
| `examples.sh`            | Example `curl` calls against a running stack                                                                |
