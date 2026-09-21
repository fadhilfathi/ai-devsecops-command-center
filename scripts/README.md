# Scripts

Local helper scripts. Run from the repository root.

| Script                   | Purpose                                                          |
| ------------------------ | ---------------------------------------------------------------- |
| `verify_compile.py`      | Byte-compile every Python module in `agents/` and `backend/`     |
| `smoke_boot_services.py` | Boot each backend service and hit `/health`                      |
| `smoke_e2e_security.py`  | End-to-end smoke of the security pipeline (SBOM -> vuln -> risk) |
| `smoke_vuln_intel.py`    | Smoke test for the `vuln-intel` agent                            |
| `examples.sh`            | Example `curl` calls against a running stack                     |
