"""Verify all our agent code compiles and the API can be imported."""
import sys
import os
import py_compile
import traceback

results = []

def check_compile(label, paths):
    fails = []
    for p in paths:
        try:
            py_compile.compile(p, doraise=True)
        except py_compile.PyCompileError as e:
            fails.append((p, str(e)))
    if fails:
        results.append((label, "FAIL", fails))
        print(f"[{label}] FAIL: {fails}")
    else:
        results.append((label, "OK", len(paths)))
        print(f"[{label}] OK ({len(paths)} files)")


# Vuln-intel
vuln_intel_root = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "agents", "roles", "security", "vuln-intel", "src"
))
vuln_intel_files = []
for base, _, files in os.walk(vuln_intel_root):
    for f in files:
        if f.endswith(".py"):
            vuln_intel_files.append(os.path.join(base, f))
check_compile("vuln-intel", vuln_intel_files)

# Dependency-intel
dep_intel_root = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "agents", "roles", "security", "dependency-intel", "src"
))
dep_intel_files = []
for base, _, files in os.walk(dep_intel_root):
    for f in files:
        if f.endswith(".py"):
            dep_intel_files.append(os.path.join(base, f))
check_compile("dependency-intel", dep_intel_files)

# Tests
test_roots = [
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "agents", "roles", "security", "vuln-intel", "tests")),
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "agents", "roles", "security", "dependency-intel", "tests")),
]
test_files = []
for root in test_roots:
    for base, _, files in os.walk(root):
        for f in files:
            if f.endswith(".py") and f != "__init__.py":
                test_files.append(os.path.join(base, f))
check_compile("tests", test_files)

# Smoke import: vuln_intel.scoring
sys.path.insert(0, vuln_intel_root)
try:
    from vuln_intel.scoring import compute_cvss3_base_score, parse_cvss_vector
    score = compute_cvss3_base_score(parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"))
    print(f"[import] vuln_intel.scoring: OK, 9.8-vector score = {score:.1f}")
except Exception as e:
    print(f"[import] vuln_intel.scoring: FAIL {e}")
    traceback.print_exc()

# Smoke import: dependency_intel.risk
sys.path.insert(0, dep_intel_root)
try:
    import networkx  # noqa
    from dependency_intel.risk import compute_risk
    print("[import] dependency_intel.risk: OK")
except ImportError:
    print("[import] dependency_intel.risk: networkx not installed, skipping")
except Exception as e:
    print(f"[import] dependency_intel.risk: FAIL {e}")

# Summary
fails = [r for r in results if r[1] == "FAIL"]
if fails:
    print(f"\nFAIL: {len(fails)} modules failed to compile")
    sys.exit(1)
print(f"\nOK: all {sum(r[2] for r in results)} files compile cleanly")
sys.exit(0)
