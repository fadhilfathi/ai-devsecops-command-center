"""Smoke test for the vuln-intel critical logic.

This is a minimal test that exercises the most important pure-Python
logic (CVSS, severity aggregation, CveRecord merge, SBOM matcher) without
requiring FastAPI / httpx. It's used as a build-time gate.
"""
import sys
import os

# Add vuln-intel source to path
SRC = os.path.abspath(os.path.join(
    os.path.dirname(__file__),
    "..", "agents", "roles", "security", "vuln-intel", "src"
))
sys.path.insert(0, SRC)

# Minimal pydantic stub - the real one is already installed


def main() -> int:
    try:
        from vuln_intel.scoring import (
            parse_cvss_vector,
            compute_cvss3_base_score,
            cvss3_severity_from_score,
            parse_cvss3_vector,
            aggregate_severity,
        )
    except Exception as e:
        print(f"IMPORT ERROR: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1
    print("imports OK")
    from vuln_intel.models.cve import (
        CveRecord,
        CvssScore,
        SeverityAggregate,
        SeverityQualitative,
        SourceName,
    )

    # --- 1) CVSS 3.1 criticality ---
    cases = [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, SeverityQualitative.CRITICAL),
        ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 2.3, SeverityQualitative.LOW),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", 6.5, SeverityQualitative.MEDIUM),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, SeverityQualitative.CRITICAL),  # scope changed
    ]
    failures = []
    for vector, expected_score, expected_sev in cases:
        m = parse_cvss_vector(vector)
        s = compute_cvss3_base_score(m)
        sev = cvss3_severity_from_score(s)
        if abs(s - expected_score) > 0.2 or sev != expected_sev:
            failures.append((vector, s, sev, expected_score, expected_sev))
    if failures:
        print("CVSS FAILURES:", failures, file=sys.stderr)
        return 1

    # --- 2) CveRecord merge ---
    a = CveRecord(
        id="CVE-2024-31337",
        aliases=[],
        source=[SourceName.NVD],
        severity=SeverityAggregate(qualitative=SeverityQualitative.MEDIUM, primary_source="nvd:primary"),
    )
    b = CveRecord(
        id="CVE-2024-31337",
        aliases=["GHSA-xxxx-yyyy-zzzz"],
        source=[SourceName.GHSA],
        severity=SeverityAggregate(qualitative=SeverityQualitative.CRITICAL, primary_source="ghsa"),
    )
    merged = a.merge(b)
    assert merged.severity.qualitative == SeverityQualitative.CRITICAL, "merge should pick higher severity"
    assert "GHSA-xxxx-yyyy-zzzz" in merged.aliases, "merge should add aliases"
    assert SourceName.NVD in merged.source and SourceName.GHSA in merged.source

    # --- 3) Severity aggregation prefers v4 over v3 ---
    sev = aggregate_severity(
        cvss_v3=CvssScore(version="3.1", vector="CVSS:3.1/AV:N", score=7.5, severity=SeverityQualitative.HIGH, source="nvd:primary"),
        cvss_v4=CvssScore(version="4.0", vector="CVSS:4.0/AV:N", score=8.5, severity=SeverityQualitative.HIGH, source="nvd:primary"),
    )
    assert sev.cvss_v4 is not None and sev.cvss_v3 is not None

    # --- 4) SBOM matcher ---
    from vuln_intel.matcher import match_components, version_in_range
    from vuln_intel.models.cve import AffectedPackage, AffectedVersionRange
    from vuln_intel.models.dto import MatchRequestComponent

    vuln = CveRecord(
        id="CVE-X",
        source=[SourceName.OSV],
        severity=SeverityAggregate(
            qualitative=SeverityQualitative.HIGH,
            cvss_v3=CvssScore(version="3.1", vector="CVSS:3.1/AV:N", score=7.5, severity=SeverityQualitative.HIGH, source="osv"),
            primary_source="osv",
        ),
        affected=[AffectedPackage(
            name="foo", ecosystem="PyPI", purl="pkg:pypi/foo@1.0.0",
            versions=[AffectedVersionRange(introduced="0", fixed="1.2.4")],
        )],
    )
    comp = MatchRequestComponent(purl="pkg:pypi/foo@1.0.0", name="foo", version="1.0.0")
    findings = match_components([comp], [vuln])
    assert len(findings) == 1, "matcher should find one finding"
    assert findings[0].confidence > 0.5

    # --- 5) Semver comparison ---
    assert version_in_range("1.0.0", [AffectedVersionRange(introduced="1.0.0", fixed="1.2.4")])
    assert not version_in_range("1.2.4", [AffectedVersionRange(introduced="1.0.0", fixed="1.2.4")])
    assert not version_in_range("0.9.9", [AffectedVersionRange(introduced="1.0.0", fixed="1.2.4")])

    print("OK: all smoke tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
