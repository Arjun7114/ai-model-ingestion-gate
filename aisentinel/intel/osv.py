"""OSV vulnerability correlation: query api.osv.dev for known CVEs."""

from dataclasses import dataclass, field
import requests

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns"

# OSV severity can come through in different ways; we normalize to our scale.
_SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


@dataclass
class Vulnerability:
    package: str
    version: str | None
    vuln_id: str            # e.g. "GHSA-..." or "PYSEC-..."
    severity: str           # our normalized scale
    summary: str


@dataclass
class OSVReport:
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    queried: int = 0
    errors: list[str] = field(default_factory=list)


def _normalize_severity(vuln_json: dict) -> str:
    """Best-effort mapping of an OSV vuln record to our severity scale."""
    # OSV records sometimes carry a database_specific severity string.
    db = vuln_json.get("database_specific", {})
    label = str(db.get("severity", "")).upper()
    if label in _SEVERITY_ORDER:
        return label
    # Fall back to CVSS score if present.
    for sev in vuln_json.get("severity", []):
        score = str(sev.get("score", ""))
        # CVSS vector strings start with "CVSS:3"; we can't parse fully here,
        # so default unknown-but-present severities to MEDIUM.
        if score:
            return "MEDIUM"
    return "MEDIUM"


def query_osv(dependencies) -> OSVReport:
    """Given a list of Dependency objects, return known vulnerabilities."""
    report = OSVReport()
    # Build the batch query. OSV wants one entry per package/version.
    queries = []
    index_map = []  # remember which dep each query maps to
    for dep in dependencies:
        if not dep.version:
            # OSV needs a version to match precisely; skip unpinned for now.
            continue
        queries.append({
            "package": {"name": dep.name, "ecosystem": "PyPI"},
            "version": dep.version,
        })
        index_map.append(dep)

    report.queried = len(queries)
    if not queries:
        return report

    try:
        resp = requests.post(OSV_BATCH_URL, json={"queries": queries}, timeout=30)
        resp.raise_for_status()
    except Exception as exc:  # noqa: BLE001
        report.errors.append(f"OSV batch query failed: {exc}")
        return report

    results = resp.json().get("results", [])

    for dep, result in zip(index_map, results):
        for vuln_stub in result.get("vulns", []) or []:
            vuln_id = vuln_stub.get("id", "UNKNOWN")
            # Fetch the full record to get a summary + severity.
            summary, severity = _fetch_vuln_detail(vuln_id, report)
            report.vulnerabilities.append(Vulnerability(
                package=dep.name,
                version=dep.version,
                vuln_id=vuln_id,
                severity=severity,
                summary=summary,
            ))

    return report


def _fetch_vuln_detail(vuln_id: str, report: OSVReport) -> tuple[str, str]:
    """Fetch a single vulnerability record for its summary and severity."""
    try:
        resp = requests.get(f"{OSV_VULN_URL}/{vuln_id}", timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:  # noqa: BLE001
        report.errors.append(f"Could not fetch detail for {vuln_id}: {exc}")
        return ("(detail unavailable)", "MEDIUM")

    summary = data.get("summary") or data.get("details", "")[:100] or "(no summary)"
    severity = _normalize_severity(data)
    return (summary, severity)