"""Reusable scan core: run a lightweight model scan and return structured
JSON-serializable results. Used by both the CLI and the cloud scanner.

'Lightweight' means metadata-level checks (file listing, declared dependencies,
framework provenance, OSV correlation) without downloading full model weights —
suitable for a time- and space-limited environment like AWS Lambda.
"""

from datetime import datetime, timezone

from aisentinel.scanners.source import resolve_source
from aisentinel.scanners.artifact import scan_artifacts
from aisentinel.scanners.dependency import scan_dependencies
from aisentinel.scanners.framework import scan_frameworks
from aisentinel.intel.osv import query_osv


class _FrameworkDep:
    """Minimal object matching what query_osv expects (.name, .version)."""
    def __init__(self, name: str, version: str):
        self.name = name
        self.version = version


def scan_model_lightweight(model: str) -> dict:
    """Run a metadata-level scan of a model and return a structured result.

    Returns a JSON-serializable dict with keys:
      model, kind, revision, file_count, artifacts, dependencies,
      dependency_vulns, framework, scanned_at, worst_severity
    """
    result = {
        "model": model,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "ok": True,
        "error": None,
    }

    try:
        source = resolve_source(model)
    except Exception as exc:  # noqa: BLE001
        result["ok"] = False
        result["error"] = f"Could not resolve target: {exc}"
        return result

    result["kind"] = source.kind
    result["revision"] = source.revision
    result["file_count"] = len(source.files)

    # --- Artifacts (format-level; no deep download in the lightweight path) ---
    artifact_report = scan_artifacts(source)
    result["artifacts"] = [
        {"check": f.check, "severity": f.severity, "message": f.message}
        for f in artifact_report.findings
    ]

    # --- Declared dependencies + OSV ---
    dep_report = scan_dependencies(source)
    dep_vulns = []
    if dep_report.dependencies:
        osv = query_osv(dep_report.dependencies)
        dep_vulns = [
            {
                "package": v.package,
                "version": v.version,
                "id": v.vuln_id,
                "severity": v.severity,
            }
            for v in osv.vulnerabilities
        ]
    result["dependencies"] = [
        {"name": d.name, "version": d.version} for d in dep_report.dependencies
    ]
    result["dependency_vulns"] = dep_vulns

    # --- Framework provenance + OSV (informational) ---
    fw_report = scan_frameworks(source)
    framework = {"declared": [], "advisory_counts": {}, "note": fw_report.note}
    if fw_report.frameworks:
        fw_deps = [_FrameworkDep(pkg, ver) for (pkg, ver, _raw) in fw_report.frameworks]
        framework["declared"] = [
            {"package": pkg, "version": ver, "raw": raw}
            for (pkg, ver, raw) in fw_report.frameworks
        ]
        fw_osv = query_osv(fw_deps)
        counts = {}
        for v in fw_osv.vulnerabilities:
            counts[v.severity] = counts.get(v.severity, 0) + 1
        framework["advisory_counts"] = counts
    result["framework"] = framework

    # --- Worst severity across the blocking-relevant findings ---
    order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    worst = "INFO"
    for f in artifact_report.findings:
        if f.severity in order and order.index(f.severity) > order.index(worst):
            worst = f.severity
    for v in dep_vulns:
        if v["severity"] in order and order.index(v["severity"]) > order.index(worst):
            worst = v["severity"]
    result["worst_severity"] = worst

    return result