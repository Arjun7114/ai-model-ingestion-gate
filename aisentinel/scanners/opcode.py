"""Deep artifact inspection: run modelscan's opcode analysis on a model file."""

import json
import subprocess
from dataclasses import dataclass


@dataclass
class OpcodeResult:
    scanned: bool                 # did modelscan actually run on this file?
    total_issues: int = 0
    highest_severity: str | None = None   # LOW | MEDIUM | HIGH | CRITICAL
    detail: str = ""              # human-readable summary
    error: str | None = None      # populated if the scan could not run


# Order used to find the most severe issue.
_SEV_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def scan_file_opcodes(path: str) -> OpcodeResult:
    """Run modelscan on a single file and summarize its findings."""
    try:
        proc = subprocess.run(
            ["modelscan", "-p", path, "-r", "json"],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except FileNotFoundError:
        return OpcodeResult(scanned=False, error="modelscan is not installed.")
    except subprocess.TimeoutExpired:
        return OpcodeResult(scanned=False, error="modelscan timed out.")

    # modelscan prints some non-JSON lines before the JSON blob, so find the
    # JSON object in stdout rather than assuming it starts at character 0.
    stdout = proc.stdout or ""
    start = stdout.find("{")
    if start == -1:
        return OpcodeResult(
            scanned=False,
            error=f"Could not parse modelscan output. stderr: {proc.stderr[:200]}",
        )

    try:
        data = json.loads(stdout[start:], strict=False)
    except json.JSONDecodeError as exc:
        return OpcodeResult(scanned=False, error=f"Invalid JSON from modelscan: {exc}")

    summary = data.get("summary", {})
    by_sev = summary.get("total_issues_by_severity", {})
    total = summary.get("total_issues", 0)

    highest = None
    for sev in reversed(_SEV_ORDER):        # check CRITICAL first
        if by_sev.get(sev, 0) > 0:
            highest = sev
            break

    if total == 0:
        detail = "modelscan inspected the file and found no unsafe operators."
    else:
        counts = ", ".join(f"{k}:{v}" for k, v in by_sev.items() if v)
        detail = f"modelscan found {total} unsafe operator(s) ({counts})."

    return OpcodeResult(
        scanned=True,
        total_issues=total,
        highest_severity=highest,
        detail=detail,
    )