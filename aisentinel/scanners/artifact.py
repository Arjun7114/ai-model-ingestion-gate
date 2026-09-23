"""Artifact scanner: inspect a model's files for unsafe serialization formats."""

import os
from dataclasses import dataclass, field

from aisentinel.scanners.opcode import scan_file_opcodes

# File extensions that use Python pickle under the hood. Loading these can
# execute arbitrary code, so they are the primary supply-chain risk.
UNSAFE_EXTENSIONS = {".bin", ".pkl", ".pickle", ".pt", ".pth", ".ckpt", ".joblib"}

# The safe, non-executable tensor format.
SAFE_EXTENSIONS = {".safetensors"}


@dataclass
class Finding:
    """A single observation about the model."""
    check: str          # short id, e.g. "unsafe_serialization"
    severity: str       # INFO | LOW | MEDIUM | HIGH | CRITICAL
    message: str


@dataclass
class ArtifactReport:
    model_id: str
    revision: str | None = None
    files: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


def _extension(filename: str) -> str:
    """Return the lowercased extension including the dot, e.g. '.bin'."""
    dot = filename.rfind(".")
    return filename[dot:].lower() if dot != -1 else ""


def scan_artifacts(source) -> ArtifactReport:
    """Classify a source's files by serialization safety, with deep opcode
    inspection of pickle files when they are available on local disk."""
    files = source.files
    report = ArtifactReport(
        model_id=source.identifier, revision=source.revision, files=files
    )

    unsafe = [f for f in files if _extension(f) in UNSAFE_EXTENSIONS]
    safe = [f for f in files if _extension(f) in SAFE_EXTENSIONS]

    # Deep-scan pickle files when we can reach them on disk (local sources).
    can_deep_scan = getattr(source, "kind", None) == "local" and getattr(
        source, "_local_root", None
    )

    for f in unsafe:
        if can_deep_scan:
            full_path = os.path.join(source._local_root, f)
            result = scan_file_opcodes(full_path)
            if not result.scanned:
                # Could not inspect — fail safe, treat as risky.
                report.findings.append(Finding(
                    check="unsafe_serialization",
                    severity="HIGH",
                    message=(
                        f"{f}: pickle-based artifact; deep inspection "
                        f"unavailable ({result.error}). Treated as risky."
                    ),
                ))
            elif result.total_issues > 0:
                sev = result.highest_severity or "HIGH"
                report.findings.append(Finding(
                    check="malicious_opcode",
                    severity=sev,
                    message=f"{f}: {result.detail}",
                ))
            else:
                report.findings.append(Finding(
                    check="pickle_inspected_clean",
                    severity="MEDIUM",
                    message=(
                        f"{f}: pickle format, but modelscan found no unsafe "
                        f"operators. Prefer safetensors."
                    ),
                ))
        else:
            # Remote source: we only have the file list, not the bytes.
            report.findings.append(Finding(
                check="unsafe_serialization",
                severity="HIGH",
                message=(
                    f"{f}: pickle-based artifact (extension check). "
                    f"Deep opcode inspection requires a local copy."
                ),
            ))

    if safe:
        report.findings.append(Finding(
            check="safe_serialization",
            severity="INFO",
            message=f"{len(safe)} safetensors artifact(s) present: {', '.join(safe)}.",
        ))

    if not safe and not unsafe:
        report.findings.append(Finding(
            check="no_recognized_weights",
            severity="LOW",
            message="No recognized model weight files were found.",
        ))

    return report