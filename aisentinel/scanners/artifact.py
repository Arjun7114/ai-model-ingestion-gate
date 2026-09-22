"""Artifact scanner: inspect a model's files for unsafe serialization formats."""

from dataclasses import dataclass, field


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
    """Classify a resolved source's files by serialization safety."""
    files = source.files
    report = ArtifactReport(
        model_id=source.identifier, revision=source.revision, files=files
    )

    unsafe = [f for f in files if _extension(f) in UNSAFE_EXTENSIONS]
    safe = [f for f in files if _extension(f) in SAFE_EXTENSIONS]

    if unsafe:
        report.findings.append(Finding(
            check="unsafe_serialization",
            severity="HIGH",
            message=(
                f"{len(unsafe)} pickle-based artifact(s) found: "
                f"{', '.join(unsafe)}. These can execute code on load."
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