"""Framework scanner: read the framework versions a model declares in its
config and check them against OSV. This is a provenance signal — it reflects
the library version that produced the model, not necessarily the runtime."""

import json
import re
from dataclasses import dataclass, field

# config fields we know how to map to a PyPI package name.
# key = field in config.json, value = PyPI package name.
_VERSION_FIELDS = {
    "transformers_version": "transformers",
    "diffusers_version": "diffusers",
    "tokenizers_version": "tokenizers",
}

_CONFIG_FILES = ["config.json"]


@dataclass
class FrameworkReport:
    model_id: str
    source_file: str | None = None
    # list of (pypi_package, normalized_version, raw_version)
    frameworks: list[tuple] = field(default_factory=list)
    note: str | None = None


def _normalize_version(raw: str) -> str | None:
    """Turn a config version like '4.10.0.dev0' into '4.10.0' for OSV matching.
    Returns None if we can't extract a clean X.Y.Z(.W) core."""
    if not raw:
        return None
    # Grab the leading numeric dotted portion, e.g. '4.10.0' from '4.10.0.dev0'.
    m = re.match(r"^\d+(\.\d+){1,3}", raw.strip())
    return m.group(0) if m else None


def scan_frameworks(source) -> FrameworkReport:
    """Read config.json from the source and extract declared framework versions."""
    files = set(source.files)
    report = FrameworkReport(model_id=source.identifier)

    target = next((f for f in _CONFIG_FILES if f in files), None)
    if target is None:
        report.note = "No config.json found; cannot assess framework provenance."
        return report

    report.source_file = target
    try:
        content = source.read_text(target)
        config = json.loads(content)
    except Exception as exc:  # noqa: BLE001
        report.note = f"Could not read/parse {target}: {exc}"
        return report

    for field_name, pkg in _VERSION_FIELDS.items():
        raw = config.get(field_name)
        if not raw:
            continue
        normalized = _normalize_version(str(raw))
        if normalized:
            report.frameworks.append((pkg, normalized, str(raw)))

    if not report.frameworks:
        report.note = (
            f"{target} declares no recognized framework version "
            f"(e.g. transformers_version)."
        )

    return report