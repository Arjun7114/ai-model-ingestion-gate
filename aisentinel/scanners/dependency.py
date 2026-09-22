"""Dependency scanner: read a model repo's declared Python dependencies."""

from dataclasses import dataclass, field



@dataclass
class Dependency:
    name: str
    version: str | None = None   # None means unpinned
    raw: str = ""                # the original line, for traceability


@dataclass
class DependencyReport:
    model_id: str
    source_file: str | None = None      # which file we read, if any
    dependencies: list[Dependency] = field(default_factory=list)
    note: str | None = None             # e.g. "no requirements file found"


# Requirement files we look for, in order of preference.
_CANDIDATE_FILES = ["requirements.txt"]


def _parse_requirement(line: str) -> Dependency | None:
    """Parse a single requirements.txt line into a Dependency, or None to skip."""
    line = line.strip()
    # Skip blanks, comments, and options like "-r base.txt" or "--index-url ...".
    if not line or line.startswith("#") or line.startswith("-"):
        return None
    # Strip inline comments.
    if " #" in line:
        line = line.split(" #", 1)[0].strip()

    raw = line
    # Handle the common pinning operators. We only need name + version here.
    for op in ("==", ">=", "<=", "~=", "!=", ">", "<"):
        if op in line:
            name, version = line.split(op, 1)
            return Dependency(name=name.strip(), version=version.strip(), raw=raw)

    # No operator: an unpinned dependency.
    return Dependency(name=line, version=None, raw=raw)


def scan_dependencies(source) -> DependencyReport:
    """Look for a requirements file in the source and parse it."""
    files = set(source.files)
    report = DependencyReport(model_id=source.identifier)

    target = next((f for f in _CANDIDATE_FILES if f in files), None)
    if target is None:
        report.note = "No requirements.txt found."
        return report

    report.source_file = target
    content = source.read_text(target)

    for line in content.splitlines():
        dep = _parse_requirement(line)
        if dep is not None:
            report.dependencies.append(dep)

    if not report.dependencies:
        report.note = f"{target} was found but contained no parseable dependencies."

    return report