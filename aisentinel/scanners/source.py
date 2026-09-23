"""Resolve a scan target (Hugging Face model id or local path) to files.

Uses a pure-Python Hugging Face REST client (no huggingface_hub dependency),
so the scan path stays lightweight and portable for the cloud scanner.
"""

import os
from dataclasses import dataclass

from aisentinel.intel.hf_api import get_model_info, fetch_file_text


@dataclass
class ScanSource:
    identifier: str          # the model id or path as given
    kind: str                # "local" or "hub"
    revision: str | None
    files: list[str]         # relative file paths
    _local_root: str | None = None

    def read_text(self, filename: str) -> str:
        """Return the text contents of one file from the source."""
        if self.kind == "local":
            full = os.path.join(self._local_root, filename)
            with open(full, "r", encoding="utf-8", errors="replace") as fh:
                return fh.read()
        # hub — fetch the file over the HF REST API.
        revision = self.revision or "main"
        return fetch_file_text(self.identifier, filename, revision=revision)


def resolve_source(identifier: str) -> ScanSource:
    """Decide whether the identifier is a local folder or a Hub model id."""
    if os.path.isdir(identifier):
        files = []
        for root, _dirs, names in os.walk(identifier):
            for n in names:
                rel = os.path.relpath(os.path.join(root, n), identifier)
                files.append(rel.replace("\\", "/"))  # normalize Windows paths
        return ScanSource(
            identifier=identifier,
            kind="local",
            revision=None,
            files=files,
            _local_root=identifier,
        )

    # Otherwise treat it as a Hub model id, resolved via the HF REST API.
    info = get_model_info(identifier)
    return ScanSource(
        identifier=identifier,
        kind="hub",
        revision=info["sha"],
        files=info["files"],
    )