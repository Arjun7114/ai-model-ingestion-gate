"""Pure-Python Hugging Face client using the public REST API.

Avoids the huggingface_hub dependency (and its native sub-dependencies) so the
package stays small and portable — important for the cloud scanner (Lambda).
"""

import requests

_API_BASE = "https://huggingface.co/api/models"
_RESOLVE_BASE = "https://huggingface.co"


def get_model_info(model_id: str, timeout: int = 30) -> dict:
    """Return {'sha': ..., 'files': [...]} for a model, via the HF REST API.

    Raises requests.HTTPError on a non-200 (e.g. 404 for a missing model,
    401 for a gated model)."""
    resp = requests.get(f"{_API_BASE}/{model_id}", timeout=timeout)
    resp.raise_for_status()
    data = resp.json()
    files = [s.get("rfilename") for s in data.get("siblings", []) if s.get("rfilename")]
    return {"sha": data.get("sha"), "files": files}


def fetch_file_text(model_id: str, filename: str, revision: str = "main",
                    timeout: int = 30) -> str:
    """Return the text contents of one file from a model repo."""
    url = f"{_RESOLVE_BASE}/{model_id}/resolve/{revision}/{filename}"
    resp = requests.get(url, timeout=timeout)
    resp.raise_for_status()
    return resp.text