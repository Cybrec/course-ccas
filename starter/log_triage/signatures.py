"""Signatures of known scanners, matched against the User-Agent header."""

import json
import os
import tempfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path

DEFAULT_PATH = Path(__file__).resolve().parent.parent / "data" / "scanner-signatures.json"
DEFAULT_URL = "https://raw.githubusercontent.com/Cybrec/course-ccas/main/signatures/scanner-signatures.json"
MAX_BYTES = 100_000


class SignatureError(Exception):
    pass


@dataclass(frozen=True)
class Signature:
    name: str
    pattern: str


def validate(data):
    """Check the signature file structure. Returns (version, signatures)."""
    if not isinstance(data, dict):
        raise SignatureError("signature file must be a JSON object")
    version = data.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise SignatureError("'version' must be a positive integer")
    items = data.get("signatures")
    if not isinstance(items, list) or not items:
        raise SignatureError("'signatures' must be a non-empty list")
    signatures = []
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise SignatureError(f"signature {index} must be an object")
        name = item.get("name")
        pattern = item.get("pattern")
        if not isinstance(name, str) or not name.strip():
            raise SignatureError(f"signature {index} needs a non-empty 'name'")
        if not isinstance(pattern, str) or len(pattern.strip()) < 3:
            raise SignatureError(f"signature {index} needs a 'pattern' of at least 3 characters")
        signatures.append(Signature(name.strip(), pattern.strip()))
    return version, signatures


def load_signatures(path=DEFAULT_PATH):
    with Path(path).open(encoding="utf-8") as handle:
        return validate(json.load(handle))[1]


def fetch(url, timeout=60):
    """Download a signature file over HTTPS."""
    if not url.startswith("https://"):
        raise SignatureError("signature updates must use https://")
    with urllib.request.urlopen(url, timeout=timeout) as response:
        body = response.read(MAX_BYTES + 1)
    if len(body) > MAX_BYTES:
        raise SignatureError("signature file is too large")
    return body


def update_signatures(url=DEFAULT_URL, path=DEFAULT_PATH, fetch=fetch):
    """Replace the local signature file with a newer one.

    The download is validated before anything is written. Returns
    (old_count, new_count, version).
    """
    path = Path(path)
    try:
        data = json.loads(fetch(url).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SignatureError(f"downloaded file is not valid JSON: {error}") from error
    version, signatures = validate(data)
    old_count = len(load_signatures(path)) if path.exists() else 0

    fd, temp_name = tempfile.mkstemp(dir=path.parent, prefix=".signatures-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)
            handle.write("\n")
        os.replace(temp_name, path)
    except BaseException:
        if os.path.exists(temp_name):
            os.remove(temp_name)
        raise
    return old_count, len(signatures), version
