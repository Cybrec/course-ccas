"""Detection rules for suspicious requests."""

import re
from collections import Counter
from dataclasses import dataclass
from urllib.parse import unquote_plus

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}

SQL_INJECTION_PATTERNS = [
    re.compile(r"'\s*or\s*'?\d*'?\s*=\s*'?\d*", re.IGNORECASE),
    re.compile(r"\bunion\b.+\bselect\b", re.IGNORECASE),
    re.compile(r"\b(sleep|benchmark)\s*\(", re.IGNORECASE),
    re.compile(r"'\s*;\s*(drop|delete|insert|update)\b", re.IGNORECASE),
]

TRAVERSAL_PATTERNS = [
    re.compile(r"\.\./"),
    re.compile(r"\.\.\\"),
    re.compile(r"/etc/(passwd|shadow)\b"),
]

# Paths this store doesn't have. Requests for them are someone probing for
# common software or leaked files.
PROBE_PATHS = (
    "/wp-login.php",
    "/wp-admin",
    "/xmlrpc.php",
    "/phpmyadmin",
    "/admin.php",
    "/.env",
    "/.git/",
    "/server-status",
    "/backup",
    "/db.sql",
)


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    request: object
    detail: str


def _decoded_path(request):
    return unquote_plus(request.path)


def check_request(request, signatures):
    """Return the findings for one request."""
    findings = []
    path = _decoded_path(request)

    for pattern in SQL_INJECTION_PATTERNS:
        if pattern.search(path):
            findings.append(Finding("sql-injection", "high", request, "SQL injection pattern in the URL"))
            break

    for pattern in TRAVERSAL_PATTERNS:
        if pattern.search(path):
            findings.append(Finding("path-traversal", "high", request, "path traversal attempt"))
            break

    lowered = path.lower()
    for probe in PROBE_PATHS:
        if lowered.startswith(probe):
            findings.append(Finding("probe", "medium", request, f"probe for {probe}"))
            break

    agent = request.agent.lower()
    for signature in signatures:
        if signature.pattern.lower() in agent:
            findings.append(Finding("scanner", "medium", request, f"known scanner: {signature.name}"))
            break

    return findings


def error_bursts(requests, threshold=20):
    """One finding per client with at least `threshold` 4xx responses."""
    counts = Counter(r.ip for r in requests if 400 <= r.status < 500)
    findings = []
    seen = set()
    for request in requests:
        if request.ip in seen or counts[request.ip] < threshold:
            continue
        if not 400 <= request.status < 500:
            continue
        seen.add(request.ip)
        findings.append(
            Finding("error-burst", "low", request, f"{counts[request.ip]} client errors from one address")
        )
    return findings


def find_all(requests, signatures, error_threshold=20):
    """Run every rule over the requests, highest severity first."""
    findings = []
    for request in requests:
        findings.extend(check_request(request, signatures))
    findings.extend(error_bursts(requests, error_threshold))
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.request.time))
    return findings
