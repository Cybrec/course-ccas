"""Parse web server access logs in the combined log format.

A line looks like this:

    198.51.100.7 - - [22/Nov/2026:08:15:02 +0000] "GET /cart HTTP/1.1" 200 5120 "-" "Mozilla/5.0 ..."
"""

import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

LINE_RE = re.compile(
    r'(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] '
    r'"(?P<request>[^"]*)" (?P<status>\d{3}) (?P<size>\d+|-) '
    r'"(?P<referrer>[^"]*)" "(?P<agent>[^"]*)"$'
)
TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


@dataclass(frozen=True)
class Request:
    ip: str
    time: datetime
    method: str
    path: str
    protocol: str
    status: int
    size: int
    referrer: str
    agent: str


def parse_line(line):
    """Return a Request for one log line, or None if the line can't be parsed."""
    match = LINE_RE.match(line.rstrip("\r\n"))
    if match is None:
        return None
    try:
        time = datetime.strptime(match["time"], TIME_FORMAT)
    except ValueError:
        return None
    parts = match["request"].split(" ")
    if len(parts) == 3:
        method, path, protocol = parts
    else:
        method, path, protocol = "", match["request"], ""
    size = 0 if match["size"] == "-" else int(match["size"])
    return Request(
        ip=match["ip"],
        time=time,
        method=method,
        path=path,
        protocol=protocol,
        status=int(match["status"]),
        size=size,
        referrer=match["referrer"],
        agent=match["agent"],
    )


def parse_lines(lines):
    """Parse an iterable of lines. Returns (requests, skipped_line_count)."""
    requests = []
    skipped = 0
    for line in lines:
        if not line.strip():
            continue
        request = parse_line(line)
        if request is None:
            skipped += 1
        else:
            requests.append(request)
    return requests, skipped


def read_log(path):
    """Read and parse a log file. Returns (requests, skipped_line_count)."""
    with Path(path).open(encoding="utf-8", errors="replace") as handle:
        return parse_lines(handle)
