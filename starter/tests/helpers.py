"""Shared test data."""

from log_triage.parser import parse_line

BROWSER = "Mozilla/5.0 (X11; Linux x86_64; rv:144.0) Gecko/20100101 Firefox/144.0"


def log_line(ip="198.51.100.7", path="/", status=200, agent=BROWSER, method="GET", time="22/Nov/2026:08:15:02"):
    return f'{ip} - - [{time} +0000] "{method} {path} HTTP/1.1" {status} 512 "-" "{agent}"'


def request(**kwargs):
    parsed = parse_line(log_line(**kwargs))
    assert parsed is not None
    return parsed
