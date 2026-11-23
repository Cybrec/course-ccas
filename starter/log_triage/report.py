"""Build the triage report."""

from collections import Counter, OrderedDict

from .rules import SEVERITY_ORDER


def summarize(requests):
    statuses = Counter(f"{r.status // 100}xx" for r in requests)
    return {
        "total": len(requests),
        "clients": len({r.ip for r in requests}),
        "first": min((r.time for r in requests), default=None),
        "last": max((r.time for r in requests), default=None),
        "statuses": {key: statuses.get(key, 0) for key in ("2xx", "3xx", "4xx", "5xx")},
        "top_clients": Counter(r.ip for r in requests).most_common(5),
        "top_paths": Counter(r.path for r in requests if r.status < 400).most_common(5),
    }


def rare_agents(requests, limit=10):
    """User agents seen exactly once, in the order they appear."""
    counts = Counter(r.agent for r in requests)
    rare = []
    for request in requests:
        if counts[request.agent] == 1:
            rare.append(request)
            if len(rare) == limit:
                break
    return rare


def group_findings(findings):
    """Group findings by severity, rule, and client address.

    Returns a list of (severity, rule, ip, count, first_finding).
    """
    groups = OrderedDict()
    for finding in findings:
        key = (finding.severity, finding.rule, finding.request.ip)
        if key in groups:
            count, first = groups[key]
            groups[key] = (count + 1, first)
        else:
            groups[key] = (1, finding)
    rows = [(sev, rule, ip, count, first) for (sev, rule, ip), (count, first) in groups.items()]
    rows.sort(key=lambda row: (SEVERITY_ORDER[row[0]], row[1], row[2]))
    return rows


def _format_time(value):
    return value.strftime("%Y-%m-%d %H:%M:%S %z") if value else "-"


def render_text(log_name, requests, skipped, findings):
    summary = summarize(requests)
    lines = [f"Access log triage: {log_name}"]
    skipped_note = f" ({skipped} {'line' if skipped == 1 else 'lines'} skipped)" if skipped else ""
    lines.append(f"Requests: {summary['total']}{skipped_note}")
    lines.append(f"Period: {_format_time(summary['first'])} to {_format_time(summary['last'])}")
    lines.append(f"Unique clients: {summary['clients']}")
    lines.append("Status codes: " + ", ".join(f"{k} {v}" for k, v in summary["statuses"].items()))

    lines.append("")
    lines.append("Top clients")
    for ip, count in summary["top_clients"]:
        lines.append(f"  {ip:<16} {count} requests")

    lines.append("")
    lines.append("Top paths")
    for path, count in summary["top_paths"]:
        lines.append(f"  {count:>5}  {path}")

    severities = Counter(f.severity for f in findings)
    lines.append("")
    lines.append(
        f"Findings: {len(findings)} ({severities['high']} high, "
        f"{severities['medium']} medium, {severities['low']} low)"
    )
    for severity, rule, ip, count, first in group_findings(findings):
        request = first.request
        times = f" x{count}" if count > 1 else ""
        lines.append(f"  {severity.upper():<7} {rule:<15} {ip:<16}{times}")
        lines.append(f"          {first.detail}; first: {request.method} {request.path} -> {request.status}")

    rare = rare_agents(requests)
    lines.append("")
    lines.append("Rare user agents (seen once)")
    if not rare:
        lines.append("  none")
    for request in rare:
        lines.append(f"  {request.ip:<16} {request.agent}")

    return "\n".join(lines) + "\n"


def one_line_summary(log_name, findings):
    severities = Counter(f.severity for f in findings)
    return (
        f"log-triage: {len(findings)} findings in {log_name} "
        f"({severities['high']} high, {severities['medium']} medium, {severities['low']} low)"
    )
