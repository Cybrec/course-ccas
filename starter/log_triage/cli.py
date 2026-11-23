"""Command-line interface: python3 -m log_triage <command> ..."""

import argparse
import sys
from pathlib import Path

from . import __version__
from .notify import NotifyError, notify
from .parser import read_log
from .report import one_line_summary, render_text
from .rules import SEVERITY_ORDER, find_all
from .signatures import DEFAULT_URL, SignatureError, load_signatures, update_signatures


def _analyze(log_path, error_threshold):
    requests, skipped = read_log(log_path)
    findings = find_all(requests, load_signatures(), error_threshold)
    return requests, skipped, findings


def cmd_report(args):
    requests, skipped, findings = _analyze(args.log, args.error_threshold)
    text = render_text(args.log, requests, skipped, findings)
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
        print(f"Report written to {output}")
    else:
        sys.stdout.write(text)
    return 0


def cmd_findings(args):
    _, _, findings = _analyze(args.log, args.error_threshold)
    limit = SEVERITY_ORDER[args.min_severity]
    selected = [f for f in findings if SEVERITY_ORDER[f.severity] <= limit]
    for finding in selected:
        request = finding.request
        print(
            "\t".join(
                [
                    finding.severity,
                    finding.rule,
                    request.ip,
                    request.time.isoformat(),
                    f"{request.method} {request.path}",
                    str(request.status),
                ]
            )
        )
    return 1 if selected else 0


def cmd_update_signatures(args):
    old_count, new_count, version = update_signatures(args.url)
    print(f"Signatures updated to version {version}: {old_count} -> {new_count}")
    return 0


def cmd_notify(args):
    _, _, findings = _analyze(args.log, args.error_threshold)
    print(notify(one_line_summary(args.log, findings), env_path=args.env_file))
    return 0


def build_parser():
    parser = argparse.ArgumentParser(prog="log_triage", description="Triage web server access logs.")
    parser.add_argument("--version", action="version", version=f"log-triage {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    def add_log_arguments(sub):
        sub.add_argument("log", help="access log in combined log format")
        sub.add_argument(
            "--error-threshold",
            type=int,
            default=20,
            help="client errors from one address that count as a burst (default 20)",
        )

    report = commands.add_parser("report", help="print a triage report")
    add_log_arguments(report)
    report.add_argument("--output", help="write the report to this file instead of printing it")
    report.set_defaults(handler=cmd_report)

    findings = commands.add_parser("findings", help="list findings, one per line; exit 1 if any")
    add_log_arguments(findings)
    findings.add_argument("--min-severity", choices=list(SEVERITY_ORDER), default="low")
    findings.set_defaults(handler=cmd_findings)

    update = commands.add_parser("update-signatures", help="download the latest scanner signatures")
    update.add_argument("--url", default=DEFAULT_URL, help="signature file URL (https only)")
    update.set_defaults(handler=cmd_update_signatures)

    alert = commands.add_parser("notify", help="send a one-line alert to the on-call webhook")
    add_log_arguments(alert)
    alert.add_argument("--env-file", default=".env", help="file with the webhook settings (default .env)")
    alert.set_defaults(handler=cmd_notify)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.handler(args)
    except FileNotFoundError as error:
        print(f"error: file not found: {error.filename}", file=sys.stderr)
    except (SignatureError, NotifyError) as error:
        print(f"error: {error}", file=sys.stderr)
    except OSError as error:
        print(f"error: {error}", file=sys.stderr)
    return 2
