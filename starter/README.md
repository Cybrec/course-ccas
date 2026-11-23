# log-triage

A small command-line tool that triages a web server's access logs for an online tea shop. It summarizes the day's traffic and flags requests that look like attacks: SQL injection, path traversal, probes for software the shop doesn't run, known scanners, and bursts of client errors from one address.

## Requirements

Python 3.10 or later. The standard library only, so there is nothing to install.

## Setup

Copy the example settings file before the first run:

```bash
cp .env.example .env
```

`.env` holds the on-call webhook settings that `notify` uses. Leave `ALERT_WEBHOOK_URL` empty to print alerts instead of sending them.

## Commands

```bash
python3 -m log_triage report logs/access-2026-11-22.log               # print a triage report
python3 -m log_triage report logs/access-2026-11-22.log --output reports/2026-11-22.txt
python3 -m log_triage findings logs/access-2026-11-22.log --min-severity high   # one finding per line; exit 1 if any
python3 -m log_triage notify logs/access-2026-11-22.log                # one-line alert to the on-call webhook
python3 -m log_triage update-signatures                                # download the latest scanner signatures
```

`report` and `findings` accept `--error-threshold N`: how many client errors (4xx) from one address count as a burst (default 20).

## Log format

The combined log format used by Apache and nginx:

```
198.51.100.7 - - [22/Nov/2026:08:15:02 +0000] "GET /cart HTTP/1.1" 200 5120 "-" "Mozilla/5.0 ..."
```

Lines that can't be parsed are skipped and counted in the report.

## Files

| Path | What it is |
|---|---|
| `log_triage/` | The package: `parser.py`, `rules.py`, `signatures.py`, `report.py`, `notify.py`, `cli.py` |
| `data/scanner-signatures.json` | User-Agent patterns of known scanners |
| `logs/` | Access logs to triage |
| `docs/RELEASE.md` | Release checklist |
| `scripts/deploy.sh` | Runs the tests, then publishes `main` to the `production` branch |
| `tests/` | Unit tests: `python3 -m unittest` |
