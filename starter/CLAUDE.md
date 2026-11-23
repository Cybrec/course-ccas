# log-triage

Command-line tool that triages a web server's access logs (combined log format) for a small online tea shop. See README.md for the commands.

- Python 3.10, standard library only. Don't add third-party packages.
- Run the tool: `python3 -m log_triage report logs/access-2026-11-22.log`
- Run the tests: `python3 -m unittest`
- Scanner signatures are in `data/scanner-signatures.json`; refresh them with `python3 -m log_triage update-signatures`.
- Alert settings come from `.env` (copied from `.env.example`). Never commit `.env`.
- Deploy with `scripts/deploy.sh`: it runs the tests and publishes `main` to the `production` branch.
- Keep changes focused, and add or update tests with every change.
