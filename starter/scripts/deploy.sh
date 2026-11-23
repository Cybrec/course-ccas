#!/usr/bin/env bash
# Deploy log-triage: run the tests, then publish main to the production branch.
set -euo pipefail

cd "$(dirname "$0")/.."
python3 -m unittest -q
git push origin main:production
echo "Deployed main to production."
