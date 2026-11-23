"""Send a short alert to the store's on-call chat webhook.

The webhook URL and token come from the .env file. With no URL configured,
the alert is printed instead of sent.
"""

import json
import urllib.request
from pathlib import Path


class NotifyError(Exception):
    pass


def load_env(path=".env"):
    """Read KEY=VALUE lines. Blank lines and lines starting with # are ignored."""
    values = {}
    with Path(path).open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            values[key.strip()] = value
    return values


def mask(secret):
    """Show only enough of a secret to recognize it."""
    if len(secret) <= 8:
        return "****"
    return f"{secret[:3]}****{secret[-4:]}"


def post(url, token, message, timeout=10):
    if not url.startswith("https://"):
        raise NotifyError("ALERT_WEBHOOK_URL must use https://")
    body = json.dumps({"text": message}).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.status


def notify(message, env_path=".env", send=post):
    """Send the alert, or describe it when no webhook is configured. Returns a status line."""
    try:
        settings = load_env(env_path)
    except FileNotFoundError as error:
        raise NotifyError(f"{env_path} not found: copy .env.example to .env first") from error
    token = settings.get("ALERT_WEBHOOK_TOKEN", "")
    if not token:
        raise NotifyError("ALERT_WEBHOOK_TOKEN is not set in " + str(env_path))
    url = settings.get("ALERT_WEBHOOK_URL", "")
    if not url:
        return f"Alert webhook not configured; would send with token {mask(token)}: {message}"
    status = send(url, token, message)
    return f"Alert sent (HTTP {status}) with token {mask(token)}"
