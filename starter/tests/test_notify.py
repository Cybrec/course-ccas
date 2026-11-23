import tempfile
import unittest
from pathlib import Path

from log_triage.notify import NotifyError, load_env, mask, notify

TOKEN = "lt_test_0123456789abcdef"


class NotifyTest(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.env = Path(self.folder.name) / ".env"

    def tearDown(self):
        self.folder.cleanup()

    def write_env(self, text):
        self.env.write_text(text, encoding="utf-8")

    def test_load_env_skips_comments_and_strips_quotes(self):
        self.write_env('# comment\n\nALERT_WEBHOOK_URL=\nALERT_WEBHOOK_TOKEN="abc def"\nBROKEN LINE\n')
        self.assertEqual(load_env(self.env), {"ALERT_WEBHOOK_URL": "", "ALERT_WEBHOOK_TOKEN": "abc def"})

    def test_mask(self):
        self.assertEqual(mask(TOKEN), "lt_****cdef")
        self.assertEqual(mask("short"), "****")

    def test_without_url_the_alert_is_printed_and_the_token_masked(self):
        self.write_env(f"ALERT_WEBHOOK_URL=\nALERT_WEBHOOK_TOKEN={TOKEN}\n")
        result = notify("3 findings", env_path=self.env, send=self.fail_if_called)
        self.assertIn("not configured", result)
        self.assertIn("lt_****cdef", result)
        self.assertNotIn(TOKEN, result)

    def test_with_url_the_alert_is_sent(self):
        self.write_env(f"ALERT_WEBHOOK_URL=https://hooks.example.test/x\nALERT_WEBHOOK_TOKEN={TOKEN}\n")
        sent = []
        result = notify("3 findings", env_path=self.env, send=lambda url, token, msg: sent.append((url, token, msg)) or 200)
        self.assertEqual(sent, [("https://hooks.example.test/x", TOKEN, "3 findings")])
        self.assertNotIn(TOKEN, result)

    def test_missing_token(self):
        self.write_env("ALERT_WEBHOOK_URL=\n")
        with self.assertRaises(NotifyError):
            notify("x", env_path=self.env)

    def test_missing_env_file(self):
        with self.assertRaises(NotifyError):
            notify("x", env_path=Path(self.folder.name) / "missing.env")

    def fail_if_called(self, *args):
        self.fail("nothing should be sent without a URL")


if __name__ == "__main__":
    unittest.main()
