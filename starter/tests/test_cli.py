import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from log_triage.cli import main

from .helpers import log_line


def run(*args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(args))
    return code, out.getvalue(), err.getvalue()


class CliTest(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.log = Path(self.folder.name) / "access.log"

    def tearDown(self):
        self.folder.cleanup()

    def write_log(self, *lines):
        self.log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def test_report_prints_and_exits_zero(self):
        self.write_log(log_line(), log_line(path="/wp-login.php", status=404))
        code, out, _ = run("report", str(self.log))
        self.assertEqual(code, 0)
        self.assertIn("Requests: 2", out)
        self.assertIn("probe", out)

    def test_report_to_file(self):
        self.write_log(log_line())
        target = Path(self.folder.name) / "reports" / "today.txt"
        code, out, _ = run("report", str(self.log), "--output", str(target))
        self.assertEqual(code, 0)
        self.assertTrue(target.exists())
        self.assertIn("Report written", out)

    def test_findings_exit_code(self):
        self.write_log(log_line())
        self.assertEqual(run("findings", str(self.log))[0], 0)
        self.write_log(log_line(path="/products?id=1%20UNION%20SELECT%201--"))
        code, out, _ = run("findings", str(self.log), "--min-severity", "high")
        self.assertEqual(code, 1)
        self.assertTrue(out.startswith("high\tsql-injection\t"))

    def test_missing_log(self):
        code, _, err = run("report", str(Path(self.folder.name) / "nope.log"))
        self.assertEqual(code, 2)
        self.assertIn("file not found", err)

    def test_update_refuses_plain_http(self):
        code, _, err = run("update-signatures", "--url", "http://example.test/s.json")
        self.assertEqual(code, 2)
        self.assertIn("https", err)

    def test_bundled_sample_log(self):
        sample = Path(__file__).resolve().parent.parent / "logs" / "access-2026-11-22.log"
        code, out, _ = run("report", str(sample))
        self.assertEqual(code, 0)
        self.assertIn("(2 lines skipped)", out)
        self.assertIn("sql-injection", out)


if __name__ == "__main__":
    unittest.main()
