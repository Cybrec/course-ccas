import unittest

from log_triage.report import group_findings, one_line_summary, rare_agents, render_text, summarize
from log_triage.rules import find_all
from log_triage.signatures import Signature

from .helpers import request

SIGNATURES = [Signature("Nikto", "Nikto")]


def sample():
    return [
        request(ip="198.51.100.7", path="/", time="22/Nov/2026:08:00:00"),
        request(ip="198.51.100.7", path="/cart", time="22/Nov/2026:08:01:00"),
        request(ip="203.0.113.80", path="/wp-login.php", status=404, agent="Nikto/2.5.0", time="22/Nov/2026:08:02:00"),
        request(ip="203.0.113.80", path="/.env", status=404, agent="Nikto/2.5.0", time="22/Nov/2026:08:03:00"),
        request(ip="192.0.2.50", path="/health", agent="curl/7.81.0", time="22/Nov/2026:08:04:00"),
    ]


class SummaryTest(unittest.TestCase):
    def test_counts(self):
        summary = summarize(sample())
        self.assertEqual(summary["total"], 5)
        self.assertEqual(summary["clients"], 3)
        self.assertEqual(summary["statuses"], {"2xx": 3, "3xx": 0, "4xx": 2, "5xx": 0})
        self.assertEqual(summary["top_clients"][0], ("198.51.100.7", 2))

    def test_empty_log(self):
        summary = summarize([])
        self.assertEqual(summary["total"], 0)
        self.assertIsNone(summary["first"])

    def test_rare_agents_are_the_ones_seen_once(self):
        self.assertEqual([r.agent for r in rare_agents(sample())], ["curl/7.81.0"])


class RenderTest(unittest.TestCase):
    def test_findings_are_grouped_per_client(self):
        groups = group_findings(find_all(sample(), SIGNATURES))
        scanner = [g for g in groups if g[1] == "scanner"]
        self.assertEqual(len(scanner), 1)
        self.assertEqual(scanner[0][3], 2)

    def test_text_report_sections(self):
        requests = sample()
        text = render_text("access.log", requests, 1, find_all(requests, SIGNATURES))
        for heading in ("Requests: 5 (1 line skipped)", "Top clients", "Top paths", "Findings: 4", "Rare user agents"):
            with self.subTest(heading=heading):
                self.assertIn(heading, text)

    def test_one_line_summary(self):
        line = one_line_summary("access.log", find_all(sample(), SIGNATURES))
        self.assertEqual(line, "log-triage: 4 findings in access.log (0 high, 4 medium, 0 low)")


if __name__ == "__main__":
    unittest.main()
