import unittest

from log_triage.rules import check_request, error_bursts, find_all
from log_triage.signatures import Signature

from .helpers import request

SIGNATURES = [Signature("sqlmap", "sqlmap"), Signature("Nikto", "Nikto")]


def rules_for(req):
    return [f.rule for f in check_request(req, SIGNATURES)]


class CheckRequestTest(unittest.TestCase):
    def test_normal_request_has_no_findings(self):
        self.assertEqual(rules_for(request(path="/products/earl-grey")), [])

    def test_encoded_sql_injection(self):
        req = request(path="/products?id=1%27%20OR%20%271%27%3D%271")
        self.assertEqual(rules_for(req), ["sql-injection"])

    def test_union_select(self):
        self.assertIn("sql-injection", rules_for(request(path="/products?id=1%20UNION%20SELECT%20NULL--")))

    def test_sleep_call(self):
        self.assertIn("sql-injection", rules_for(request(path="/products?id=1%20AND%20SLEEP(5)")))

    def test_path_traversal_plain_and_encoded(self):
        self.assertIn("path-traversal", rules_for(request(path="/static/../../etc/passwd")))
        self.assertIn("path-traversal", rules_for(request(path="/images/..%2f..%2fetc%2fpasswd")))

    def test_probe_paths(self):
        for path in ("/wp-login.php", "/.env", "/.git/config", "/phpMyAdmin/"):
            with self.subTest(path=path):
                self.assertIn("probe", rules_for(request(path=path)))

    def test_known_scanner_is_matched_case_insensitively(self):
        findings = check_request(request(agent="Mozilla/5.00 (nikto/2.5.0)"), SIGNATURES)
        self.assertEqual([f.rule for f in findings], ["scanner"])
        self.assertIn("Nikto", findings[0].detail)

    def test_one_request_can_match_several_rules(self):
        req = request(path="/products?id=1%27%20OR%20%271%27%3D%271", agent="sqlmap/1.9.10")
        self.assertEqual(sorted(rules_for(req)), ["scanner", "sql-injection"])


class ErrorBurstTest(unittest.TestCase):
    def test_burst_at_threshold(self):
        requests = [request(ip="203.0.113.12", path=f"/x{n}", status=404) for n in range(5)]
        findings = error_bursts(requests, threshold=5)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].request.ip, "203.0.113.12")
        self.assertIn("5 client errors", findings[0].detail)

    def test_below_threshold(self):
        requests = [request(ip="203.0.113.12", status=404) for _ in range(4)]
        self.assertEqual(error_bursts(requests, threshold=5), [])

    def test_server_errors_do_not_count(self):
        requests = [request(ip="203.0.113.12", status=500) for _ in range(10)]
        self.assertEqual(error_bursts(requests, threshold=5), [])


class FindAllTest(unittest.TestCase):
    def test_highest_severity_first(self):
        requests = [
            request(path="/wp-login.php", time="22/Nov/2026:08:00:00"),
            request(path="/products?id=1%20UNION%20SELECT%201--", time="22/Nov/2026:09:00:00"),
        ]
        findings = find_all(requests, SIGNATURES)
        self.assertEqual([f.severity for f in findings], ["high", "medium"])


if __name__ == "__main__":
    unittest.main()
