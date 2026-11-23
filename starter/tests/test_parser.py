import unittest
from datetime import timezone

from log_triage.parser import parse_line, parse_lines

from .helpers import log_line


class ParseLineTest(unittest.TestCase):
    def test_parses_all_fields(self):
        request = parse_line(log_line(ip="192.0.2.10", path="/cart", status=404, method="POST"))
        self.assertEqual(request.ip, "192.0.2.10")
        self.assertEqual(request.method, "POST")
        self.assertEqual(request.path, "/cart")
        self.assertEqual(request.protocol, "HTTP/1.1")
        self.assertEqual(request.status, 404)
        self.assertEqual(request.size, 512)
        self.assertEqual(request.referrer, "-")
        self.assertIn("Firefox", request.agent)

    def test_time_keeps_the_timezone(self):
        request = parse_line(log_line())
        self.assertEqual(request.time.tzinfo, timezone.utc)
        self.assertEqual(request.time.hour, 8)

    def test_dash_size_is_zero(self):
        line = '192.0.2.1 - - [22/Nov/2026:08:00:00 +0000] "GET / HTTP/1.1" 304 - "-" "curl/7.81.0"'
        self.assertEqual(parse_line(line).size, 0)

    def test_user_agent_with_parentheses_and_semicolons(self):
        agent = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
        self.assertEqual(parse_line(log_line(agent=agent)).agent, agent)

    def test_malformed_request_line_keeps_the_raw_text(self):
        line = '192.0.2.1 - - [22/Nov/2026:08:00:00 +0000] "garbage" 400 0 "-" "-"'
        request = parse_line(line)
        self.assertEqual(request.method, "")
        self.assertEqual(request.path, "garbage")

    def test_truncated_line_is_rejected(self):
        self.assertIsNone(parse_line('198.51.100.31 - - [22/Nov/2026:09:58:12 +0000] "GET /products/earl-gr'))

    def test_bad_timestamp_is_rejected(self):
        self.assertIsNone(parse_line(log_line(time="99/Nov/2026:08:00:00")))


class ParseLinesTest(unittest.TestCase):
    def test_counts_skipped_lines_and_ignores_blank_ones(self):
        requests, skipped = parse_lines([log_line(), "", "-", log_line(path="/cart"), "   \n"])
        self.assertEqual(len(requests), 2)
        self.assertEqual(skipped, 1)


if __name__ == "__main__":
    unittest.main()
