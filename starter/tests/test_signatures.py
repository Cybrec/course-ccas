import json
import tempfile
import unittest
from pathlib import Path

from log_triage.signatures import (
    DEFAULT_PATH,
    SignatureError,
    fetch,
    load_signatures,
    update_signatures,
    validate,
)

NEWER = {"version": 2, "signatures": [{"name": "sqlmap", "pattern": "sqlmap"}, {"name": "Nikto", "pattern": "Nikto"}]}


class SignatureFileTest(unittest.TestCase):
    def test_bundled_file_loads(self):
        signatures = load_signatures(DEFAULT_PATH)
        self.assertGreaterEqual(len(signatures), 5)
        self.assertIn("sqlmap", [s.name for s in signatures])

    def test_validate_rejects_bad_shapes(self):
        bad = [
            [],
            {"version": 1},
            {"version": 0, "signatures": [{"name": "a", "pattern": "abc"}]},
            {"version": True, "signatures": [{"name": "a", "pattern": "abc"}]},
            {"version": 1, "signatures": []},
            {"version": 1, "signatures": ["sqlmap"]},
            {"version": 1, "signatures": [{"name": "", "pattern": "abc"}]},
            {"version": 1, "signatures": [{"name": "a", "pattern": "ab"}]},
        ]
        for data in bad:
            with self.subTest(data=data):
                with self.assertRaises(SignatureError):
                    validate(data)


class UpdateTest(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.path = Path(self.folder.name) / "scanner-signatures.json"
        self.path.write_text(json.dumps({"version": 1, "signatures": [{"name": "a", "pattern": "abc"}]}))

    def tearDown(self):
        self.folder.cleanup()

    def test_update_replaces_the_file(self):
        result = update_signatures("https://example.test/s.json", self.path, fetch=lambda url: json.dumps(NEWER).encode())
        self.assertEqual(result, (1, 2, 2))
        self.assertEqual(len(load_signatures(self.path)), 2)

    def test_invalid_download_leaves_the_file_alone(self):
        before = self.path.read_text()
        for body in (b"not json", json.dumps({"version": 2, "signatures": []}).encode()):
            with self.subTest(body=body):
                with self.assertRaises(SignatureError):
                    update_signatures("https://example.test/s.json", self.path, fetch=lambda url: body)
                self.assertEqual(self.path.read_text(), before)
        self.assertEqual([p.name for p in Path(self.folder.name).iterdir()], [self.path.name])

    def test_fetch_requires_https(self):
        with self.assertRaises(SignatureError):
            fetch("http://example.test/s.json")


if __name__ == "__main__":
    unittest.main()
