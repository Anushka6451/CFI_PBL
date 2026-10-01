import json
import threading
import time
import unittest
import urllib.request
from http.server import ThreadingHTTPServer

from app import CaseHandler, load_case


class CyberTraceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), CaseHandler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.05)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def get(self, path):
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}{path}", timeout=3) as response:
            return response.status, response.read(), response.headers

    def test_home_page(self):
        status, body, _ = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn(b"Cyber Terrorism Case Study Investigation", body)

    def test_evidence_api(self):
        status, body, _ = self.get("/api/evidence")
        evidence = json.loads(body)
        self.assertEqual(status, 200)
        self.assertGreaterEqual(len(evidence), 8)
        self.assertEqual(evidence[0]["id"], "EV-001")

    def test_incident_dataset(self):
        case = load_case()
        self.assertEqual(case["case"]["id"], "CTI-UA-2015-DEMO")
        self.assertEqual(len(case["events"]), 10)


if __name__ == "__main__":
    unittest.main()
