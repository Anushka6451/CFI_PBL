from __future__ import annotations

import os
import json
import mimetypes
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

BASE_DIR = Path(__file__).resolve().parent
DATA_FILE = BASE_DIR / "data" / "incident.json"
HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", 10000))


def load_case() -> dict:
    with DATA_FILE.open("r", encoding="utf-8") as fh:
        return json.load(fh)


class CaseHandler(BaseHTTPRequestHandler):
    server_version = "CyberTraceLab/1.0"

    def log_message(self, fmt, *args):
        print(f"[CyberTrace] {self.address_string()} - {fmt % args}")

    def _send_bytes(self, data: bytes, content_type: str, status=HTTPStatus.OK, extra_headers=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        if extra_headers:
            for key, value in extra_headers.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def _send_json(self, payload, status=HTTPStatus.OK, download_name=None):
        data = json.dumps(payload, indent=2).encode("utf-8")
        headers = {}
        if download_name:
            headers["Content-Disposition"] = f'attachment; filename="{download_name}"'
        self._send_bytes(data, "application/json; charset=utf-8", status, headers)

    def _serve_file(self, path: Path):
        try:
            path = path.resolve(strict=True)
        except FileNotFoundError:
            self.send_error(HTTPStatus.NOT_FOUND, "File not found")
            return

        if BASE_DIR not in path.parents and path != BASE_DIR:
            self.send_error(HTTPStatus.FORBIDDEN, "Forbidden")
            return
        if not path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND, "File not found")
            return

        content_type, _ = mimetypes.guess_type(path.name)
        content_type = content_type or "application/octet-stream"
        if content_type.startswith("text/") or content_type in {"application/javascript", "application/json"}:
            content_type += "; charset=utf-8"
        self._send_bytes(path.read_bytes(), content_type)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/":
            return self._serve_file(BASE_DIR / "templates" / "index.html")

        if path.startswith("/static/"):
            rel = path.removeprefix("/static/")
            return self._serve_file(BASE_DIR / "static" / rel)

        case = load_case()
        if path == "/api/incident":
            return self._send_json({
                "case": case["case"],
                "historical_context": case["historical_context"],
                "attack_path": case["attack_path"],
                "sources": case["sources"],
            })

        if path == "/api/evidence":
            return self._send_json(case["evidence"])

        if path == "/api/export-case":
            return self._send_json(case, download_name="ukraine_2015_forensic_case_export.json")

        if path == "/api/stream":
            try:
                speed = float(query.get("speed", ["1"])[0])
            except ValueError:
                speed = 1.0
            speed = max(0.5, min(speed, 5.0))
            return self._stream_events(case, speed)

        self.send_error(HTTPStatus.NOT_FOUND, "Not found")

    def _stream_events(self, case: dict, speed: float):
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()

        try:
            self.wfile.write(b'event: ready\ndata: {"message":"simulation-ready"}\n\n')
            self.wfile.flush()
            for event in case["events"]:
                delay = max(0.15, float(event.get("delay", 1.0)) / speed)
                time.sleep(delay)
                payload = json.dumps(event, separators=(",", ":"))
                self.wfile.write(f"event: incident\ndata: {payload}\n\n".encode("utf-8"))
                self.wfile.flush()
            self.wfile.write(b'event: complete\ndata: {"message":"simulation-complete"}\n\n')
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass


def run(host: str = HOST, port: int = PORT):
    server = ThreadingHTTPServer((host, port), CaseHandler)
    print(f"CyberTrace Lab running at http://{host}:{port}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping CyberTrace Lab...")
    finally:
        server.server_close()


if __name__ == "__main__":
    run()
