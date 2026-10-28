"""Local web server and PBKDF2 password-hashing demonstration."""

import hashlib
import json
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parent
HOST = "127.0.0.1"
PORT = 8000
PBKDF2_ITERATIONS = 600_000
SALT_LENGTH = 16
MAX_REQUEST_BYTES = 8192
MAX_PASSWORD_BYTES = 1024


def hash_password(password):
    """Return a fresh salt and PBKDF2-HMAC-SHA256 digest for a demo password."""
    if not isinstance(password, str) or not password:
        raise ValueError("Enter a password before creating a hash.")
    password_bytes = password.encode("utf-8")
    if len(password_bytes) > MAX_PASSWORD_BYTES:
        raise ValueError("The password must be no more than 1,024 UTF-8 bytes.")
    salt = secrets.token_bytes(SALT_LENGTH)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password_bytes, salt, PBKDF2_ITERATIONS, dklen=32
    )
    return {
        "algorithm": "PBKDF2-HMAC-SHA256",
        "iterations": PBKDF2_ITERATIONS,
        "salt": salt.hex(),
        "hash": digest.hex(),
    }


class AnalyzerHandler(BaseHTTPRequestHandler):
    server_version = "PasswiseLocal/1.0"

    def _send_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if urlsplit(self.path).path != "/api/hash":
            self._send_json(404, {"error": "API endpoint not found."})
            return
        if self.headers.get_content_type() != "application/json":
            self._send_json(400, {"error": "Content-Type must be application/json."})
            return

        content_length = self.headers.get("Content-Length")
        try:
            length = int(content_length) if content_length is not None else -1
        except ValueError:
            length = -1
        if length < 0 or length > MAX_REQUEST_BYTES:
            self._send_json(400, {"error": "Invalid or oversized request."})
            return

        try:
            request = json.loads(self.rfile.read(length))
            password = request.get("password") if isinstance(request, dict) else None
            result = hash_password(password)
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send_json(400, {"error": "Request must contain valid JSON."})
            return
        except ValueError as error:
            self._send_json(400, {"error": str(error)})
            return
        self._send_json(200, result)

    def do_GET(self):
        self._serve_static()

    def do_HEAD(self):
        self._serve_static(head_only=True)

    def _serve_static(self, head_only=False):
        request_path = unquote(urlsplit(self.path).path)
        relative_path = request_path.lstrip("/") or "index.html"
        if any(part in (".", "..") for part in Path(relative_path).parts):
            self.send_error(404)
            return

        target = (ROOT / relative_path).resolve()
        try:
            target.relative_to(ROOT)
        except ValueError:
            self.send_error(404)
            return
        if not target.is_file():
            self.send_error(404)
            return

        content_types = {
            ".css": "text/css; charset=utf-8",
            ".html": "text/html; charset=utf-8",
            ".js": "text/javascript; charset=utf-8",
        }
        try:
            body = target.read_bytes()
        except OSError:
            self.send_error(500)
            return
        self.send_response(200)
        self.send_header(
            "Content-Type",
            content_types.get(target.suffix.lower(), "application/octet-stream"),
        )
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self' 'unsafe-inline'; "
            "font-src 'self'; script-src 'self'; connect-src 'self'; "
            "object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        )
        self.end_headers()
        if not head_only:
            self.wfile.write(body)


def main():
    server = ThreadingHTTPServer((HOST, PORT), AnalyzerHandler)
    print(f"Password Security Analyzer is running at http://{HOST}:{PORT}")
    print("Press Ctrl+C to stop the server.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
