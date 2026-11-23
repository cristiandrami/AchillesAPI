"""Loopback-only callback observer for RC15 SSRF/XXE tests.

Expose /callback/ via an explicitly configured reverse proxy or port-forward
when the API target is not local. /observed/ is an *untrusted* local test
observation unless the callback receiver is independently controlled.
"""
from __future__ import annotations

import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

TOKEN = re.compile(r'^[0-9a-f]{32}$')


class RC15Collector:
    def __init__(self, host: str = '127.0.0.1', port: int = 8788):
        if host != '127.0.0.1' or not 1024 <= port <= 65535:
            raise ValueError('Collector must bind to 127.0.0.1 and an unprivileged port')
        self.tokens: set[str] = set()
        self.lock = threading.Lock()
        parent = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                parts = urlsplit(self.path)
                path = parts.path
                payload = b''
                code = 404
                if not parts.query and not parts.fragment:
                    if path.startswith('/callback/') and TOKEN.fullmatch(path.removeprefix('/callback/')):
                        with parent.lock:
                            if len(parent.tokens) < 10000:
                                parent.tokens.add(path.removeprefix('/callback/'))
                                code = 204
                            else:
                                code = 429
                    elif path.startswith('/observed/') and TOKEN.fullmatch(path.removeprefix('/observed/')):
                        with parent.lock:
                            found = path.removeprefix('/observed/') in parent.tokens
                        payload = b'true' if found else b'false'
                        code = 200
                self.send_response(code)
                self.send_header('Content-Type', 'text/plain')
                self.send_header('Content-Length', str(len(payload)))
                self.send_header('Cache-Control', 'no-store')
                self.end_headers()
                if payload:
                    self.wfile.write(payload)

            def log_message(self, format, *args):
                pass  # never record source IP, URL or metadata

        self.server = ThreadingHTTPServer((host, port), Handler)
        self.server.daemon_threads = True

    def serve(self) -> None:
        self.server.serve_forever()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def seen(self, token: str) -> bool:
        with self.lock:
            return token in self.tokens
