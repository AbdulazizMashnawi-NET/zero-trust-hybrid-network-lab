#!/usr/bin/env python3
"""Exam application - Team T01. Trusts only the verified identity
headers stamped by the PEP; it is never meant to be reached directly by a
user zone."""
import http.server, os
TEAM = "T01"
class App(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        u = self.headers.get("X-Verified-User", "?")
        r = self.headers.get("X-Verified-Role", "?")
        self.send_response(200); self.send_header("Content-Type","text/plain"); self.end_headers()
        self.wfile.write(f"[exam-app {TEAM}] served to {u}/{r} - records held on-prem\n".encode())
http.server.HTTPServer(("0.0.0.0", 80), App).serve_forever()
