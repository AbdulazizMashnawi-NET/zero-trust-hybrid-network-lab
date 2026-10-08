#!/usr/bin/env python3
"""Mock Identity Provider - Team T01.
Issues signed access tokens the PEP can verify. This models the IdP box in a
Zero Trust design: it authenticates the subject and states role + device
posture as signed claims. Get a token:

    curl "http://10.145.50.11:8081/token?user=sara&role=student&device=managed"

Then present it to the PEP:

    curl -k --resolve exam.engineering.t01.uni.lab:10443:10.145.50.10 \
         -H "Authorization: Bearer <token>" \
         https://exam.engineering.t01.uni.lab:10443/exam
"""
import http.server, hmac, hashlib, os, urllib.parse

SECRET = b"idp-pep-shared-secret-T01"
TEAM = "T01"

class IdP(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        q = urllib.parse.urlparse(self.path)
        if not q.path.startswith("/token"):
            self.send_response(404); self.end_headers(); return
        args = urllib.parse.parse_qs(q.query)
        user = args.get("user", ["anon"])[0]
        role = args.get("role", ["student"])[0]
        device = args.get("device", ["unmanaged"])[0]
        body = f"{user}|{role}|{device}".encode()
        sig = hmac.new(SECRET, body, hashlib.sha256).hexdigest()
        token = f"{user}|{role}|{device}|{sig}"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain"); self.end_headers()
        self.wfile.write((token + "\n").encode())

http.server.HTTPServer(("0.0.0.0", 8081), IdP).serve_forever()
