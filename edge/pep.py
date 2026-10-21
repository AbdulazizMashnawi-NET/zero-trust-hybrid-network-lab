#!/usr/bin/env python3
"""
Policy Enforcement Point (PEP) for the exam service - Team T01.

This sits in the DMZ. Every user request for the exam application passes
through here. The PEP is supposed to make a Zero Trust access decision on
EVERY request using the token issued by the Identity Provider (IdP) - never
by trusting the user's network location or anything the client simply claims.

The four policy switches below are what your team must get right. Read them,
test them with curl, and fix the ones that are wrong. After editing:
    docker compose restart pep
"""
import http.server, socketserver, ssl, urllib.request, urllib.parse, hmac, hashlib, os, json
TEAM        = os.environ.get("TEAM", "T01")
EXAM_FQDN   = "exam.engineering.t01.uni.lab"
IDP_URL     = "http://10.145.50.11:8081"
UPSTREAM    = "http://10.145.20.10:80"
HTTPS_PORT  = 10443
SHARED_SECRET = b"idp-pep-shared-secret-T01"

# ---------------------------------------------------------------------------
# POLICY SWITCHES  - decide, with evidence, what each one should be.
# ---------------------------------------------------------------------------
TLS_MIN_VERSION        = ssl.TLSVersion.TLSv1_2   # lowest TLS version the PEP accepts
TLS_CIPHERS            = "DEFAULT"   # OpenSSL cipher string / security level
TRUST_CLIENT_HEADERS   = False   # accept identity headers (X-User/X-Role/X-Device) from the client if no token?
REQUIRE_DEVICE_POSTURE = True   # require the token's device claim to be 'managed'?
EXPOSE_ADMIN_PATHS     = False  # route /admin and /metrics through this PEP?
# ---------------------------------------------------------------------------


def verify_token(token: str):
    """IdP tokens are 'user|role|device|sig' where sig = HMAC(secret, user|role|device)."""
    try:
        user, role, device, sig = token.split("|", 3)
    except ValueError:
        return None
    body = f"{user}|{role}|{device}".encode()
    good = hmac.new(SHARED_SECRET, body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(good, sig):
        return None
    return {"user": user, "role": role, "device": device}


class PEP(http.server.BaseHTTPRequestHandler):
    server_version = f"CampusPEP/{TEAM}"

    def _deny(self, code, msg):
        self._reply(code, f"[PEP {TEAM}] DENY: {msg}\n".encode())

    def _reply(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # Path policy -------------------------------------------------------
        if urllib.parse.unquote(self.path).lower().startswith(("/admin", "/metrics")) and not EXPOSE_ADMIN_PATHS:
            return self._deny(404, "path not available through student-facing PEP")

        # Identity ----------------------------------------------------------
        ident = None
        token = self.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        if token:
            ident = verify_token(token)
        if ident is None and TRUST_CLIENT_HEADERS:
            # Fallback: identity taken from request headers.
            u = self.headers.get("X-User"); r = self.headers.get("X-Role")
            if u and r:
                ident = {"user": u, "role": r,
                         "device": self.headers.get("X-Device", "unknown")}
        if ident is None:
            return self._deny(401, "no valid IdP token")

        # Device posture ----------------------------------------------------
        if REQUIRE_DEVICE_POSTURE and ident.get("device", "") != "managed":
            return self._deny(403, f"device posture '{ident.get('device')}' not permitted")

        # Allowed -> proxy upstream ----------------------------------------
        try:
            req = urllib.request.Request(UPSTREAM + self.path)
            req.add_header("X-Verified-User", ident["user"])
            req.add_header("X-Verified-Role", ident["role"])
            with urllib.request.urlopen(req, timeout=5) as up:
                data = up.read()
            self._reply(200, f"[PEP {TEAM}] ALLOW {ident['user']}/{ident['role']} -> exam app\n".encode() + data)
        except Exception as e:
            self._deny(502, f"upstream error: {e}")


ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = TLS_MIN_VERSION
ctx.set_ciphers(TLS_CIPHERS)
ctx.load_cert_chain("/lab/pki/out/exam.crt", "/lab/pki/out/exam.key")

with socketserver.ThreadingTCPServer(("0.0.0.0", HTTPS_PORT), PEP) as httpd:
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print(f"[PEP {TEAM}] TLS on :{HTTPS_PORT} for {EXAM_FQDN} "
          f"(min TLS={TLS_MIN_VERSION}, trust_headers={TRUST_CLIENT_HEADERS}, "
          f"require_device={REQUIRE_DEVICE_POSTURE}, expose_admin={EXPOSE_ADMIN_PATHS})")
    httpd.serve_forever()