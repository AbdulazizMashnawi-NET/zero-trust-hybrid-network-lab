#!/usr/bin/env python3
"""Tiny TCP listener used by the mock DB / records / support hosts. It just
accepts a connection and announces itself, so nmap shows the port open and the
team can see WHICH host answered. Args: <port> <label>."""
import socket, sys, os
port = int(sys.argv[1]); label = sys.argv[2]
team = os.environ.get("TEAM", "?")
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", port)); s.listen(16)
print(f"[{label} {team}] listening on :{port}")
while True:
    try:
        c, a = s.accept()
        c.sendall(f"{label} ({team}) on port {port}\n".encode())
        c.close()
    except Exception:
        pass
