#!/usr/bin/env python3
"""Serves this exit's probe state (status.json) to its peers: GET /status with header X-Probe-Token."""
import hmac, http.server, os, sys

STATE = os.environ.get("GAMEBOND_PROBE_STATE", "/var/lib/gamebond-probe")
TOKEN = open(os.environ.get("GAMEBOND_PEER_TOKEN_FILE", "/etc/gamebond/peer.token")).read().strip()
PORT = int(os.environ.get("GAMEBOND_PROBE_STATUS_PORT", "8099"))

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        ok = self.path == "/status" and hmac.compare_digest(self.headers.get("X-Probe-Token", ""), TOKEN)
        if not ok:
            self.send_response(403); self.end_headers(); return
        try:
            body = open(os.path.join(STATE, "status.json"), "rb").read()
        except OSError:
            self.send_response(503); self.end_headers(); return
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass

http.server.ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
