#!/usr/bin/env python3
# ============================================================================
# mockrpc.py — localhost JSON-RPC stand-in for zclassicd (L1 + L2 backend).
#
# The wallet's ONLY network primitive is Connection::doRPC, which POSTs plain
# HTTP/Basic-auth JSON-RPC 1.0 to a QNetworkAccessManager and then reads
# parsed["result"] off the reply body (src/connection.cpp:2476). So a localhost
# http.server that answers each "method" with a canned "result" is a zero-
# product-change drop-in for the daemon, reusable by every test layer.
#
# Run (inside the proot chroot OR on the host — python3 is in both):
#   MOCK_PORT=18232 MOCK_SCENARIO=funded-synced \
#   MOCK_LOG=/tmp/mockrpc.requests.log \
#   python3 /src/wallet/tests/mock/mockrpc.py
#
# It listens on 127.0.0.1:$MOCK_PORT, ignores Basic auth, dispatches by the
# JSON-RPC "method" field to a per-scenario fixture, and APPENDS every incoming
# request body (one JSON object per line) to $MOCK_LOG so a test can assert,
# e.g., the z_sendmany change-routing payload.
#
# Scenario  = env MOCK_SCENARIO (default funded-synced); a directory under
#             tests/mock/fixtures/<scenario>/ holding <method>.json files, each
#             the bare RESULT value the wallet expects (NOT wrapped in an
#             envelope — the server wraps it).
#
# Per-method resolution order (first hit wins):
#   1. fixtures/<scenario>/<method>.json     (scenario override)
#   2. a built-in default in DEFAULTS below  (scenario-agnostic boilerplate)
#   3. JSON-RPC method-not-found error        (mirrors a real daemon)
#
# Clean shutdown: SIGTERM/SIGINT -> shutdown(); a GET /__shutdown also stops it
# (handy for tests that don't hold the PID).
# ============================================================================

import json
import os
import signal
import sys
import threading

from http.server import BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from http.server import HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES_ROOT = os.path.join(HERE, "fixtures")

PORT = int(os.environ.get("MOCK_PORT", "18232"))
SCENARIO = os.environ.get("MOCK_SCENARIO", "funded-synced")
LOG_PATH = os.environ.get(
    "MOCK_LOG", os.path.join(HERE, "mockrpc.requests.log")
)

# Scenario-agnostic defaults. A scenario file of the same name overrides these.
# These cover the methods whose reply shape never needs to vary per scenario
# (key dumps, imports, the no-op operation status, change-history lookups), so
# every scenario dir only has to carry what is actually scenario-specific.
DEFAULTS = {
    # Per-address key dumps (string). Real-format-ish placeholders; tests that
    # need a specific key seed a fixture file instead.
    "dumpprivkey": "Ky5gd0MOCKtPriVkEYpLaCeHoLdErForTestsOnly1111111111111",
    "z_exportkey": "secret-extended-key-main1MOCKzExtSpendKeyPlaceholder0000",
    "importprivkey": None,
    "z_importkey": None,
    # Newly-minted addresses. The wallet defaults receive/reply-to to Sapling,
    # so z_getnewaddress MUST return a zs-prefixed (Sapling) address.
    "z_getnewaddress": "zs1newmockaddr0sapling000000000000000000000000000000000000000000000000",
    "getnewaddress": "t1NewMockTransparentAddr000000000000",
    # No pending shielded operations by default (z_getoperationstatus is an array).
    "z_getoperationstatus": [],
    # z_sendmany returns an opid string; the wallet then polls z_getoperationstatus.
    "z_sendmany": "opid-00000000-0000-0000-0000-00000000mock",
    # z_listreceivedbyaddress / gettransaction are batched per-address/per-txid;
    # default to empty so an un-seeded scenario doesn't choke the batch walker.
    "z_listreceivedbyaddress": [],
    # getnetworksolps is only called when an embedded node is present (number).
    "getnetworksolps": 0,
    # stop is the graceful-shutdown RPC.
    "stop": "ZClassic server stopping",
}


def load_fixture(method):
    """Return (found, result_value). Scenario file beats DEFAULTS."""
    path = os.path.join(FIXTURES_ROOT, SCENARIO, method + ".json")
    if os.path.isfile(path):
        with open(path, "r") as f:
            return True, json.load(f)
    if method in DEFAULTS:
        return True, DEFAULTS[method]
    return False, None


def log_request(raw_body):
    """Append the raw request body as one line to the request log (best-effort)."""
    try:
        with open(LOG_PATH, "a") as f:
            # Normalize to a single compact line so a test can grep/parse it,
            # but fall back to the raw text if it isn't valid JSON.
            try:
                obj = json.loads(raw_body)
                f.write(json.dumps(obj, separators=(",", ":")) + "\n")
            except Exception:
                f.write(raw_body.replace("\n", " ") + "\n")
    except Exception as e:
        sys.stderr.write("mockrpc: could not write log: %s\n" % e)


class Handler(BaseHTTPRequestHandler):
    # Silence the default per-request stderr noise; we keep our own log.
    def log_message(self, fmt, *args):
        pass

    def _send_json(self, obj, code=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # A tiny control + health surface. Never used by the wallet (it only POSTs).
        if self.path == "/__shutdown":
            self._send_json({"ok": True, "stopping": True})
            threading.Thread(target=self.server.shutdown, daemon=True).start()
            return
        self._send_json(
            {"ok": True, "scenario": SCENARIO, "port": PORT, "log": LOG_PATH}
        )

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
        except (TypeError, ValueError):
            length = 0
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""

        # IGNORE Basic auth entirely — record + dispatch regardless.
        log_request(raw)

        try:
            req = json.loads(raw)
        except Exception:
            # Malformed JSON body. Mirror a daemon-style parse error so the
            # wallet's error path (noConnection / showTxError) is exercised.
            self._send_json(
                {
                    "result": None,
                    "error": {"code": -32700, "message": "Parse error"},
                    "id": None,
                }
            )
            return

        method = req.get("method")
        req_id = req.get("id")

        # getwalletsummary — the GUI's instant-balance fast path. Derive it from the
        # scenario's z_gettotalbalance so the displayed transparent/private/total are
        # IDENTICAL to the legacy hero source, then add the extra metadata fields the
        # real RPC returns (unused by the GUI). This exercises the GUI fast path with
        # values consistent with every scenario's balance assertions. A scenario with
        # no z_gettotalbalance falls through to the generic -32601 below, which the GUI
        # treats as an OLD daemon and falls back — so both paths stay reachable.
        if method == "getwalletsummary":
            found_b, bal = load_fixture("z_gettotalbalance")
            if found_b and isinstance(bal, dict):
                summary = {
                    "transparent": bal.get("transparent", "0.00"),
                    "transparentunconfirmed": "0.00",
                    "transparentimmature": "0.00",
                    "private": bal.get("private", "0.00"),
                    "total": bal.get("total", "0.00"),
                    "shieldedcached": True,
                    "txcount": 0,
                    "height": 0,
                    "bestblockhash": "00" * 32,
                }
                self._send_json({"result": summary, "error": None, "id": req_id})
                return

        found, result = load_fixture(method)
        if not found:
            self._send_json(
                {
                    "result": None,
                    "error": {
                        "code": -32601,
                        "message": "Method not found: %s" % method,
                    },
                    "id": req_id,
                }
            )
            return

        # JSON-RPC success envelope: the wallet reads parsed["result"].
        self._send_json({"result": result, "error": None, "id": req_id})


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    if not os.path.isdir(os.path.join(FIXTURES_ROOT, SCENARIO)):
        sys.stderr.write(
            "mockrpc: WARNING scenario dir not found: %s "
            "(only DEFAULTS will answer)\n"
            % os.path.join(FIXTURES_ROOT, SCENARIO)
        )

    httpd = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)

    def _stop(signum, frame):
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    sys.stderr.write(
        "mockrpc: listening on 127.0.0.1:%d  scenario=%s  log=%s\n"
        % (PORT, SCENARIO, LOG_PATH)
    )
    sys.stderr.flush()
    try:
        httpd.serve_forever(poll_interval=0.2)
    finally:
        httpd.server_close()
        sys.stderr.write("mockrpc: stopped\n")


if __name__ == "__main__":
    main()
