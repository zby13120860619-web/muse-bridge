#!/usr/bin/env python3
"""Muse Bridge — a tiny keyed mailbox relay for a team of Muse agents.

Design (mirrors the team rules):
- Each member holds a secret key; the server stores only SHA-256 hashes.
- POST /send {to, text, topic?}  — to = "group" or a member id.
- GET  /poll                     — fetch-and-delete: returns this member's
                                   pending messages and removes them.
- GET  /members                  — roster + online status (seen < 30 s ago).
- GET  /ledger?after=<unix ts>   — captain only: the full message ledger.
- POST /revoke {member}          — captain only: kill a member's key.
- Every message is appended to the captain's ledger (state/ledger.jsonl).
- Rules enforced here: message length cap, quiet hours 23:00-07:00
  (Asia/Shanghai) — non-captain messages are held until 07:00;
  captain messages are never held.
Stdlib only. State lives next to this file under state/.
"""
import hashlib
import json
import os
import threading
import time
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from zoneinfo import ZoneInfo

BASE = os.path.dirname(os.path.abspath(__file__))
STATE = os.path.join(BASE, "state")
os.makedirs(STATE, exist_ok=True)
MEMBERS_FILE = os.path.join(BASE, "members.json")
QUEUE_FILE = os.path.join(STATE, "queue.json")
LEDGER_FILE = os.path.join(STATE, "ledger.jsonl")

MAX_LEN = 5000
TZ = ZoneInfo("Asia/Shanghai")
QUIET_START, QUIET_END = 23, 7
PORT = int(os.environ.get("PORT", os.environ.get("BRIDGE_PORT", "18765")))

lock = threading.Lock()
last_seen = {}


def load_members():
    with open(MEMBERS_FILE, encoding="utf-8") as f:
        return json.load(f)


def key_to_member(key):
    if not key:
        return None
    h = hashlib.sha256(key.encode()).hexdigest()
    for m in load_members():
        if m.get("key_hash") == h and not m.get("revoked"):
            return m
    return None


def load_queue():
    if os.path.exists(QUEUE_FILE):
        with open(QUEUE_FILE, encoding="utf-8") as f:
            return json.load(f)
    return []


def save_queue(q):
    tmp = QUEUE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(q, f, ensure_ascii=False)
    os.replace(tmp, QUEUE_FILE)


def append_ledger(entry):
    with open(LEDGER_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def quiet_hold_until(now=None):
    """If now is inside quiet hours, return the unix ts of next 07:00 CST,
    else 0 (no hold)."""
    now = now or datetime.now(TZ)
    if now.hour >= QUIET_START or now.hour < QUIET_END:
        end = now.replace(hour=QUIET_END, minute=0, second=0, microsecond=0)
        if now.hour >= QUIET_START:
            end += timedelta(days=1)
        return end.timestamp()
    return 0


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _auth(self):
        return key_to_member(self.headers.get("X-Key", ""))

    def _body(self):
        n = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(n) if n else b"{}"
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    def do_GET(self):
        m = self._auth()
        if not m:
            return self._json(401, {"error": "bad key"})
        last_seen[m["id"]] = time.time()
        if self.path.startswith("/poll"):
            with lock:
                q = load_queue()
                mine, rest = [], []
                now = time.time()
                for msg in q:
                    deliver = False
                    if msg["to"] == "group":
                        if m["id"] in msg.get("pending_for", []):
                            if msg.get("hold_until", 0) <= now or m["role"] == "captain":
                                deliver = True
                                msg["pending_for"].remove(m["id"])
                    elif msg["to"] == m["id"]:
                        if msg.get("hold_until", 0) <= now or m["role"] == "captain":
                            deliver = True
                    if deliver:
                        mine.append({k: msg[k] for k in
                                     ("id", "from", "to", "topic", "text", "ts")})
                        if msg["to"] == "group" and msg.get("pending_for"):
                            rest.append(msg)
                    else:
                        rest.append(msg)
                save_queue(rest)
            return self._json(200, {"messages": mine})
        if self.path.startswith("/members"):
            roster = []
            for mm in load_members():
                if mm.get("revoked"):
                    continue
                roster.append({
                    "id": mm["id"], "name": mm["name"], "role": mm["role"],
                    "online": time.time() - last_seen.get(mm["id"], 0) < 30,
                })
            return self._json(200, {"members": roster})
        if self.path.startswith("/ledger"):
            if m["role"] != "captain":
                return self._json(403, {"error": "captain only"})
            after = 0.0
            if "after=" in self.path:
                try:
                    after = float(self.path.split("after=")[1].split("&")[0])
                except Exception:
                    after = 0.0
            entries = []
            if os.path.exists(LEDGER_FILE):
                with open(LEDGER_FILE, encoding="utf-8") as f:
                    for line in f:
                        try:
                            e = json.loads(line)
                        except Exception:
                            continue
                        if e.get("ts", 0) > after:
                            entries.append(e)
            return self._json(200, {"entries": entries})
        return self._json(404, {"error": "not found"})

    def do_POST(self):
        m = self._auth()
        if not m:
            return self._json(401, {"error": "bad key"})
        last_seen[m["id"]] = time.time()
        body = self._body()
        if self.path.startswith("/send"):
            to = str(body.get("to", ""))
            text = str(body.get("text", ""))
            topic = str(body.get("topic", ""))[:64]
            if not text:
                return self._json(400, {"error": "empty text"})
            if len(text) > MAX_LEN:
                return self._json(400, {"error": f"text too long (>{MAX_LEN})"})
            members = [mm for mm in load_members() if not mm.get("revoked")]
            ids = {mm["id"] for mm in members}
            if to != "group" and to not in ids:
                return self._json(400, {"error": "unknown recipient"})
            hold = 0
            if m["role"] != "captain":
                hold = quiet_hold_until()
            msg = {
                "id": f"{int(time.time()*1000)}-{m['id']}",
                "from": m["id"], "to": to, "topic": topic, "text": text,
                "ts": time.time(), "hold_until": hold,
            }
            if to == "group":
                msg["pending_for"] = [mm["id"] for mm in members
                                       if mm["id"] != m["id"]]
            with lock:
                q = load_queue()
                q.append(msg)
                save_queue(q)
                append_ledger({k: msg[k] for k in
                               ("id", "from", "to", "topic", "text", "ts")})
            return self._json(200, {"ok": True, "id": msg["id"], "held": bool(hold)})
        if self.path.startswith("/revoke"):
            if m["role"] != "captain":
                return self._json(403, {"error": "captain only"})
            target = str(body.get("member", ""))
            members = load_members()
            hit = False
            for mm in members:
                if mm["id"] == target:
                    mm["revoked"] = True
                    hit = True
            if hit:
                with open(MEMBERS_FILE, "w", encoding="utf-8") as f:
                    json.dump(members, f, ensure_ascii=False, indent=1)
            return self._json(200, {"ok": hit})
        return self._json(404, {"error": "not found"})


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"muse-bridge listening on :{PORT}", flush=True)
    srv.serve_forever()
