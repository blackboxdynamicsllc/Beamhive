#!/usr/bin/env python3
"""beamhive-federation-peer.py -- a minimal, dependency-free BeamHive
federation peer.

This speaks *only* the small federation discovery and mission-listing
protocol that beamhive-server.py implements (see the "BeamHive server
federation" section in that file) -- nothing else. It carries none of
the mission, BBS, mail, or Reticulum machinery, so it's cheap to run
anywhere you just want another dot on the federation map: a spare VPS, a
Raspberry Pi, a box with no telescope attached at all. Real BeamHive
servers that crawl this peer can't tell the difference from a full
instance; they only ever call GET /federation/info, GET
/federation/peers, and GET /federation/community-missions -- the last of
which this peer always answers with an empty list, a real, complete
response rather than an error, since it runs no telescope and has no
missions of its own to contribute.

Protocol recap (kept identical to the real server so crawling is a
drop-in match):
  GET /federation/info  -> {"ok": true, "server_id", "name", "software", "url"}
  GET /federation/peers -> {"ok": true, "peers": [{"server_id","url","name"}, ...]}
  GET /federation/community-missions -> {"ok": true, "server_id", "name", "missions": []}

Usage:
  python3 beamhive-federation-peer.py --port 8420 --name "My Peer" \
      --public-url https://peer.example.com --seed https://beamhive.io

Run it behind any TLS-terminating reverse proxy the same way the real
server sits behind nginx; this script itself only speaks plain HTTP.
"""

import argparse
import json
import os
import socket
import sys
import threading
import time
import urllib.parse
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SOFTWARE_NAME = "beamhive-federation-peer"
UA = f"{SOFTWARE_NAME}/1.0"

CRAWL_INTERVAL_SECONDS = 10 * 60
STALE_SECONDS = 3 * CRAWL_INTERVAL_SECONDS
MAX_PEERS = 300
FETCH_TIMEOUT = 8
MAX_RESPONSE_BYTES = 200_000
NAME_MAX_CHARS = 80
URL_MAX_CHARS = 300

# Render's convention for a mounted persistent disk (its "Disk" feature
# defaults new disks to this mount path). Without a real persistent disk
# behind it this is just another ephemeral directory like any other --
# provisioning the disk on Render's dashboard is a separate, manual
# step this script can't do for you -- but defaulting to this path means
# no extra env var/flag is needed once that disk exists: identity
# (federation_peer_id.txt) and the known-peers list
# (federation_peer_peers.json) survive restarts and redeploys instead of
# resetting every time, which otherwise means this peer can never hold
# onto anyone long enough to be useful as a federation bootstrap point.
DEFAULT_DATA_DIR = "/var/data"

peers_lock = threading.Lock()
state = {
    "server_id": None,
    "name": None,
    "public_url": None,
    "data_dir": None,
    "peers_file": None,
    "id_file": None,
    "pending_seeds": [],
}


# --- persistence -------------------------------------------------------

def resolve_data_dir(requested):
    """Makes sure `requested` (DEFAULT_DATA_DIR unless overridden by
    --data-dir/DATA_DIR) is actually usable before committing to it,
    falling back to the directory this script lives in rather than
    crashing outright -- DEFAULT_DATA_DIR only behaves like a real
    persistent disk once one is actually mounted there on Render's end;
    run anywhere else (a plain VPS, locally) with nothing mounted at
    /var/data and creating it would either fail outright (no permission
    to create a top-level directory) or silently succeed as just another
    ephemeral path, which is no better than the old default and worth a
    visible warning rather than pretending it's persistent."""
    try:
        os.makedirs(requested, exist_ok=True)
        probe = os.path.join(requested, ".write_test")
        with open(probe, "w", encoding="utf-8") as f:
            f.write("")
        os.remove(probe)
        return requested
    except Exception as e:
        fallback = os.path.dirname(os.path.abspath(__file__))
        print(f"[warn] {requested} isn't writable here ({e}); falling back to {fallback} -- "
              f"identity and known peers won't survive a restart there")
        return fallback


def load_server_id():
    try:
        with open(state["id_file"], "r", encoding="utf-8") as f:
            sid = f.read().strip()
        if sid:
            return sid
    except Exception:
        pass
    sid = str(uuid.uuid4())
    tmp = state["id_file"] + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(sid)
    os.replace(tmp, state["id_file"])
    return sid


def load_peers():
    with peers_lock:
        try:
            with open(state["peers_file"], "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                return data
        except Exception:
            pass
        return {}


def save_peers(data):
    with peers_lock:
        path = state["peers_file"]
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f)
        os.replace(tmp, path)


# --- SSRF-safe outbound fetch (same shape as the real server's checks) --

def is_private_ip(ip):
    if not ip:
        return True
    if ip in ("127.0.0.1", "::1", "localhost"):
        return True
    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("169.254."):
        return True
    if ip.startswith("172."):
        try:
            return 16 <= int(ip.split(".")[1]) <= 31
        except Exception:
            return False
    return False


def host_is_safe(hostname):
    try:
        infos = socket.getaddrinfo(hostname, None)
    except Exception:
        return False
    if not infos:
        return False
    return all(not is_private_ip(info[4][0]) for info in infos)


def valid_federation_url(url):
    if not isinstance(url, str) or not url or len(url) > URL_MAX_CHARS:
        return False
    try:
        parts = urllib.parse.urlsplit(url)
    except Exception:
        return False
    return parts.scheme in ("http", "https") and bool(parts.hostname)


def url_join(base, path):
    return base.rstrip("/") + path


def fetch_json(url, timeout=FETCH_TIMEOUT):
    parts = urllib.parse.urlsplit(url)
    if not host_is_safe(parts.hostname):
        raise RuntimeError("refusing to fetch a private/local address")
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read(MAX_RESPONSE_BYTES + 1)
    if len(body) > MAX_RESPONSE_BYTES:
        raise RuntimeError("response too large")
    data = json.loads(body.decode("utf-8", errors="replace"))
    if not isinstance(data, dict):
        raise RuntimeError("malformed response")
    return data


# --- federation logic ----------------------------------------------------

def self_info():
    return {
        "ok": True,
        "server_id": state["server_id"],
        "name": state["name"],
        "software": SOFTWARE_NAME,
        "url": state["public_url"] or "",
    }


def community_missions_response():
    """GET /federation/community-missions -- a real BeamHive server's
    mission-federation crawl (see _federation_missions_refresh_once in
    beamhive-server.py) polls every known peer for this. This peer never
    runs any telescope and carries no mission data at all (see the module
    docstring), so it always answers with an empty list -- a real,
    complete response in the same shape a full server would give, not an
    error -- so a crawling server's poll of this peer just contributes
    nothing rather than logging it as unreachable or malformed."""
    return {
        "ok": True,
        "server_id": state["server_id"],
        "name": state["name"],
        "missions": [],
    }


def add_or_update_peer(server_id, url, name, mark_seen, ping_ms=None):
    peers = load_peers()
    existing = peers.get(server_id)
    now = time.time()
    peers[server_id] = {
        "url": url,
        "name": (name or (existing or {}).get("name") or "Unknown BeamHive")[:NAME_MAX_CHARS],
        "first_seen_epoch": (existing or {}).get("first_seen_epoch") or now,
        "last_seen_epoch": now if mark_seen else (existing or {}).get("last_seen_epoch") or 0,
        "ping_ms": ping_ms if ping_ms is not None else (existing or {}).get("ping_ms"),
    }
    save_peers(peers)
    return peers[server_id]


def add_peer_by_url(url):
    """Verifies a candidate peer is actually a live, reachable BeamHive
    server before trusting anything it claims about itself -- backs both
    the --seed startup flag and POST /federation/announce (see the
    Handler below). The MAX_PEERS check matters here specifically
    because /federation/announce is unauthenticated and reachable by
    anyone: without it, enough distinct reachable "BeamHive" responders
    could grow federation_peer_peers.json without bound."""
    if not valid_federation_url(url):
        return False, "invalid URL (must be http:// or https://)"
    own_id = state["server_id"]
    t0 = time.monotonic()
    try:
        info = fetch_json(url_join(url, "/federation/info"))
    except Exception as e:
        return False, f"could not reach {url}: {e}"
    ping_ms = round((time.monotonic() - t0) * 1000)
    server_id = str(info.get("server_id") or "")[:64]
    if not server_id:
        return False, "peer did not return a server_id"
    if server_id == own_id:
        return False, "that's this server's own address"
    if server_id not in load_peers() and len(load_peers()) >= MAX_PEERS:
        return False, "this server already knows the maximum number of peers"
    peer = add_or_update_peer(server_id, url, info.get("name"), mark_seen=True, ping_ms=ping_ms)
    return True, dict(peer, server_id=server_id)


def crawl_once():
    peers = load_peers()
    if not peers:
        return
    own_id = state["server_id"]
    snapshot = list(peers.items())
    changed = False
    for server_id, peer in snapshot:
        url = peer.get("url")
        if not valid_federation_url(url):
            continue
        try:
            t0 = time.monotonic()
            info = fetch_json(url_join(url, "/federation/info"))
            ping_ms = round((time.monotonic() - t0) * 1000)
            if str(info.get("server_id") or "") == server_id:
                peer["name"] = str(info.get("name") or peer.get("name") or "Unknown BeamHive")[:NAME_MAX_CHARS]
                peer["last_seen_epoch"] = time.time()
                peer["ping_ms"] = ping_ms
                changed = True
        except Exception:
            pass  # unreachable this cycle isn't the same as gone -- leave last_seen_epoch alone
        if len(peers) >= MAX_PEERS:
            continue
        try:
            their_peers = fetch_json(url_join(url, "/federation/peers"))
            for p in (their_peers.get("peers") or [])[:MAX_PEERS]:
                if not isinstance(p, dict) or len(peers) >= MAX_PEERS:
                    break
                pid = str(p.get("server_id") or "")[:64]
                purl = str(p.get("url") or "")
                if not pid or pid == own_id or pid in peers or not valid_federation_url(purl):
                    continue
                peers[pid] = {
                    "url": purl[:URL_MAX_CHARS],
                    "name": str(p.get("name") or "Unknown BeamHive")[:NAME_MAX_CHARS],
                    "first_seen_epoch": time.time(), "last_seen_epoch": 0, "ping_ms": None,
                }
                changed = True
        except Exception:
            pass
    if changed:
        save_peers(peers)


def retry_pending_seeds():
    """Seeds passed on the command line that weren't reachable at startup
    (the other server was mid-restart, DNS hadn't propagated yet, etc.)
    aren't in peers.json at all -- crawl_once only re-verifies peers it
    already knows -- so they'd otherwise be silently dropped forever.
    Keep trying each one here until it resolves into a real peer entry."""
    still_pending = []
    for url in state["pending_seeds"]:
        ok, result = add_peer_by_url(url)
        if ok:
            print(f"[info] seeded peer {url} -> {result['server_id']}")
        else:
            still_pending.append(url)
    state["pending_seeds"] = still_pending


def crawl_loop(interval):
    while True:
        try:
            if state["pending_seeds"]:
                retry_pending_seeds()
            crawl_once()
        except Exception as e:
            print(f"[crawl] error: {e}", file=sys.stderr)
        time.sleep(interval)


def peers_response():
    peers = load_peers()
    return {
        "ok": True,
        "peers": [{"server_id": sid, "url": p.get("url"), "name": p.get("name")}
                  for sid, p in peers.items()],
    }


# --- HTTP handler ----------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = SOFTWARE_NAME
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        print(f"[http] {self.address_string()} {fmt % args}")

    def _json(self, status, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _maybe_autoseed_public_url(self):
        # Defaults to http, not https, when nothing upstream sets
        # X-Forwarded-Proto: this script never terminates TLS itself, so a
        # request reaching it with no reverse proxy in front genuinely
        # arrived over plain HTTP. Guessing https for a bare-IP or
        # otherwise proxy-less deployment (the common case for this
        # script -- see the module docstring) seeds a public_url nobody
        # can ever reach, which silently breaks --seed/announce
        # verification for it with no visible error (see add_peer_by_url).
        if state["public_url"]:
            return
        host = self.headers.get("Host")
        if not host:
            return
        proto = self.headers.get("X-Forwarded-Proto") or "http"
        candidate = f"{proto}://{host}"
        if not valid_federation_url(candidate):
            return
        hostname = urllib.parse.urlsplit(candidate).hostname
        if hostname and host_is_safe(hostname):
            state["public_url"] = candidate
            print(f"[info] auto-detected public URL: {candidate}")

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path
        if path == "/federation/info":
            self._maybe_autoseed_public_url()
            self._json(200, self_info())
            return
        if path == "/federation/peers":
            self._json(200, peers_response())
            return
        if path == "/federation/community-missions":
            self._json(200, community_missions_response())
            return
        if path == "/mission-activity":
            # Real beamhive-server.py instances poll every known peer's
            # /mission-activity every few seconds to gate the Execute
            # On-Demand Mission button federation-wide (see
            # _federation_busy_refresh_once in beamhive-server.py). This
            # peer runs no telescope at all (see the module docstring),
            # so "not busy" is always the correct, real answer -- not
            # just a stub -- and answering it here (instead of 404ing)
            # means one fewer guaranteed-failing request every cycle for
            # every real server that has this as a peer.
            self._json(200, {"busy": False, "federated_busy": False})
            return
        if path == "/federation/scheduled-missions":
            # Real beamhive-server.py instances poll every known peer's
            # /federation/scheduled-missions every ~20s so a timeslot
            # booked on one server is unavailable on every other one too
            # (see _federation_schedules_refresh_once in beamhive-
            # server.py). This peer runs no telescope and has no
            # scheduling of its own (see the module docstring), so an
            # empty list is always the correct, real answer -- same
            # reasoning as /mission-activity and /federation/community-
            # missions above.
            self._json(200, {"ok": True, "server_id": state["server_id"], "name": state["name"], "schedules": []})
            return
        if path == "/":
            self._json(200, {"ok": True, "software": SOFTWARE_NAME, **self_info()})
            return
        self._json(404, {"ok": False, "error": "not found"})

    def do_POST(self):
        path = urllib.parse.urlsplit(self.path).path
        if path == "/federation/announce":
            # Unauthenticated by design -- the push half of gossip
            # discovery (see beamhive-server.py's _federation_announce_
            # self_to and matching /federation/announce route). Safe to
            # expose without auth because trust never comes from the
            # request body -- add_peer_by_url always calls back out to the
            # claimed url's own /federation/info and only adds it if that
            # independently confirms a live, self-consistent BeamHive
            # server, exactly the same verification --seed gets at
            # startup.
            body = {}
            try:
                n = int(self.headers.get("Content-Length", "0") or "0")
                if n:
                    raw = self.rfile.read(n).decode("utf-8")
                    if raw.strip():
                        body = json.loads(raw)
            except Exception:
                body = {}
            if not isinstance(body, dict):
                body = {}
            url = str(body.get("url") or "").strip()
            ok, result = add_peer_by_url(url)
            if not ok:
                self._json(400, {"ok": False, "error": result})
                return
            self._json(200, {"ok": True, "peer": result})
            return
        self._json(404, {"ok": False, "error": "not found"})


def main():
    ap = argparse.ArgumentParser(description="Minimal standalone BeamHive Network Bootstrap")
    ap.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8420")))
    ap.add_argument("--bind", default=os.environ.get("BIND", "0.0.0.0"))
    ap.add_argument("--name", default=os.environ.get("PEER_NAME", "BeamHive Network Bootstrap"))
    ap.add_argument("--public-url", default=os.environ.get("PUBLIC_URL", ""))
    ap.add_argument("--seed", action="append", default=[],
                     help="URL of an existing BeamHive server to bootstrap discovery from; repeatable")
    ap.add_argument("--data-dir", default=os.environ.get("DATA_DIR", DEFAULT_DATA_DIR),
                     help=f"where federation_peer_id.txt / federation_peer_peers.json live "
                          f"(default: {DEFAULT_DATA_DIR}, Render's persistent-disk mount "
                          f"convention -- falls back to this script's own directory if that "
                          f"path isn't actually writable here)")
    ap.add_argument("--crawl-interval", type=int, default=CRAWL_INTERVAL_SECONDS)
    args = ap.parse_args()

    args.data_dir = resolve_data_dir(args.data_dir)
    state["data_dir"] = args.data_dir
    state["id_file"] = os.path.join(args.data_dir, "federation_peer_id.txt")
    state["peers_file"] = os.path.join(args.data_dir, "federation_peer_peers.json")
    state["server_id"] = load_server_id()
    state["name"] = args.name[:NAME_MAX_CHARS]
    state["public_url"] = args.public_url or None

    print(f"[info] server_id={state['server_id']}")
    print(f"[info] name={state['name']!r}")
    print(f"[info] public_url={state['public_url'] or '(not set -- will auto-detect from inbound Host header)'}")

    for seed_url in args.seed:
        ok, result = add_peer_by_url(seed_url)
        if ok:
            print(f"[info] seeded peer {seed_url} -> {result['server_id']}")
        else:
            print(f"[warn] could not seed {seed_url} yet: {result} (will keep retrying)")
            state["pending_seeds"].append(seed_url)

    threading.Thread(target=crawl_loop, args=(args.crawl_interval,), daemon=True).start()

    httpd = ThreadingHTTPServer((args.bind, args.port), Handler)
    print(f"[info] listening on {args.bind}:{args.port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
