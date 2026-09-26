"""Panel local y control de acceso para la carpeta compartida SMB.

Corre como root (necesita iptables, systemctl y smbcontrol). Escucha solo en
127.0.0.1 y exige un token (header X-Token) para toda la API; el token se
escribe en /run/fileshare/token, legible solo por el usuario dueño.
"""

import ipaddress
import json
import os
import pwd
import re
import secrets
import subprocess
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

USER = os.environ.get("FILESHARE_USER", "alecor")
SHARE = os.environ.get("FILESHARE_SHARE", "Compartida")
SHARE_PATH = os.environ.get("FILESHARE_PATH", f"/home/{USER}/{SHARE}")
STATE_DIR = os.environ.get("FILESHARE_STATE", "/var/lib/fileshare")
RUN_DIR = os.environ.get("FILESHARE_RUN", "/run/fileshare")
PORT = int(os.environ.get("FILESHARE_PORT", "8445"))
HOST = os.environ.get("FILESHARE_HOST", os.uname().nodename)
SMBD_UNIT = os.environ.get("FILESHARE_SMBD_UNIT", "samba-smbd")
HTML_PATH = os.environ.get(
    "FILESHARE_HTML", os.path.join(os.path.dirname(__file__), "panel.html")
)

STATE_FILE = os.path.join(STATE_DIR, "state.json")
SMB_GLOBAL_CONF = os.path.join(STATE_DIR, "smb-global.conf")
SMB_SHARE_CONF = os.path.join(STATE_DIR, "smb-share.conf")
TOKEN_FILE = os.path.join(RUN_DIR, "token")

CHAIN = "fileshare"
ACCT_IN = "fileshare-acct-in"
ACCT_OUT = "fileshare-acct-out"
LOG_PREFIX = "FILESHARE-DENY "
MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")

lock = threading.RLock()
TOKEN = secrets.token_urlsafe(32)


def now():
    return int(time.time())


def run(*cmd, check=False):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return None if check else ""
    if check and p.returncode != 0:
        return None
    return p.stdout


def ok(*cmd):
    return run(*cmd, check=True) is not None


# ---------------------------------------------------------------- estado


def default_state():
    return {
        "devices": [],
        "settings": {"idle_minutes": 30, "read_only": False},
        "events": [],
        "traffic": {},
    }


def load_state():
    try:
        with open(STATE_FILE) as f:
            s = json.load(f)
    except (OSError, ValueError):
        return default_state()
    base = default_state()
    base.update(s)
    base["settings"] = {**default_state()["settings"], **s.get("settings", {})}
    return base


state = load_state()
runtime = {
    "running": False,
    "started_at": None,
    "last_activity": now(),
    "sessions": [],
    "blocked": {},  # mac -> {mac, ip, count, first, last, iface}
    "activity": deque(maxlen=300),
    "auth": deque(maxlen=100),
    "folder": {"size": 0, "files": 0, "recent": [], "at": 0},
    "net": {"addresses": [], "subnets": [], "ssid": None, "ifaces": []},
    "neigh": {},  # mac -> ip
    "fw_ok": False,
    "acct_prev": {},
}


def save_state():
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f, indent=1)
    os.replace(tmp, STATE_FILE)


def event(kind, msg):
    with lock:
        state["events"].append({"t": now(), "kind": kind, "msg": msg})
        state["events"] = state["events"][-200:]
        save_state()


def device(mac):
    return next((d for d in state["devices"] if d["mac"] == mac), None)


# ---------------------------------------------------------------- red


def refresh_net():
    addrs, subnets, ifaces = [], [], []
    try:
        data = json.loads(run("ip", "-j", "addr") or "[]")
    except ValueError:
        data = []
    for itf in data:
        name = itf.get("ifname", "")
        if name == "lo" or name.startswith(("docker", "br-", "veth", "virbr")):
            continue
        if "UP" not in itf.get("flags", []):
            continue
        for a in itf.get("addr_info", []):
            if a.get("family") != "inet":
                continue
            addrs.append(a["local"])
            subnets.append(str(ipaddress.ip_interface(f"{a['local']}/{a['prefixlen']}").network))
            ifaces.append(name)
    ssid = None
    for line in (run("nmcli", "-t", "-f", "active,ssid", "dev", "wifi") or "").splitlines():
        if line.startswith("yes:"):
            ssid = line[4:] or None
    neigh = {}
    try:
        for n in json.loads(run("ip", "-j", "-4", "neigh") or "[]"):
            mac = (n.get("lladdr") or "").lower()
            if mac and "FAILED" not in n.get("state", []):
                neigh[mac] = n["dst"]
    except ValueError:
        pass
    with lock:
        runtime["net"] = {"addresses": addrs, "subnets": subnets, "ssid": ssid, "ifaces": ifaces}
        runtime["neigh"] = neigh


# ---------------------------------------------------------------- firewall


def fw_rules():
    rules = []
    for d in state["devices"]:
        rules.append(["-m", "mac", "--mac-source", d["mac"], "-j", "ACCEPT"])
    rules.append(["-m", "limit", "--limit", "20/min", "--limit-burst", "10",
                  "-j", "LOG", "--log-level", "info", "--log-prefix", LOG_PREFIX])
    rules.append(["-j", "DROP"])
    return rules


def ensure_chain(name):
    if not ok("iptables", "-n", "-L", name):
        run("iptables", "-N", name)


def ensure_jump(parent, spec):
    if not ok("iptables", "-C", parent, *spec):
        run("iptables", "-I", parent, "1", *spec)


_fw_applied = {"key": None, "dump": None}


def sync_firewall():
    with lock:
        rules = fw_rules()
        macs = [d["mac"] for d in state["devices"]]
        ips = sorted({runtime["neigh"][m] for m in macs if m in runtime["neigh"]})
    for c in (CHAIN, ACCT_IN, ACCT_OUT):
        ensure_chain(c)

    key = json.dumps([rules, macs, ips])
    dump = run("iptables", "-S", CHAIN) + run("iptables", "-S", ACCT_IN) + run("iptables", "-S", ACCT_OUT)
    if key != _fw_applied["key"] or dump != _fw_applied["dump"]:
        harvest_traffic()
        for c in (CHAIN, ACCT_IN, ACCT_OUT):
            run("iptables", "-F", c)
        for r in rules:
            run("iptables", "-A", CHAIN, *r)
        for m in macs:
            run("iptables", "-A", ACCT_IN, "-m", "mac", "--mac-source", m, "-j", "RETURN")
        for ip in ips:
            run("iptables", "-A", ACCT_OUT, "-d", ip, "-j", "RETURN")
        runtime["acct_prev"] = {}
        _fw_applied["key"] = key
        _fw_applied["dump"] = run("iptables", "-S", CHAIN) + run("iptables", "-S", ACCT_IN) + run("iptables", "-S", ACCT_OUT)

    new445 = ["-p", "tcp", "--dport", "445", "-m", "conntrack", "--ctstate", "NEW", "-j", CHAIN]
    parent = "nixos-fw" if ok("iptables", "-n", "-L", "nixos-fw") else "INPUT"
    ensure_jump(parent, new445)
    ensure_jump("INPUT", ["-p", "tcp", "--dport", "445", "-j", ACCT_IN])
    ensure_jump("OUTPUT", ["-p", "tcp", "--sport", "445", "-j", ACCT_OUT])
    with lock:
        runtime["fw_ok"] = ok("iptables", "-C", parent, *new445)


def harvest_traffic():
    """Suma los contadores de iptables a los totales persistentes por MAC."""
    with lock:
        ip_to_mac = {ip: m for m, ip in runtime["neigh"].items()}
        prev = runtime["acct_prev"]
        for chain, direction in ((ACCT_IN, "up"), (ACCT_OUT, "down")):
            out = run("iptables", "-L", chain, "-v", "-x", "-n") or ""
            for line in out.splitlines()[2:]:
                parts = line.split()
                if len(parts) < 9:
                    continue
                nbytes = int(parts[1])
                if direction == "up":
                    m = re.search(r"MAC\s*([0-9A-Fa-f:]{17})", line)
                    mac = m.group(1).lower() if m else None
                else:
                    mac = ip_to_mac.get(parts[8])
                if not mac:
                    continue
                k = f"{chain}|{mac}"
                delta = nbytes - prev.get(k, 0)
                if delta < 0:
                    delta = nbytes
                prev[k] = nbytes
                t = state["traffic"].setdefault(mac, {"up": 0, "down": 0})
                t[direction] += delta


# ---------------------------------------------------------------- samba


def write_samba_conf():
    with lock:
        subnets = runtime["net"]["subnets"]
        ro = state["settings"]["read_only"]
    g = f"hosts allow = 127.0.0.1 {' '.join(subnets)}\nhosts deny = ALL\n"
    s = f"read only = {'yes' if ro else 'no'}\n"
    changed = False
    for path, content in ((SMB_GLOBAL_CONF, g), (SMB_SHARE_CONF, s)):
        try:
            with open(path) as f:
                if f.read() == content:
                    continue
        except OSError:
            pass
        with open(path, "w") as f:
            f.write(content)
        changed = True
    if changed and runtime["running"]:
        run("smbcontrol", "smbd", "reload-config")


def smbd_active():
    return (run("systemctl", "is-active", SMBD_UNIT) or "").strip() == "active"


def set_share(on):
    if on:
        write_samba_conf()
        run("systemctl", "start", SMBD_UNIT)
    else:
        run("systemctl", "stop", SMBD_UNIT)
    running = smbd_active()
    with lock:
        runtime["running"] = running
        runtime["started_at"] = now() if running else None
        runtime["last_activity"] = now()
    event("share", "Carpeta encendida" if running else "Carpeta apagada")
    return running


def refresh_sessions():
    if not runtime["running"]:
        with lock:
            runtime["sessions"] = []
        return
    try:
        data = json.loads(run("smbstatus", "--json") or "{}")
    except ValueError:
        data = {}
    tcons = data.get("tcons", {}) or {}
    opens = data.get("open_files", {}) or {}
    sessions = []
    for s in (data.get("sessions", {}) or {}).values():
        pid = str((s.get("server_id") or {}).get("pid", ""))
        rip = s.get("remote_machine") or s.get("hostname") or ""
        m = re.match(r"ipv4:([\d.]+):", s.get("hostname", "") or "")
        ip = m.group(1) if m else rip
        nfiles = sum(
            1 for f in opens.values()
            for o in (f.get("opens") or {}).values()
            if str((o.get("server_id") or {}).get("pid", "")) == pid
        )
        mac = next((mc for mc, i in runtime["neigh"].items() if i == ip), None)
        d = device(mac) if mac else None
        sessions.append({
            "pid": pid,
            "user": s.get("username", ""),
            "ip": ip,
            "mac": mac,
            "device": d["name"] if d else None,
            "dialect": s.get("session_dialect", ""),
            "encryption": (s.get("encryption") or {}).get("cipher", "") or "-",
            "signing": (s.get("signing") or {}).get("cipher", "") or "-",
            "shares": sum(1 for t in tcons.values() if str((t.get("server_id") or {}).get("pid", "")) == pid),
            "open_files": nfiles,
        })
    with lock:
        runtime["sessions"] = sessions
        if sessions:
            runtime["last_activity"] = now()
            for s in sessions:
                d = device(s["mac"]) if s["mac"] else None
                if d:
                    d["last_seen"] = now()
                    d["last_ip"] = s["ip"]


def kill_session(pid):
    with lock:
        s = next((s for s in runtime["sessions"] if s["pid"] == str(pid)), None)
    if not s or not s["pid"].isdigit():
        return False
    try:
        os.kill(int(s["pid"]), 15)
    except OSError:
        return False
    event("session", f"Sesión expulsada: {s['device'] or s['ip']}")
    return True


def refresh_folder():
    if time.time() - runtime["folder"]["at"] < 10:
        return
    size = files = 0
    recent = []
    for root, dirs, names in os.walk(SHARE_PATH):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for n in names:
            p = os.path.join(root, n)
            try:
                st = os.lstat(p)
            except OSError:
                continue
            size += st.st_size
            files += 1
            recent.append((st.st_mtime, os.path.relpath(p, SHARE_PATH), st.st_size))
    recent.sort(reverse=True)
    try:
        du = os.statvfs(SHARE_PATH)
        free = du.f_bavail * du.f_frsize
    except OSError:
        free = None
    with lock:
        runtime["folder"] = {
            "size": size, "files": files, "free": free, "at": time.time(),
            "recent": [{"t": int(t), "name": n, "size": s} for t, n, s in recent[:8]],
        }


# ---------------------------------------------------------------- journald


def follow(args, handler):
    while True:
        try:
            p = subprocess.Popen(
                ["journalctl", "-f", "-n", "0", "-o", "json", *args],
                stdout=subprocess.PIPE, text=True,
            )
            for line in p.stdout:
                try:
                    handler(json.loads(line))
                except (ValueError, KeyError):
                    pass
        except OSError:
            pass
        time.sleep(3)


def msg_of(entry):
    m = entry.get("MESSAGE", "")
    if isinstance(m, list):
        m = bytes(m).decode("utf-8", "replace")
    return m


def on_kernel(entry):
    msg = msg_of(entry)
    if LOG_PREFIX.strip() not in msg:
        return
    f = dict(kv.split("=", 1) for kv in msg.split() if "=" in kv)
    parts = f.get("MAC", "").split(":")
    if len(parts) < 12:
        return
    mac = ":".join(parts[6:12]).lower()
    t = now()
    with lock:
        b = runtime["blocked"].get(mac)
        if not b:
            b = runtime["blocked"][mac] = {"mac": mac, "ip": f.get("SRC"), "count": 0, "first": t, "iface": f.get("IN")}
            event("blocked", f"Intento bloqueado desde {f.get('SRC')} ({mac})")
        b["count"] += 1
        b["last"] = t
        b["ip"] = f.get("SRC")


def on_audit(entry):
    # prefijo configurado: usuario|ip|máquina|operación|ok/fail|args...
    parts = msg_of(entry).split("|")
    if len(parts) < 5:
        return
    user, ip, machine, op, result = parts[:5]
    args = parts[5:]
    path = args[-1] if args else ""
    if op == "openat":
        if not path or path == "." or path.startswith(".") or "/." in path:
            return
        if os.path.isdir(os.path.join(SHARE_PATH, path)):
            return
        op = "escribió" if args and args[0] == "w" else "abrió"
    elif op in ("connect", "disconnect"):
        path = ""
        op = {"connect": "conectó", "disconnect": "desconectó"}[op]
        if result != "ok":
            op = "conexión rechazada"
    else:
        op = {"renameat": "renombró", "unlinkat": "borró", "mkdirat": "creó carpeta"}.get(op, op)
        if op == "renombró" and len(args) >= 2:
            path = f"{args[-2]} → {args[-1]}"
    with lock:
        act = runtime["activity"]
        if act and act[-1]["op"] == op and act[-1]["path"] == path and now() - act[-1]["t"] < 5:
            return
        act.append({"t": now(), "user": user, "ip": ip, "machine": machine, "op": op, "path": path})
        runtime["last_activity"] = now()


AUTH_RE = re.compile(r"user \[[^\]]*\]\\\[([^\]]*)\].*status \[(\w+)\].*remote host \[ipv4:([\d.]+):")


def on_smbd(entry):
    m = AUTH_RE.search(msg_of(entry))
    if not m:
        return
    user, status, ip = m.groups()
    with lock:
        runtime["auth"].append({"t": now(), "user": user, "ip": ip, "ok": status == "NT_STATUS_OK", "status": status})
    if status != "NT_STATUS_OK":
        event("auth", f"Login fallido ({status}) usuario '{user}' desde {ip}")


# ---------------------------------------------------------------- bucle


def loop():
    tick = 0
    while True:
        try:
            refresh_net()
            write_samba_conf()
            sync_firewall()
            running = smbd_active()
            with lock:
                if running and not runtime["running"]:
                    runtime["started_at"] = now()
                    runtime["last_activity"] = now()
                runtime["running"] = running
            refresh_sessions()
            if tick % 5 == 0:
                harvest_traffic()
                refresh_folder()
                with lock:
                    save_state()
            idle = state["settings"]["idle_minutes"]
            if running and idle and not runtime["sessions"] and now() - runtime["last_activity"] > idle * 60:
                set_share(False)
                event("share", f"Apagado automático tras {idle} min sin actividad")
        except Exception as e:  # el panel nunca debe morir por un error puntual
            print("loop error:", repr(e))
        tick += 1
        time.sleep(2)


# ---------------------------------------------------------------- API


def samba_user_ok():
    return USER in (run("pdbedit", "-L") or "")


def snapshot():
    with lock:
        net = runtime["net"]
        neigh = runtime["neigh"]
        online_ips = {s["ip"] for s in runtime["sessions"]}
        devs = []
        for d in state["devices"]:
            ip = neigh.get(d["mac"])
            devs.append({**d, "ip": ip, "reachable": ip is not None,
                         "connected": ip in online_ips,
                         "traffic": state["traffic"].get(d["mac"], {"up": 0, "down": 0})})
        cut = now() - 86400
        return {
            "running": runtime["running"],
            "started_at": runtime["started_at"],
            "idle_left": (
                max(0, state["settings"]["idle_minutes"] * 60 - (now() - runtime["last_activity"]))
                if runtime["running"] and state["settings"]["idle_minutes"] and not runtime["sessions"] else None
            ),
            "host": HOST,
            "share": SHARE,
            "share_path": SHARE_PATH,
            "user": USER,
            "addresses": [f"smb://{HOST}.local"] + [f"smb://{a}" for a in net["addresses"]],
            "net": net,
            "devices": devs,
            "blocked": sorted(runtime["blocked"].values(), key=lambda b: -b.get("last", 0)),
            "sessions": runtime["sessions"],
            "activity": list(runtime["activity"])[-60:][::-1],
            "auth": list(runtime["auth"])[-30:][::-1],
            "auth_fail_24h": sum(1 for a in runtime["auth"] if not a["ok"] and a["t"] > cut),
            "blocked_24h": sum(b["count"] for b in runtime["blocked"].values() if b.get("last", 0) > cut),
            "events": state["events"][-40:][::-1],
            "settings": state["settings"],
            "folder": runtime["folder"],
            "checks": {
                "firewall": runtime["fw_ok"],
                "samba_user": _samba_user_cache["ok"],
                "whitelist_only": True,
                "smb3": True,
                "guest_disabled": True,
                "panel_local_only": True,
            },
        }


_samba_user_cache = {"ok": False, "at": 0}


def api(method, path, body):
    if method == "GET" and path == "/api/state":
        if time.time() - _samba_user_cache["at"] > 15:
            _samba_user_cache.update(ok=samba_user_ok(), at=time.time())
        return 200, snapshot()

    if method != "POST":
        return 404, {"error": "no existe"}

    if path == "/api/share":
        return 200, {"running": set_share(bool(body.get("on")))}

    if path == "/api/devices/add":
        mac = str(body.get("mac", "")).strip().lower()
        name = str(body.get("name", "")).strip()[:40] or "Dispositivo"
        if not MAC_RE.match(mac):
            return 400, {"error": "MAC inválida"}
        with lock:
            d = device(mac)
            if d:
                d["name"] = name
            else:
                state["devices"].append({"mac": mac, "name": name, "added": now(), "last_seen": None, "last_ip": None})
            runtime["blocked"].pop(mac, None)
        event("device", f"Autorizado: {name} ({mac})")
        sync_firewall()
        return 200, {"ok": True}

    if path == "/api/devices/remove":
        mac = str(body.get("mac", "")).lower()
        with lock:
            d = device(mac)
            if not d:
                return 404, {"error": "no existe"}
            state["devices"].remove(d)
            victims = [s["pid"] for s in runtime["sessions"] if s["mac"] == mac]
        sync_firewall()
        for pid in victims:
            kill_session(pid)
        event("device", f"Revocado: {d['name']} ({mac})")
        return 200, {"ok": True}

    if path == "/api/sessions/kill":
        return 200, {"ok": kill_session(body.get("pid"))}

    if path == "/api/blocked/clear":
        with lock:
            runtime["blocked"].clear()
        return 200, {"ok": True}

    if path == "/api/settings":
        with lock:
            s = state["settings"]
            if "idle_minutes" in body:
                s["idle_minutes"] = max(0, min(24 * 60, int(body["idle_minutes"])))
            if "read_only" in body:
                s["read_only"] = bool(body["read_only"])
        write_samba_conf()
        event("settings", f"Ajustes: solo lectura={'sí' if s['read_only'] else 'no'}, auto-apagado={s['idle_minutes']} min")
        return 200, s

    if path == "/api/panic":
        pids = [s["pid"] for s in runtime["sessions"]]
        for pid in pids:
            kill_session(pid)
        set_share(False)
        event("panic", "Botón de pánico: sesiones cerradas y carpeta apagada")
        return 200, {"ok": True}

    return 404, {"error": "no existe"}


class Handler(BaseHTTPRequestHandler):
    server_version = "fileshare"

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; frame-ancestors 'none'",
        )
        self.end_headers()
        self.wfile.write(data)

    def _guard(self):
        # Anti DNS-rebinding: solo hosts locales.
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0]
        if host not in ("127.0.0.1", "localhost"):
            self._send(403, {"error": "host no permitido"})
            return False
        return True

    def _handle(self, method):
        if not self._guard():
            return
        path = self.path.split("?", 1)[0]
        if method == "GET" and path in ("/", "/index.html"):
            with open(HTML_PATH, "rb") as f:
                return self._send(200, f.read(), "text/html; charset=utf-8")
        if not path.startswith("/api/"):
            return self._send(404, {"error": "no existe"})
        if not secrets.compare_digest(self.headers.get("X-Token", ""), TOKEN):
            return self._send(401, {"error": "token inválido"})
        body = {}
        if method == "POST":
            n = int(self.headers.get("Content-Length") or 0)
            if n > 10000:
                return self._send(413, {"error": "muy grande"})
            try:
                body = json.loads(self.rfile.read(n) or b"{}")
            except ValueError:
                return self._send(400, {"error": "json inválido"})
        try:
            code, out = api(method, path, body)
        except (ValueError, TypeError) as e:
            code, out = 400, {"error": str(e)}
        self._send(code, out)

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")


def write_token():
    os.makedirs(RUN_DIR, exist_ok=True)
    try:
        os.unlink(TOKEN_FILE)
    except FileNotFoundError:
        pass
    fd = os.open(TOKEN_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    with os.fdopen(fd, "w") as f:
        f.write(TOKEN)
    try:
        pw = pwd.getpwnam(USER)
        os.chown(TOKEN_FILE, pw.pw_uid, pw.pw_gid)
    except (KeyError, PermissionError):
        pass


def main():
    os.makedirs(STATE_DIR, exist_ok=True)
    write_token()
    refresh_net()
    write_samba_conf()
    runtime["running"] = smbd_active()
    threading.Thread(target=follow, args=(["-k"], on_kernel), daemon=True).start()
    threading.Thread(target=follow, args=(["-t", "smbd_audit"], on_audit), daemon=True).start()
    threading.Thread(target=follow, args=(["-u", SMBD_UNIT], on_smbd), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()
    print(f"panel en http://127.0.0.1:{PORT}")
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
