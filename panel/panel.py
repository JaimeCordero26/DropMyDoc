"""Panel local y control de acceso para la carpeta compartida SMB.

Corre como root (necesita iptables, systemctl, smbcontrol y useradd). Escucha
solo en 127.0.0.1 y exige un token (header X-Token) para toda la API; el token
se escribe en /run/dropmydoc/token, legible solo por el usuario dueño.

Con `--check USUARIO IP` actúa como `root preexec` de Samba: permite o rechaza
la conexión según el usuario esté habilitado y, si tiene dispositivos
vinculados, según la MAC de la IP que se conecta. Con "aprender MAC" activo, un
login correcto desde una MAC desconocida (p. ej. la MAC privada que iOS usa en
cada red Wi-Fi) actualiza la MAC del dispositivo de ese usuario en vez de pedir
aprobación manual.

Funciona igual por IPv4 e IPv6: las reglas se aplican con iptables e ip6tables.
"""

import grp
import ipaddress
import json
import os
import pwd
import re
import secrets
import subprocess
import sys
import syslog
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

USER = os.environ.get("DROPMYDOC_USER", "alecor")
SHARE = os.environ.get("DROPMYDOC_SHARE", "DropMyDoc")
SHARE_PATH = os.environ.get("DROPMYDOC_PATH", f"/home/{USER}/{SHARE}")
STATE_DIR = os.environ.get("DROPMYDOC_STATE", "/var/lib/dropmydoc")
RUN_DIR = os.environ.get("DROPMYDOC_RUN", "/run/dropmydoc")
PORT = int(os.environ.get("DROPMYDOC_PORT", "8445"))
HOST = os.environ.get("DROPMYDOC_HOST", os.uname().nodename)
SMBD_UNIT = os.environ.get("DROPMYDOC_SMBD_UNIT", "samba-smbd")
HTML_PATH = os.environ.get(
    "DROPMYDOC_HTML", os.path.join(os.path.dirname(__file__), "panel.html")
)

STATE_FILE = os.path.join(STATE_DIR, "state.json")
SMB_GLOBAL_CONF = os.path.join(STATE_DIR, "smb-global.conf")
SMB_SHARE_CONF = os.path.join(STATE_DIR, "smb-share.conf")
TOKEN_FILE = os.path.join(RUN_DIR, "token")

SMB_GROUP = "dropmydoc"
USER_RE = re.compile(r"^[a-z][a-z0-9_-]{1,30}$")
PASS_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"
CHECK_TAG = "dropmydoc-check"

CHAIN = "dropmydoc"
ACCT_IN = "dropmydoc-acct-in"
ACCT_OUT = "dropmydoc-acct-out"
LOG_PREFIX = "DROPMYDOC-DENY "
MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
IPTABLES = ("iptables", "ip6tables")
# conexiones nuevas por IP desde MAC desconocidas cuando se aprende la MAC al hacer login
LEARN_LIMIT = ["--hashlimit-upto", "10/min", "--hashlimit-burst", "10",
               "--hashlimit-mode", "srcip", "--hashlimit-name", "dropmydoc"]

lock = threading.RLock()
TOKEN = secrets.token_urlsafe(32)


def now():
    return int(time.time())


def run(*cmd, check=False, input=None):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=15, input=input)
    except (OSError, subprocess.TimeoutExpired):
        return None if check else ""
    if check and p.returncode != 0:
        return None
    return p.stdout


def ok(*cmd, input=None):
    return run(*cmd, check=True, input=input) is not None


# ---------------------------------------------------------------- estado


def default_state():
    return {
        "devices": [],
        "users": [],
        "settings": {"idle_minutes": 30, "read_only": False, "learn_mac": True},
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
    "net": {"addresses": [], "subnets": [], "subnets6": [], "ssid": None, "ifaces": []},
    "neigh": {},  # mac -> ip (IPv4 si hay, si no IPv6)
    "neigh_ips": {},  # mac -> [todas sus IPs, v4 y v6]
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


def smb_user(name):
    name = (name or "").lower()
    return next((u for u in state["users"] if u["name"] == name), None)


def user_stats(u):
    return u.setdefault("stats", {
        "logins": 0, "fails": 0, "written": 0, "read": 0, "deleted": 0,
        "up": 0, "down": 0, "last_login": None, "last_ip": None,
    })


# ---------------------------------------------------------------- red


def clean_ip(ip):
    """Normaliza la IP que da Samba: sin zona (%iface) ni prefijo IPv4-mapeado."""
    ip = (ip or "").split("%", 1)[0].strip("[]")
    return ip[7:] if ip.startswith("::ffff:") and "." in ip else ip


def read_neigh():
    """mac -> [ips] a partir de la tabla de vecinos IPv4 e IPv6."""
    out = {}
    try:
        data = json.loads(run("ip", "-j", "neigh") or "[]")
    except ValueError:
        data = []
    for n in data:
        mac = (n.get("lladdr") or "").lower()
        if mac and "FAILED" not in n.get("state", []) and n.get("dst"):
            out.setdefault(mac, []).append(n["dst"])
    return out


def refresh_net():
    addrs, subnets, subnets6, ifaces = [], [], [], []
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
            net = str(ipaddress.ip_interface(f"{a['local']}/{a['prefixlen']}").network)
            if a.get("family") == "inet":
                addrs.append(a["local"])
                subnets.append(net)
                ifaces.append(name)
            elif a.get("family") == "inet6" and a.get("scope") == "global" and a["prefixlen"] < 128:
                subnets6.append(net)
    ssid = None
    for line in (run("nmcli", "-t", "-f", "active,ssid", "dev", "wifi") or "").splitlines():
        if line.startswith("yes:"):
            ssid = line[4:] or None
    neigh_ips = read_neigh()
    neigh = {}
    for mac, ips in neigh_ips.items():
        neigh[mac] = next((i for i in ips if ":" not in i), ips[0])
    with lock:
        runtime["net"] = {"addresses": addrs, "subnets": subnets, "subnets6": sorted(set(subnets6)),
                          "ssid": ssid, "ifaces": ifaces}
        runtime["neigh"] = neigh
        runtime["neigh_ips"] = neigh_ips


def mac_of_ip(ip):
    ip = clean_ip(ip)
    with lock:
        return next((m for m, ips in runtime["neigh_ips"].items() if ip in ips), None)


# ---------------------------------------------------------------- firewall


def fw_rules():
    rules = []
    for d in state["devices"]:
        rules.append(["-m", "mac", "--mac-source", d["mac"], "-j", "ACCEPT"])
    if state["settings"].get("learn_mac"):
        # MAC desconocida: pasa a Samba (con límite de ritmo) y solo se queda si el login es correcto
        rules.append(["-m", "hashlimit", *LEARN_LIMIT, "-j", "ACCEPT"])
    rules.append(["-m", "limit", "--limit", "20/min", "--limit-burst", "10",
                  "-j", "LOG", "--log-level", "info", "--log-prefix", LOG_PREFIX])
    rules.append(["-j", "DROP"])
    return rules


def ensure_chain(ipt, name):
    if not ok(ipt, "-n", "-L", name):
        run(ipt, "-N", name)


def ensure_jump(ipt, parent, spec):
    if not ok(ipt, "-C", parent, *spec):
        run(ipt, "-I", parent, "1", *spec)


_fw_applied = {"key": None, "dump": None}


def fw_dump():
    return "".join(run(ipt, "-S", c) for ipt in IPTABLES for c in (CHAIN, ACCT_IN, ACCT_OUT))


def sync_firewall():
    with lock:
        rules = fw_rules()
        macs = [d["mac"] for d in state["devices"]]
        ips = sorted({ip for m in macs for ip in runtime["neigh_ips"].get(m, [])})
    for ipt in IPTABLES:
        for c in (CHAIN, ACCT_IN, ACCT_OUT):
            ensure_chain(ipt, c)

    key = json.dumps([rules, macs, ips])
    if key != _fw_applied["key"] or fw_dump() != _fw_applied["dump"]:
        harvest_traffic()
        for ipt in IPTABLES:
            v6 = ipt == "ip6tables"
            for c in (CHAIN, ACCT_IN, ACCT_OUT):
                run(ipt, "-F", c)
            for r in rules:
                run(ipt, "-A", CHAIN, *r)
            for m in macs:
                run(ipt, "-A", ACCT_IN, "-m", "mac", "--mac-source", m, "-j", "RETURN")
            for ip in ips:
                if (":" in ip) == v6:
                    run(ipt, "-A", ACCT_OUT, "-d", ip, "-j", "RETURN")
        runtime["acct_prev"] = {}
        _fw_applied["key"] = key
        _fw_applied["dump"] = fw_dump()

    new445 = ["-p", "tcp", "--dport", "445", "-m", "conntrack", "--ctstate", "NEW", "-j", CHAIN]
    fw_ok = True
    for ipt in IPTABLES:
        parent = "nixos-fw" if ok(ipt, "-n", "-L", "nixos-fw") else "INPUT"
        ensure_jump(ipt, parent, new445)
        ensure_jump(ipt, "INPUT", ["-p", "tcp", "--dport", "445", "-j", ACCT_IN])
        ensure_jump(ipt, "OUTPUT", ["-p", "tcp", "--sport", "445", "-j", ACCT_OUT])
        fw_ok = fw_ok and ok(ipt, "-C", parent, *new445)
    with lock:
        runtime["fw_ok"] = fw_ok


def harvest_traffic():
    """Suma los contadores de iptables/ip6tables a los totales persistentes por MAC."""
    with lock:
        ip_to_mac = {ip: m for m, ips in runtime["neigh_ips"].items() for ip in ips}
        mac_to_user = {s["mac"]: s["user"] for s in runtime["sessions"] if s["mac"]}
        prev = runtime["acct_prev"]
        for ipt in IPTABLES:
            for chain, direction in ((ACCT_IN, "up"), (ACCT_OUT, "down")):
                out = run(ipt, "-L", chain, "-v", "-x", "-n") or ""
                for line in out.splitlines()[2:]:
                    parts = line.split()
                    if len(parts) < 3 or not parts[1].isdigit():
                        continue
                    nbytes = int(parts[1])
                    if direction == "up":
                        m = re.search(r"MAC\s*([0-9A-Fa-f:]{17})", line)
                        mac = m.group(1).lower() if m else None
                    else:
                        mac = next((ip_to_mac[p.split("/")[0]] for p in parts[2:]
                                    if p.split("/")[0] in ip_to_mac), None)
                    if not mac:
                        continue
                    k = f"{ipt}|{chain}|{mac}"
                    delta = nbytes - prev.get(k, 0)
                    if delta < 0:
                        delta = nbytes
                    prev[k] = nbytes
                    t = state["traffic"].setdefault(mac, {"up": 0, "down": 0})
                    t[direction] += delta
                    u = smb_user(mac_to_user.get(mac))
                    if u and delta:
                        user_stats(u)[direction] += delta


# ---------------------------------------------------------------- samba


def write_samba_conf():
    with lock:
        subnets = runtime["net"]["subnets"] + runtime["net"]["subnets6"]
        ro = state["settings"]["read_only"]
        disabled = [u["name"] for u in state["users"] if not u.get("enabled", True)]
        readers = [u["name"] for u in state["users"] if u.get("perm") == "ro"]
    g = f"hosts allow = 127.0.0.1 ::1 fe80::/10 {' '.join(subnets)}\nhosts deny = ALL\n"
    s = f"read only = {'yes' if ro else 'no'}\n"
    if disabled:
        s += f"invalid users = {' '.join(disabled)}\n"
    if readers:
        s += f"read list = {' '.join(readers)}\n"
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
        m = re.match(r"ipv[46]:\[?(.+?)\]?:\d+$", s.get("hostname", "") or "")
        ip = clean_ip(m.group(1) if m else rip)
        nfiles = sum(
            1 for f in opens.values()
            for o in (f.get("opens") or {}).values()
            if str((o.get("server_id") or {}).get("pid", "")) == pid
        )
        mac = mac_of_ip(ip)
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
    event("session", f"Sesión expulsada: {s['user']} desde {s['device'] or s['ip']}")
    return True


def kill_user_sessions(name):
    for pid in [s["pid"] for s in runtime["sessions"] if s["user"].lower() == name]:
        kill_session(pid)


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
        u = smb_user(user)
        if u:
            key = {"escribió": "written", "abrió": "read", "borró": "deleted"}.get(op)
            if key:
                user_stats(u)[key] += 1


AUTH_RE = re.compile(r"user \[[^\]]*\]\\\[([^\]]*)\].*status \[(\w+)\].*remote host \[ipv[46]:\[?([0-9a-fA-F.:%\w]+?)\]?:\d+\]")


def on_smbd(entry):
    m = AUTH_RE.search(msg_of(entry))
    if not m:
        return
    user, status, ip = m.groups()
    ip = clean_ip(ip)
    with lock:
        runtime["auth"].append({"t": now(), "user": user, "ip": ip, "ok": status == "NT_STATUS_OK", "status": status})
        u = smb_user(user)
        if u:
            st = user_stats(u)
            if status == "NT_STATUS_OK":
                st["logins"] += 1
                st["last_login"] = now()
                st["last_ip"] = ip
            else:
                st["fails"] += 1
    if status != "NT_STATUS_OK":
        event("auth", f"Login fallido ({status}) usuario '{user}' desde {ip}")


def on_check(entry):
    # DENY|LEARN|ALLOW + |usuario|ip|mac|motivo  (lo escribe `panel.py --check`)
    parts = msg_of(entry).split("|")
    if len(parts) < 5:
        return
    verdict, user, ip, mac, reason = parts[:5]
    if verdict == "DENY":
        event("auth", f"Conexión rechazada a '{user}' desde {ip} {mac}: {reason}")
    elif verdict == "LEARN":
        learn_mac(user, mac)


def learn_mac(user, mac):
    """Login correcto desde una MAC desconocida: la asocia al dispositivo del usuario.

    Si el usuario tiene un solo dispositivo vinculado, se le cambia la MAC (iOS usa
    una MAC privada distinta en cada red). Si no tiene ninguno, se crea uno y se
    vincula; si tiene varios, se agrega uno nuevo con el nombre de la red.
    """
    with lock:
        u = smb_user(user)
        if not u or not MAC_RE.match(mac) or device(mac):
            return
        ssid = runtime["net"]["ssid"]
        linked = [d for d in (device(m) for m in u.get("devices", [])) if d]
        if len(linked) == 1:
            d = linked[0]
            old = d["mac"]
            d["mac"] = mac
            u["devices"] = sorted({mac if m == old else m for m in u["devices"]})
            state["traffic"][mac] = state["traffic"].pop(old, {"up": 0, "down": 0})
            msg = f"MAC actualizada: {d['name']} {old} → {mac}"
        else:
            name = u.get("label") or u["name"]
            if linked and ssid:
                name = f"{name} ({ssid})"
            d = {"mac": mac, "name": name[:40], "added": now(), "last_seen": now(), "last_ip": None}
            state["devices"].append(d)
            u["devices"] = sorted(set(u.get("devices", [])) | {mac})
            msg = f"Dispositivo aprendido: {d['name']} ({mac}) al entrar como '{u['name']}'"
        d["network"] = ssid
        runtime["blocked"].pop(mac, None)
    event("device", msg + (f" en la red {ssid}" if ssid else ""))


# ---------------------------------------------------------------- usuarios


def nologin_shell():
    for p in ("/run/current-system/sw/bin/nologin", "/usr/sbin/nologin", "/usr/bin/nologin", "/sbin/nologin"):
        if os.path.exists(p):
            return p
    return "/bin/false"


def gen_password():
    raw = "".join(secrets.choice(PASS_ALPHABET) for _ in range(12))
    return f"{raw[:4]}-{raw[4:8]}-{raw[8:]}"


def set_smb_password(name, password):
    return ok("smbpasswd", "-s", "-a", name, input=f"{password}\n{password}\n")


def create_user(name, label, perm, password):
    try:
        grp.getgrnam(SMB_GROUP)
    except KeyError:
        run("groupadd", "--system", SMB_GROUP)
    created = False
    try:
        pwd.getpwnam(name)
    except KeyError:
        created = True
        if not ok("useradd", "--system", "--no-create-home", "--home-dir", "/var/empty",
                  "--shell", nologin_shell(), "--gid", SMB_GROUP,
                  "--comment", f"dropmydoc: {label}", name):
            return "no se pudo crear el usuario del sistema"
    if not set_smb_password(name, password):
        if created:
            run("userdel", name)
        return "no se pudo fijar la contraseña SMB"
    with lock:
        state["users"].append({
            "name": name, "label": label, "perm": perm, "enabled": True,
            "devices": [], "created": now(),
        })
        user_stats(state["users"][-1])
        save_state()
    write_samba_conf()
    return None


def delete_user(name):
    kill_user_sessions(name)
    run("smbpasswd", "-x", name)
    run("userdel", name)
    with lock:
        u = smb_user(name)
        if u:
            state["users"].remove(u)
            save_state()
    write_samba_conf()


def check_main(user, ip):
    """root preexec de Samba: exit 0 permite, exit 1 corta la conexión."""
    syslog.openlog(CHECK_TAG, 0, syslog.LOG_AUTH)
    user = user.lower()
    ip = clean_ip(ip)
    u = smb_user(user)
    mac = next((m for m, ips in read_neigh().items() if ip in ips), "")
    if not mac:
        try:
            with open("/proc/net/arp") as f:
                for line in f.readlines()[1:]:
                    cols = line.split()
                    if len(cols) >= 4 and cols[0] == ip:
                        mac = cols[3].lower()
        except OSError:
            pass
    local = ip in ("127.0.0.1", "::1")
    verdict, reason = "ALLOW", None
    if not u:
        reason = "usuario no gestionado por dropmydoc"
    elif not u.get("enabled", True):
        reason = "usuario deshabilitado"
    elif local:
        pass
    elif not device(mac):
        # el firewall solo deja pasar MAC desconocidas si "aprender MAC" está activo
        if state["settings"].get("learn_mac") and MAC_RE.match(mac):
            verdict = "LEARN"
        else:
            reason = "dispositivo no autorizado"
    elif u.get("devices") and mac not in u["devices"]:
        reason = "dispositivo no vinculado a este usuario"
    if reason:
        verdict = "DENY"
    syslog.syslog(syslog.LOG_NOTICE, f"{verdict}|{user}|{ip}|{mac}|{reason or ''}")
    sys.exit(1 if reason else 0)


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


def samba_users():
    return {line.split(":", 1)[0] for line in (run("pdbedit", "-L") or "").splitlines() if ":" in line}


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
        online_users = {s["user"].lower() for s in runtime["sessions"]}
        dev_names = {d["mac"]: d["name"] for d in state["devices"]}
        users = []
        for u in state["users"]:
            users.append({
                **u,
                "stats": user_stats(u),
                "online": u["name"] in online_users,
                "has_password": u["name"] in _samba_user_cache["names"],
                "device_names": [dev_names.get(m, m) for m in u.get("devices", [])],
            })
        for d in devs:
            d["users"] = [u["name"] for u in state["users"] if d["mac"] in u.get("devices", [])]
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
            "users": users,
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
                "learn_mac": state["settings"]["learn_mac"],
                "samba_user": any(u.get("enabled", True) for u in state["users"]),
                "whitelist_only": True,
                "smb3": True,
                "guest_disabled": True,
                "panel_local_only": True,
            },
        }


_samba_user_cache = {"names": set(), "at": 0}


def api(method, path, body):
    if method == "GET" and path == "/api/state":
        if time.time() - _samba_user_cache["at"] > 15:
            _samba_user_cache.update(names=samba_users(), at=time.time())
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
            for u in state["users"]:
                if mac in u.get("devices", []):
                    u["devices"].remove(mac)
            victims = [s["pid"] for s in runtime["sessions"] if s["mac"] == mac]
        sync_firewall()
        for pid in victims:
            kill_session(pid)
        event("device", f"Revocado: {d['name']} ({mac})")
        return 200, {"ok": True}

    if path == "/api/users/add":
        name = str(body.get("name", "")).strip().lower()
        label = str(body.get("label", "")).strip()[:40] or name
        perm = "ro" if body.get("perm") == "ro" else "rw"
        password = str(body.get("password") or "") or gen_password()
        if not USER_RE.match(name):
            return 400, {"error": "Nombre inválido: minúsculas, números, - o _, empezando por letra (2-31)."}
        if len(password) < 8:
            return 400, {"error": "La contraseña debe tener al menos 8 caracteres."}
        if smb_user(name):
            return 409, {"error": "Ese usuario ya existe."}
        try:
            pwd.getpwnam(name)
            return 409, {"error": f"'{name}' ya es un usuario del sistema; elige otro nombre."}
        except KeyError:
            pass
        err = create_user(name, label, perm, password)
        if err:
            return 500, {"error": err}
        _samba_user_cache["at"] = 0
        event("user", f"Usuario creado: {name} ({label}, {'solo lectura' if perm == 'ro' else 'lectura y escritura'})")
        return 200, {"ok": True, "name": name, "password": password}

    if path == "/api/users/update":
        name = str(body.get("name", "")).lower()
        with lock:
            u = smb_user(name)
            if not u:
                return 404, {"error": "no existe"}
            changes = []
            if "label" in body:
                u["label"] = str(body["label"]).strip()[:40] or name
            if "perm" in body:
                u["perm"] = "ro" if body["perm"] == "ro" else "rw"
                changes.append("solo lectura" if u["perm"] == "ro" else "lectura y escritura")
            if "enabled" in body:
                u["enabled"] = bool(body["enabled"])
                changes.append("habilitado" if u["enabled"] else "deshabilitado")
            if "devices" in body:
                macs = [str(m).lower() for m in body["devices"]]
                if not all(MAC_RE.match(m) for m in macs):
                    return 400, {"error": "MAC inválida"}
                u["devices"] = sorted(set(macs))
                changes.append(f"{len(u['devices'])} dispositivo(s) vinculado(s)" if u["devices"] else "cualquier dispositivo autorizado")
            save_state()
        if "enabled" in body:
            run("smbpasswd", "-e" if u["enabled"] else "-d", name)
        write_samba_conf()
        # los permisos se evalúan al conectar: se expulsa para que apliquen ya
        if {"perm", "enabled", "devices"} & body.keys():
            kill_user_sessions(name)
        if changes:
            event("user", f"Usuario {name}: {', '.join(changes)}")
        return 200, {"ok": True}

    if path == "/api/users/password":
        name = str(body.get("name", "")).lower()
        if not smb_user(name):
            return 404, {"error": "no existe"}
        password = str(body.get("password") or "") or gen_password()
        if len(password) < 8:
            return 400, {"error": "La contraseña debe tener al menos 8 caracteres."}
        if not set_smb_password(name, password):
            return 500, {"error": "no se pudo cambiar la contraseña"}
        kill_user_sessions(name)
        event("user", f"Contraseña cambiada: {name}")
        return 200, {"ok": True, "name": name, "password": password}

    if path == "/api/users/remove":
        name = str(body.get("name", "")).lower()
        if not smb_user(name):
            return 404, {"error": "no existe"}
        delete_user(name)
        _samba_user_cache["at"] = 0
        event("user", f"Usuario eliminado: {name}")
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
            if "learn_mac" in body:
                s["learn_mac"] = bool(body["learn_mac"])
        write_samba_conf()
        sync_firewall()
        event("settings", f"Ajustes: solo lectura={'sí' if s['read_only'] else 'no'}, "
                          f"aprender MAC={'sí' if s['learn_mac'] else 'no'}, auto-apagado={s['idle_minutes']} min")
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
    server_version = "dropmydoc"

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
    threading.Thread(target=follow, args=(["-t", CHECK_TAG], on_check), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()
    print(f"panel en http://127.0.0.1:{PORT}")
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--check":
        check_main(sys.argv[2], sys.argv[3])
    main()
