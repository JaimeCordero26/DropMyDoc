#!/usr/bin/env bash
# Instalador para Linux con systemd (Arch, Debian/Ubuntu, Fedora...).
# En NixOS usa el módulo del flake en su lugar.
#
#   sudo ./linux/install.sh <usuario> [nombre-carpeta]
#   sudo ./linux/install.sh --uninstall
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
PREFIX=/opt/compartir
UNIT_FILE=/etc/systemd/system/fileshare-panel.service
SMB_CONF=/etc/samba/smb.conf
STATE_DIR=/var/lib/fileshare
PORT=8445
MARK="# gestionado por compartir"

die() { echo "error: $*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die "ejecuta con sudo"

# Nombre de la unidad de smbd según la distro.
smbd_unit() {
  for u in smb smbd samba-smbd; do
    if systemctl cat "$u.service" >/dev/null 2>&1; then echo "$u"; return; fi
  done
  die "no encuentro el servicio de smbd; instala samba (Arch: pacman -S samba, Debian: apt install samba, Fedora: dnf install samba)"
}

if [ "${1:-}" = "--uninstall" ]; then
  systemctl disable --now fileshare-panel 2>/dev/null || true
  systemctl stop "$(smbd_unit)" 2>/dev/null || true
  for c in INPUT OUTPUT; do
    while iptables -S "$c" | grep -q fileshare; do
      rule=$(iptables -S "$c" | grep fileshare | head -1 | sed 's/^-A /-D /')
      eval iptables "$rule"
    done
  done
  for ch in fileshare fileshare-acct-in fileshare-acct-out; do
    iptables -F "$ch" 2>/dev/null || true
    iptables -X "$ch" 2>/dev/null || true
  done
  rm -rf "$PREFIX" "$UNIT_FILE" /usr/local/bin/compartir
  systemctl daemon-reload
  if grep -q "$MARK" "$SMB_CONF" 2>/dev/null; then
    last=$(ls -t "$SMB_CONF".bak-* 2>/dev/null | head -1 || true)
    if [ -n "$last" ]; then mv "$last" "$SMB_CONF"; else rm -f "$SMB_CONF"; fi
  fi
  echo "Desinstalado. Estado conservado en $STATE_DIR (bórralo a mano si quieres)."
  exit 0
fi

USER_NAME="${1:-${SUDO_USER:-}}"
[ -n "$USER_NAME" ] || die "uso: sudo $0 <usuario> [nombre-carpeta]"
id "$USER_NAME" >/dev/null 2>&1 || die "el usuario $USER_NAME no existe"
SHARE="${2:-Compartida}"
HOME_DIR=$(getent passwd "$USER_NAME" | cut -d: -f6)
SHARE_PATH="$HOME_DIR/$SHARE"
GROUP=$(id -gn "$USER_NAME")
HOSTNAME_=$(hostname)
UNIT=$(smbd_unit)

for bin in python3 iptables ip curl jq journalctl; do
  command -v "$bin" >/dev/null || die "falta '$bin' (Arch: pacman -S --needed python iptables-nft iproute2 curl jq)"
done

echo "→ archivos en $PREFIX"
install -d "$PREFIX"
install -m 0644 "$REPO/panel/panel.py" "$REPO/panel/panel.html" "$PREFIX/"
install -m 0755 "$REPO/bin/compartir" /usr/local/bin/compartir

echo "→ carpeta $SHARE_PATH"
install -d -o "$USER_NAME" -g "$GROUP" -m 0755 "$SHARE_PATH"
install -d -m 0755 "$STATE_DIR"

echo "→ $SMB_CONF"
install -d /etc/samba
if [ -f "$SMB_CONF" ] && ! grep -q "$MARK" "$SMB_CONF"; then
  cp -a "$SMB_CONF" "$SMB_CONF.bak-$(date +%Y%m%d%H%M%S)"
  echo "  (respaldo del smb.conf anterior creado)"
fi
cat > "$SMB_CONF" <<EOF
$MARK
[global]
  server string = $HOSTNAME_
  netbios name = $HOSTNAME_
  security = user
  passdb backend = tdbsam
  map to guest = never
  restrict anonymous = 2
  ntlm auth = ntlmv2-only
  server min protocol = SMB3_00
  server smb encrypt = desired
  server signing = desired
  disable netbios = yes
  smb ports = 445
  load printers = no
  printing = bsd
  printcap name = /dev/null
  disable spoolss = yes
  logging = systemd
  log level = 1 auth_audit:3
  include = $STATE_DIR/smb-global.conf

[$SHARE]
  path = $SHARE_PATH
  valid users = $USER_NAME
  guest ok = no
  browseable = yes
  create mask = 0644
  directory mask = 0755
  vfs objects = catia fruit streams_xattr full_audit
  fruit:metadata = stream
  fruit:model = MacSamba
  fruit:posix_rename = yes
  fruit:veto_appledouble = no
  fruit:wipe_intentionally_left_blank_rfork = yes
  fruit:delete_empty_adfiles = yes
  full_audit:prefix = %u|%I|%m
  full_audit:success = connect disconnect openat renameat unlinkat mkdirat
  full_audit:failure = connect
  full_audit:facility = local5
  full_audit:priority = notice
  include = $STATE_DIR/smb-share.conf
EOF

echo "→ servicio fileshare-panel (smbd: $UNIT.service, sin autoarranque)"
systemctl disable --now "$UNIT" nmb 2>/dev/null || true
cat > "$UNIT_FILE" <<EOF
[Unit]
Description=Panel y control de acceso de la carpeta compartida SMB
After=network.target

[Service]
ExecStart=$(command -v python3) -u $PREFIX/panel.py
Environment=FILESHARE_USER=$USER_NAME
Environment=FILESHARE_SHARE=$SHARE
Environment=FILESHARE_PATH=$SHARE_PATH
Environment=FILESHARE_STATE=$STATE_DIR
Environment=FILESHARE_PORT=$PORT
Environment=FILESHARE_HOST=$HOSTNAME_
Environment=FILESHARE_HTML=$PREFIX/panel.html
Environment=FILESHARE_SMBD_UNIT=$UNIT
Restart=always
RestartSec=2
StateDirectory=fileshare
RuntimeDirectory=fileshare
ProtectHome=read-only
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now fileshare-panel

cat <<EOF

Listo. Pasos siguientes:
  1. Contraseña SMB (distinta de la de tu sesión):  sudo smbpasswd -a $USER_NAME
  2. compartir on && compartir panel

Si usas firewalld o ufw, esos firewalls también deben permitir el puerto 445/tcp;
el filtrado por MAC lo sigue haciendo compartir.
EOF
