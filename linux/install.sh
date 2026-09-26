#!/usr/bin/env bash
# Instalador para Linux con systemd (Arch, Debian/Ubuntu, Fedora...).
# En NixOS usa el módulo del flake en su lugar.
#
#   sudo ./linux/install.sh <usuario> [nombre-carpeta]
#   sudo ./linux/install.sh --uninstall
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
PREFIX=/opt/dropmydoc
UNIT_FILE=/etc/systemd/system/dropmydoc.service
SMB_CONF=/etc/samba/smb.conf
STATE_DIR=/var/lib/dropmydoc
PORT=8445
MARK="# gestionado por dropmydoc"

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
  systemctl disable --now dropmydoc 2>/dev/null || true
  systemctl stop "$(smbd_unit)" 2>/dev/null || true
  for ipt in iptables ip6tables; do
    for c in INPUT OUTPUT; do
      while $ipt -S "$c" 2>/dev/null | grep -q dropmydoc; do
        rule=$($ipt -S "$c" | grep dropmydoc | head -1 | sed 's/^-A /-D /')
        eval $ipt "$rule"
      done
    done
    for ch in dropmydoc dropmydoc-acct-in dropmydoc-acct-out; do
      $ipt -F "$ch" 2>/dev/null || true
      $ipt -X "$ch" 2>/dev/null || true
    done
  done
  rm -rf "$PREFIX" "$UNIT_FILE" /usr/local/bin/dmd
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
SHARE="${2:-DropMyDoc}"
HOME_DIR=$(getent passwd "$USER_NAME" | cut -d: -f6)
SHARE_PATH="$HOME_DIR/$SHARE"
GROUP=$(id -gn "$USER_NAME")
HOSTNAME_=$(hostname)
UNIT=$(smbd_unit)

for bin in python3 iptables ip6tables ip curl jq journalctl useradd smbpasswd; do
  command -v "$bin" >/dev/null || die "falta '$bin' (Arch: pacman -S --needed python iptables-nft iproute2 curl jq)"
done

echo "→ archivos en $PREFIX"
install -d "$PREFIX"
install -m 0644 "$REPO/panel/panel.py" "$REPO/panel/panel.html" "$PREFIX/"
install -m 0755 "$REPO/bin/dmd" /usr/local/bin/dmd

echo "→ carpeta $SHARE_PATH"
install -d -o "$USER_NAME" -g "$GROUP" -m 0755 "$SHARE_PATH"
install -d -m 0755 "$STATE_DIR"
getent group dropmydoc >/dev/null || groupadd --system dropmydoc

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
  valid users = @dropmydoc
  force user = $USER_NAME
  force group = $GROUP
  root preexec = /usr/bin/env PATH=$(dirname "$(command -v ip)"):/usr/bin:/bin $(command -v python3) $PREFIX/panel.py --check %U %I
  root preexec close = yes
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
  full_audit:prefix = %U|%I|%m
  full_audit:success = connect disconnect openat renameat unlinkat mkdirat
  full_audit:failure = connect
  full_audit:facility = local5
  full_audit:priority = notice
  include = $STATE_DIR/smb-share.conf
EOF

echo "→ servicio dropmydoc (smbd: $UNIT.service, sin autoarranque)"
systemctl disable --now "$UNIT" nmb 2>/dev/null || true
cat > "$UNIT_FILE" <<EOF
[Unit]
Description=Panel y control de acceso de la carpeta compartida SMB
After=network.target

[Service]
ExecStart=$(command -v python3) -u $PREFIX/panel.py
Environment=DROPMYDOC_USER=$USER_NAME
Environment=DROPMYDOC_SHARE=$SHARE
Environment=DROPMYDOC_PATH=$SHARE_PATH
Environment=DROPMYDOC_STATE=$STATE_DIR
Environment=DROPMYDOC_PORT=$PORT
Environment=DROPMYDOC_HOST=$HOSTNAME_
Environment=DROPMYDOC_HTML=$PREFIX/panel.html
Environment=DROPMYDOC_SMBD_UNIT=$UNIT
Restart=always
RestartSec=2
StateDirectory=dropmydoc
RuntimeDirectory=dropmydoc
ProtectHome=read-only
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now dropmydoc

cat <<EOF

Listo. Pasos siguientes:
  1. dmd panel  → crea un usuario por dispositivo (iphone, windows, ...)
  2. dmd on

Si usas firewalld o ufw, esos firewalls también deben permitir el puerto 445/tcp;
el filtrado por MAC lo sigue haciendo dropmydoc.
EOF
