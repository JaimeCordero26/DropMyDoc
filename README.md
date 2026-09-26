# compartir

Una carpeta de tu laptop compartida por SMB para abrirla desde la app **Archivos** del iPhone (o cualquier cliente SMB) sin instalar nada en el teléfono. Solo entran los dispositivos que apruebes. Se enciende y se apaga cuando quieras, y trae un panel web local para ver quién está conectado y qué está pasando.

## Cómo protege el acceso

1. **Firewall por MAC.** El puerto 445 solo acepta conexiones nuevas de las MAC que están en la whitelist. Todo lo demás se descarta y se registra como "intento bloqueado".
2. **Samba `hosts allow`.** Solo acepta la subred local actual; el panel la regenera cuando cambias de red.
3. **Usuario y contraseña SMB.** Un único usuario válido, invitados deshabilitados, SMB3 como mínimo y solo NTLMv2.
4. **Encendido bajo demanda.** `smbd` no arranca con el sistema. El panel lo apaga solo tras N minutos sin sesiones (30 por defecto).
5. **Panel solo en `127.0.0.1`.** Pide un token que solo puede leer tu usuario (`/run/fileshare/token`) y comprueba el header `Host` para impedir DNS rebinding.

## Panel (`http://127.0.0.1:8445`, se abre con `compartir panel`)

- Whitelist de dispositivos: estado (conectado / en la red / fuera), IP actual, último uso y tráfico subido y descargado. Se pueden revocar.
- Intentos bloqueados, cada uno con botón **Aprobar**. Así se agrega un dispositivo nuevo.
- Sesiones activas: dialecto SMB, cifrado, firma y archivos abiertos. Se pueden expulsar.
- Actividad de archivos (abrió, escribió, renombró, borró) sacada de `vfs_full_audit`.
- Logins correctos y fallidos (`auth_audit`) y eventos.
- Ajustes: solo lectura, auto-apagado y botón de **pánico** (expulsa a todos y apaga).

## Estructura

```
panel/panel.py     daemon (Python stdlib, corre como root): firewall, samba, API, logs
panel/panel.html   interfaz del panel
bin/compartir      CLI: compartir on | off | status | panel
nixos/module.nix   módulo NixOS (services.compartir)
linux/install.sh   instalador para otras distros con systemd
flake.nix          expone nixosModules.default
```

## Instalación

### NixOS (flake)

```nix
# flake.nix
inputs.compartir.url = "github:JaimeCordero26/compartir";

# en los módulos del sistema
imports = [ inputs.compartir.nixosModules.default ];
services.compartir = {
  enable = true;
  user = "alecor";
};
```

Luego:

```sh
sudo nixos-rebuild switch --flake .#<host>
sudo smbpasswd -a alecor
```

### Arch, Debian/Ubuntu, Fedora u otra distro con systemd

```sh
# Arch
sudo pacman -S --needed samba python iptables-nft iproute2 curl jq
# Debian/Ubuntu
sudo apt install samba python3 iptables iproute2 curl jq

sudo ./linux/install.sh "$USER"        # nombre de carpeta opcional; por defecto ~/Compartida
sudo smbpasswd -a "$USER"
compartir on && compartir panel
```

El instalador hace un respaldo del `/etc/samba/smb.conf` que ya tengas antes de reemplazarlo. Para desinstalar: `sudo ./linux/install.sh --uninstall`.

Si usas **firewalld** o **ufw**, tienes que abrir 445/tcp en ellos. El filtrado por MAC lo sigue haciendo `compartir`, porque un DROP en su cadena gana de todas formas.

### Windows

**Todavía no es compatible.** El panel depende de iptables, systemd/journald y Samba. Para portarlo haría falta:

- Usar el servidor SMB nativo (`New-SmbShare` con `-FullAccess` restringido a un usuario local) en lugar de Samba.
- Usar reglas de Windows Defender Firewall en lugar de iptables. Filtran por IP, no por MAC, así que la whitelist tendría que traducir MAC → IP a partir de `Get-NetNeighbor`.
- Leer sesiones y archivos abiertos con `Get-SmbSession` y `Get-SmbOpenFile`, y auditar desde el Visor de eventos (`Microsoft-Windows-SMBServer/Audit`).

Lo razonable sería separar en `panel.py` un "backend" por sistema operativo (firewall, servicio, sesiones, logs) y dejar la API y la interfaz iguales.

## Conectar el iPhone

1. `compartir on`
2. Archivos → **···** → *Conectarse al servidor* → `smb://<host>.local` o `smb://<ip>` (el panel muestra las dos).
3. *Usuario registrado* → tu usuario y la contraseña SMB.
4. El primer intento de un dispositivo nuevo falla a propósito. Aparece en **Intentos bloqueados**; lo apruebas y vuelves a intentar.

Notas:

- iOS usa una **MAC privada distinta en cada red Wi-Fi**. En Ajustes → Wi-Fi → (i) → Dirección privada, elige **Fija** para que no cambie dentro de esa red. En una red nueva hay que aprobarlo una vez más.
- Muchas redes públicas o universitarias aíslan a los clientes entre sí. Si el iPhone no llega a la laptop, usa el hotspot del teléfono.

## Desarrollo

El panel se puede ejecutar sin root para trabajar en la interfaz. Los comandos privilegiados fallan en silencio:

```sh
mkdir -p /tmp/fs/{st,run,share}
FILESHARE_STATE=/tmp/fs/st FILESHARE_RUN=/tmp/fs/run FILESHARE_PATH=/tmp/fs/share \
FILESHARE_PORT=18445 python3 panel/panel.py
# abrir http://127.0.0.1:18445/#t=$(cat /tmp/fs/run/token)
```
