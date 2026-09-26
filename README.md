# compartir

Una carpeta de tu laptop compartida por SMB para abrirla desde la app **Archivos** del iPhone (o cualquier cliente SMB) sin instalar nada en el teléfono. Solo entran los dispositivos que apruebes. Se enciende y se apaga cuando quieras, y trae un panel web local para ver quién está conectado y qué está pasando.

## Cómo protege el acceso

1. **Firewall por MAC.** El puerto 445 solo acepta conexiones nuevas de las MAC que están en la whitelist. Todo lo demás se descarta y se registra como "intento bloqueado".
2. **Samba `hosts allow`.** Solo acepta la subred local actual; el panel la regenera cuando cambias de red.
3. **Un usuario SMB por dispositivo o persona** (`iphone`, `windows`, `t14`…), cada uno con su contraseña. Invitados deshabilitados, SMB3 como mínimo y solo NTLMv2.
4. **Vínculo usuario ↔ dispositivo.** Si a un usuario le vinculas dispositivos, Samba (`root preexec`) rechaza la conexión cuando la MAC de origen no es una de ellos. Así, aunque alguien consiga la contraseña del iPhone, no puede usarla desde otro equipo.
5. **Encendido bajo demanda.** `smbd` no arranca con el sistema. El panel lo apaga solo tras N minutos sin sesiones (30 por defecto).
6. **Panel solo en `127.0.0.1`.** Pide un token que solo puede leer tu usuario (`/run/fileshare/token`) y comprueba el header `Host` para impedir DNS rebinding.

## Panel (`http://127.0.0.1:8445`, se abre con `compartir panel`)

- **Usuarios:** crear, poner solo lectura o lectura y escritura, vincular dispositivos, deshabilitar, generar nueva contraseña y eliminar. Cada usuario muestra sus propias métricas: logins correctos y fallidos, archivos escritos, leídos y borrados, y bytes subidos y bajados.
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
compartir panel   # crea los usuarios
```

### Arch, Debian/Ubuntu, Fedora u otra distro con systemd

```sh
# Arch
sudo pacman -S --needed samba python iptables-nft iproute2 curl jq
# Debian/Ubuntu
sudo apt install samba python3 iptables iproute2 curl jq

sudo ./linux/install.sh "$USER"        # nombre de carpeta opcional; por defecto ~/Compartida
compartir panel   # crea los usuarios
compartir on
```

El instalador hace un respaldo del `/etc/samba/smb.conf` que ya tengas antes de reemplazarlo. Para desinstalar: `sudo ./linux/install.sh --uninstall`.

Si usas **firewalld** o **ufw**, tienes que abrir 445/tcp en ellos. El filtrado por MAC lo sigue haciendo `compartir`, porque un DROP en su cadena gana de todas formas.

### Windows

**Todavía no es compatible.** El panel depende de iptables, systemd/journald y Samba. Para portarlo haría falta:

- Usar el servidor SMB nativo (`New-SmbShare` con `-FullAccess` restringido a un usuario local) en lugar de Samba.
- Usar reglas de Windows Defender Firewall en lugar de iptables. Filtran por IP, no por MAC, así que la whitelist tendría que traducir MAC → IP a partir de `Get-NetNeighbor`.
- Leer sesiones y archivos abiertos con `Get-SmbSession` y `Get-SmbOpenFile`, y auditar desde el Visor de eventos (`Microsoft-Windows-SMBServer/Audit`).

Lo razonable sería separar en `panel.py` un "backend" por sistema operativo (firewall, servicio, sesiones, logs) y dejar la API y la interfaz iguales.

## Usuarios

Cada usuario SMB es un usuario Unix de sistema, sin login ni home, del grupo `fileshare`. Lo crea el panel con `useradd` y `smbpasswd`. En NixOS esto requiere `users.mutableUsers = true`, que es el valor por defecto.

- Todo lo que suben se guarda a nombre del dueño de la carpeta (`force user`), así que desde la laptop los archivos se ven como tuyos.
- La contraseña, si no escribes una, se genera con el formato `xxxx-xxxx-xxxx` y **se muestra una sola vez**.
- Los usuarios en solo lectura van a `read list`; los deshabilitados, a `invalid users` y además `smbpasswd -d`.
- Cambiar permisos, deshabilitar o cambiar la contraseña cierra las sesiones de ese usuario para que el cambio aplique de inmediato.

## Conectar un dispositivo

1. En el panel, crea su usuario (por ejemplo `iphone`).
2. `compartir on`
3. **iPhone:** Archivos → **···** → *Conectarse al servidor* → `smb://<host>.local` o `smb://<ip>` → *Usuario registrado* → `iphone` y su contraseña.
   **Windows:** Explorador → `\\<host>.local\Compartida`, o *Conectar a unidad de red*, con el usuario y la contraseña.
4. El primer intento de un dispositivo nuevo falla a propósito. Aparece en **Intentos bloqueados**; lo apruebas y vuelves a intentar.
5. Opcional: vincula el dispositivo a su usuario para que esa contraseña solo funcione desde él.

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
