# Módulo NixOS: carpeta compartida SMB bajo demanda con whitelist por MAC y panel local.
#
#   services.dropmydoc = {
#     enable = true;
#     user = "alecor";
#   };
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.services.dropmydoc;
  sharePath = "/home/${cfg.user}/${cfg.shareName}";
  stateDir = "/var/lib/dropmydoc";

  dropmydoc = pkgs.writeShellApplication {
    name = "dmd";
    runtimeInputs = [pkgs.curl pkgs.jq pkgs.xdg-utils];
    runtimeEnv.DROPMYDOC_PORT = toString cfg.port;
    text = builtins.readFile ../bin/dmd;
  };
in {
  options.services.dropmydoc = {
    enable = lib.mkEnableOption "carpeta compartida SMB bajo demanda";
    user = lib.mkOption {
      type = lib.types.str;
      description = "Usuario dueño de la carpeta. Los usuarios SMB (uno por dispositivo) se crean desde el panel y escriben como este usuario.";
    };
    shareName = lib.mkOption {
      type = lib.types.str;
      default = "DropMyDoc";
      description = "Nombre del recurso SMB y de la carpeta en el home del usuario.";
    };
    port = lib.mkOption {
      type = lib.types.port;
      default = 8445;
      description = "Puerto del panel (solo escucha en 127.0.0.1).";
    };
  };

  config = lib.mkIf cfg.enable {
    services.samba = {
      enable = true;
      openFirewall = false; # el acceso lo controla dropmydoc por MAC
      nmbd.enable = false;
      winbindd.enable = false;
      settings = {
        global = {
          "server string" = config.networking.hostName;
          "netbios name" = config.networking.hostName;
          "security" = "user";
          "passdb backend" = "tdbsam";
          "map to guest" = "never";
          "restrict anonymous" = "2";
          "ntlm auth" = "ntlmv2-only";
          "server min protocol" = "SMB3_00";
          "server smb encrypt" = "desired";
          "server signing" = "desired";
          "disable netbios" = "yes";
          "smb ports" = "445";
          "load printers" = "no";
          "printing" = "bsd";
          "printcap name" = "/dev/null";
          "disable spoolss" = "yes";
          "logging" = "systemd";
          "log level" = "1 auth_audit:3";
          # hosts allow/deny generado por el panel (subredes locales actuales)
          "include" = "${stateDir}/smb-global.conf";
        };
        ${cfg.shareName} = {
          "path" = sharePath;
          # usuarios SMB creados desde el panel; los archivos quedan a nombre del dueño
          "valid users" = "@dropmydoc";
          "force user" = cfg.user;
          "force group" = config.users.users.${cfg.user}.group;
          # rechaza usuarios deshabilitados o que entran desde un dispositivo no vinculado
          # (necesita `ip` para ver la MAC de clientes IPv4 e IPv6)
          "root preexec" = "${pkgs.coreutils}/bin/env PATH=${pkgs.iproute2}/bin ${pkgs.python3}/bin/python3 ${../panel/panel.py} --check %U %I";
          "root preexec close" = "yes";
          "guest ok" = "no";
          "browseable" = "yes";
          "create mask" = "0644";
          "directory mask" = "0755";
          "vfs objects" = "catia fruit streams_xattr full_audit";
          "fruit:metadata" = "stream";
          "fruit:model" = "MacSamba";
          "fruit:posix_rename" = "yes";
          "fruit:veto_appledouble" = "no";
          "fruit:wipe_intentionally_left_blank_rfork" = "yes";
          "fruit:delete_empty_adfiles" = "yes";
          "full_audit:prefix" = "%U|%I|%m";
          "full_audit:success" = "connect disconnect openat renameat unlinkat mkdirat";
          "full_audit:failure" = "connect";
          "full_audit:facility" = "local5";
          "full_audit:priority" = "notice";
          # read only = yes/no generado por el panel
          "include" = "${stateDir}/smb-share.conf";
        };
      };
    };

    # smbd solo corre cuando se enciende a mano.
    systemd.targets.samba.wantedBy = lib.mkForce [];
    systemd.services.samba-smbd = {
      wantedBy = lib.mkForce [];
      after = ["dropmydoc.service"];
      wants = ["dropmydoc.service"];
    };

    # Avahi anunciaría <host>.local con la IP de docker0 (172.17.0.1), que los
    # dispositivos de la red no alcanzan.
    services.avahi.denyInterfaces = lib.mkIf config.services.avahi.enable ["docker0"];

    users.groups.dropmydoc = {};

    systemd.tmpfiles.rules = [
      "d ${sharePath} 0755 ${cfg.user} users -"
    ];

    systemd.services.dropmydoc = {
      description = "Panel y control de acceso de la carpeta compartida SMB";
      wantedBy = ["multi-user.target"];
      after = ["network.target" "firewall.service"];
      path = [
        config.networking.firewall.package
        config.services.samba.package
        config.systemd.package
        pkgs.iproute2
        pkgs.networkmanager
        pkgs.coreutils
        pkgs.shadow
      ];
      environment = {
        DROPMYDOC_USER = cfg.user;
        DROPMYDOC_SHARE = cfg.shareName;
        DROPMYDOC_PATH = sharePath;
        DROPMYDOC_STATE = stateDir;
        DROPMYDOC_PORT = toString cfg.port;
        DROPMYDOC_HOST = config.networking.hostName;
        DROPMYDOC_HTML = "${../panel/panel.html}";
        DROPMYDOC_SMBD_UNIT = "samba-smbd";
      };
      serviceConfig = {
        ExecStart = "${pkgs.python3}/bin/python3 -u ${../panel/panel.py}";
        Restart = "always";
        RestartSec = 2;
        StateDirectory = "dropmydoc";
        RuntimeDirectory = "dropmydoc";
        ProtectHome = "read-only";
        PrivateTmp = true;
      };
    };

    environment.systemPackages = [dropmydoc];
  };
}
