# Módulo NixOS: carpeta compartida SMB bajo demanda con whitelist por MAC y panel local.
#
#   services.compartir = {
#     enable = true;
#     user = "alecor";
#   };
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.services.compartir;
  sharePath = "/home/${cfg.user}/${cfg.shareName}";
  stateDir = "/var/lib/fileshare";

  compartir = pkgs.writeShellApplication {
    name = "compartir";
    runtimeInputs = [pkgs.curl pkgs.jq pkgs.xdg-utils];
    runtimeEnv.FILESHARE_PORT = toString cfg.port;
    text = builtins.readFile ../bin/compartir;
  };
in {
  options.services.compartir = {
    enable = lib.mkEnableOption "carpeta compartida SMB bajo demanda";
    user = lib.mkOption {
      type = lib.types.str;
      description = "Usuario dueño de la carpeta y único usuario SMB permitido.";
    };
    shareName = lib.mkOption {
      type = lib.types.str;
      default = "Compartida";
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
      openFirewall = false; # el acceso lo controla fileshare-panel por MAC
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
          "valid users" = cfg.user;
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
          "full_audit:prefix" = "%u|%I|%m";
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
      after = ["fileshare-panel.service"];
      wants = ["fileshare-panel.service"];
    };

    systemd.tmpfiles.rules = [
      "d ${sharePath} 0755 ${cfg.user} users -"
    ];

    systemd.services.fileshare-panel = {
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
      ];
      environment = {
        FILESHARE_USER = cfg.user;
        FILESHARE_SHARE = cfg.shareName;
        FILESHARE_PATH = sharePath;
        FILESHARE_STATE = stateDir;
        FILESHARE_PORT = toString cfg.port;
        FILESHARE_HOST = config.networking.hostName;
        FILESHARE_HTML = "${../panel/panel.html}";
        FILESHARE_SMBD_UNIT = "samba-smbd";
      };
      serviceConfig = {
        ExecStart = "${pkgs.python3}/bin/python3 -u ${../panel/panel.py}";
        Restart = "always";
        RestartSec = 2;
        StateDirectory = "fileshare";
        RuntimeDirectory = "fileshare";
        ProtectHome = "read-only";
        PrivateTmp = true;
      };
    };

    environment.systemPackages = [compartir];
  };
}
