{
  description = "Carpeta compartida SMB bajo demanda con whitelist por MAC y panel local";

  outputs = {self}: {
    nixosModules.default = import ./nixos/module.nix;
    nixosModules.compartir = self.nixosModules.default;
  };
}
