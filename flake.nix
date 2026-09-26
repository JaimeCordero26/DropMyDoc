{
  description = "DropMyDoc: carpeta compartida SMB bajo demanda con whitelist por MAC y panel local";

  outputs = {self}: {
    nixosModules.default = import ./nixos/module.nix;
    nixosModules.dropmydoc = self.nixosModules.default;
  };
}
