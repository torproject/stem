{
  description = "Controller library that allows applications to interact with Tor";

  outputs = { self, nixpkgs }:
    let
      inherit (nixpkgs) lib;
      forAllSystems = lib.genAttrs lib.systems.flakeExposed;
    in
    {
      packages = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          packages = self.packages.${system};
        in
        {
          super = pkgs.python3Packages.stem;
          stem = packages.super.overrideAttrs {
            src = ./.;
          };
          default = packages.stem;
        });
    };
}
