{
  description = "Check the audits of a DAR in a checkout of the identity repository";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    nix-haskell.url = "git+https://github.com/reflex-frp/nix-haskell?submodules=1";
    nix-haskell.inputs.haskell-nix.url = "github:input-output-hk/haskell.nix";
    nix-dpm.url = "github:0xsend/nix-dpm";
    nix-dpm.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    { nixpkgs, nix-dpm, nix-haskell, ... }:
    let
      inherit (nixpkgs) lib;

      forAllSystems =
        f:
        lib.genAttrs [ "x86_64-linux" "aarch64-linux" ] (
          system:
          f {
            pkgs = import nixpkgs {
              inherit system;
              overlays = [ nix-dpm.overlays.default ];
            };
            haskellProject =
              (import ./default.nix {
                inherit system;
                inputs = { inherit nix-haskell; };
              }).haskell-nix;
          }
        );

      runtimeInputs = pkgs: [
        pkgs.dpm
        pkgs.git
        pkgs.gnupg
      ];

      bootstrapDpm = pkgs: onFailure: ''
        dpm_home=''${DPM_HOME:-$HOME/.dpm}
        dpm_stamp="$dpm_home/.bootstrapped-${baseNameOf pkgs.dpm}"
        if [ ! -e "$dpm_stamp" ]; then
          echo "Bootstrapping dpm ${pkgs.dpm.version} into $dpm_home" >&2
          if dpm_output=$(dpm bootstrap "${pkgs.dpm}" 2>&1); then
            touch "$dpm_stamp"
          else
            printf '%s\ndpm bootstrap failed\n' "$dpm_output" >&2
            ${onFailure}
          fi
        fi
      '';
    in
    {
      packages = forAllSystems (
        { pkgs, haskellProject }:
        let
          exe = haskellProject.hsPkgs.dpm-registry-audit.components.exes.dpm-registry-audit;
          dpm-registry-audit = pkgs.writeShellApplication {
            name = "dpm-registry-audit";
            runtimeInputs = runtimeInputs pkgs ++ [
              pkgs.coreutils
              pkgs.bash
            ];
            text = ''
              ${bootstrapDpm pkgs "exit 1"}
              exec ${lib.getExe' exe "dpm-registry-audit"} "$@"
            '';
          };
        in
        {
          inherit dpm-registry-audit;
          default = dpm-registry-audit;
        }
      );

      devShells = forAllSystems (
        { pkgs, haskellProject }:
        {
          default = pkgs.mkShell {
            inputsFrom = [ haskellProject.shell ];
            packages = runtimeInputs pkgs;
            shellHook = bootstrapDpm pkgs ":";
          };
        }
      );
    };

  nixConfig = {
    extra-substituters = [
      "https://nixcache.reflex-frp.org"
      "https://cache.iog.io"
    ];
    extra-trusted-public-keys = [
      "ryantrinkle.com-1:JJiAKaRv9mWgpVAz8dwewnZe0AzzEAzPkagE9SP5NWI="
      "hydra.iohk.io:f/Ea+s+dFdN+3Y/G+FDgSq+a5NEWhJGzdjvKNGv0/EQ="
    ];
    allow-import-from-derivation = "true";
  };
}
