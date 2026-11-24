{
  description = "dpm-registry-audit: check the audits of a DAR in a checkout of the identity repository";

  # The inputs and their pins are those of dpm-registry.
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

    nix-haskell.url = "git+https://github.com/reflex-frp/nix-haskell?submodules=1";
    nix-haskell.inputs.haskell-nix.url = "github:input-output-hk/haskell.nix";

    # dpm packaged from Digital Asset's official release bundle, pinned by hash.
    # Only its overlay is used, so Nix does not import nixpkgs a second time for
    # nix-dpm's package outputs.
    nix-dpm.url = "github:0xsend/nix-dpm";
    nix-dpm.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    { self, nixpkgs, nix-dpm, nix-haskell, ... }:
    let
      lib = nixpkgs.lib;

      # The systems of dpm-registry.
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      forAllSystems =
        outputsFor:
        lib.genAttrs systems (
          system:
          outputsFor (
            import nixpkgs {
              inherit system;
              overlays = [ nix-dpm.overlays.default ];
            }
          )
        );

      haskellProjectFor =
        pkgs:
        (import ./default.nix {
          system = pkgs.stdenv.hostPlatform.system;
          inputs = { inherit nix-haskell; };
        }).haskell-nix;

      # The programs that dpm-registry-audit runs from the PATH.
      runtimeInputsFor = pkgs: [
        pkgs.dpm
        pkgs.git
        pkgs.gnupg
      ];

      # `dpm damlc` needs the SDK that `dpm bootstrap` installs into
      # DPM_HOME (default ~/.dpm) from the release bundle in the Nix store,
      # without a download. The dev shell of dpm-registry bootstraps in its
      # hook; this does it once per dpm store path, and runs onFailure when
      # the bootstrap fails.
      bootstrapDpm = pkgs: onFailure: ''
        dpm_home=''${DPM_HOME:-$HOME/.dpm}
        dpm_stamp="$dpm_home/.bootstrapped-${baseNameOf pkgs.dpm}"
        if [ ! -e "$dpm_stamp" ]; then
          printf 'dpm-registry-audit: bootstrapping dpm %s into %s\n' "${pkgs.dpm.version}" "$dpm_home" >&2
          if dpm_output=$(dpm bootstrap "${pkgs.dpm}" 2>&1); then
            touch "$dpm_stamp"
          else
            printf '%s\ndpm-registry-audit: dpm bootstrap failed\n' "$dpm_output" >&2
            ${onFailure}
          fi
        fi
      '';
    in
    {
      packages = forAllSystems (
        pkgs:
        let
          unwrapped = (haskellProjectFor pkgs).hsPkgs.dpm-registry-audit.components.exes.dpm-registry-audit;

          dpm-registry-audit = pkgs.writeShellApplication {
            name = "dpm-registry-audit";
            meta = {
              description = "Check the audits of a DAR in a checkout of the identity repository";
              mainProgram = "dpm-registry-audit";
            };
            # coreutils for the bootstrap, and bash because the commands that
            # dpm bootstrap installs are `#!/usr/bin/env sh` scripts.
            runtimeInputs = runtimeInputsFor pkgs ++ [ pkgs.coreutils pkgs.bash ];
            text = ''
              ${bootstrapDpm pkgs "exit 1"}
              exec ${lib.getExe' unwrapped "dpm-registry-audit"} "$@"
            '';
          };
        in
        {
          inherit dpm-registry-audit;
          dpm-registry-audit-unwrapped = unwrapped;
          default = dpm-registry-audit;
        }
      );

      apps = lib.mapAttrs (_: packages: rec {
        dpm-registry-audit = {
          type = "app";
          program = lib.getExe packages.dpm-registry-audit;
          inherit (packages.dpm-registry-audit) meta;
        };
        default = dpm-registry-audit;
      }) self.packages;

      devShells = forAllSystems (
        pkgs:
        let
          haskellShell = import ./shell.nix {
            system = pkgs.stdenv.hostPlatform.system;
            inputs = { inherit nix-haskell; };
          };
        in
        {
          default = pkgs.mkShell {
            name = "dpm-registry-audit";
            inputsFrom = [ haskellShell ];
            packages = runtimeInputsFor pkgs;
            shellHook = ''
              ${bootstrapDpm pkgs ":"}
              printf 'audit:  cabal run dpm-registry-audit -- DAR IDENTITY_REPOSITORY\n'
            '';
          };
        }
      );
    };

  nixConfig = {
    extra-substituters = [
      "https://cache.nixos.org"
      "https://nixcache.reflex-frp.org"
      "https://cache.iog.io"
    ];
    extra-trusted-public-keys = [
      "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
      "ryantrinkle.com-1:JJiAKaRv9mWgpVAz8dwewnZe0AzzEAzPkagE9SP5NWI=" # reflex-frp
      "hydra.iohk.io:f/Ea+s+dFdN+3Y/G+FDgSq+a5NEWhJGzdjvKNGv0/EQ="
    ];
    allow-import-from-derivation = "true";
  };
}
