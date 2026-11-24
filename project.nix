# The nix-haskell project of dpm-registry-audit: cabal.project, built with
# haskell.nix. Taken from the project.nix of dpm-registry, without the browser
# (Wasm and reflex-dom) parts.
{ ... }:

{
  name = "dpm-registry-audit";
  src = ./.;

  # dpm-registry-audit.cabal needs base 4.22.
  compiler.name = "ghc914";

  haskell-nix.options.shell.withHaddock = false;

  shell = {
    packages = haskellPackages: with haskellPackages; [ dpm-registry-audit ];
    withHoogle = false;
  };
}
