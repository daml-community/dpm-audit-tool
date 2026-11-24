{ system ? builtins.currentSystem, inputs ? {} }:

(import ./default.nix { inherit system inputs; }).haskell-nix.shell
