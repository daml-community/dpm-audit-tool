{ system ? builtins.currentSystem, inputs ? {} }:

let nix-haskell = import inputs.nix-haskell { inherit system inputs; };
    project = nix-haskell (import ./project.nix);

in {
  haskell-nix = project.haskell-nix.project;
}
