# This nix-shell only supports macOS right now. Soon I will also add support for Linux
# The repository supports direnv (https://direnv.net/). If your IDE supports direnv,
# then you do not need to care about dependencies.

{ pkgs ? import <nixpkgs> { } }:
with pkgs;
(pkgs.mkShell.override {
  stdenv = stdenvNoCC;
}) {
  nativeBuildInputs = [
    pkgs.hugo
  ];
}
