{
  description = "Realliance SSO operator toolchain";

  # nixos-unstable, pinned by flake.lock (same revision luma-homeops pins).
  # Bump with `nix flake update nixpkgs`, then enter the shell and check the
  # tool versions before committing the lock.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      devShells = forAll (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            opentofu
            ansible
            ansible-lint
            git-crypt
            gnupg
            jq
            rclone
            gh
            openssl
            (python3.withPackages (ps: with ps; [ pytest pytest-testinfra requests pyyaml ]))
          ];
        };
      });
    };
}
