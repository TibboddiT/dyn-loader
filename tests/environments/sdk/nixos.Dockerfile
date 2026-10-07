ARG BASE
FROM ${BASE} AS runtime
# The base image contains an immutable nixpkgs snapshot. Keep its store closure
# intact: embedded store RUNPATHs must resolve without flattened library copies.
RUN nix-build --out-link /opt/runtime -E 'let pkgs = import <nixpkgs> {}; in pkgs.buildEnv { name = "dynloader-runtime"; paths = [ pkgs.glibc.bin pkgs.gcc.cc.lib pkgs.coreutils pkgs.bash ]; }'
ENV PATH="/opt/runtime/bin:/root/.nix-profile/bin:/nix/var/nix/profiles/default/bin"

FROM runtime AS sdk
RUN nix-build --out-link /opt/sdk -E 'let pkgs = import <nixpkgs> {}; in pkgs.buildEnv { name = "dynloader-sdk"; paths = [ pkgs.gcc pkgs.binutils ]; }'
ENV PATH="/opt/sdk/bin:/opt/runtime/bin:/root/.nix-profile/bin:/nix/var/nix/profiles/default/bin"
