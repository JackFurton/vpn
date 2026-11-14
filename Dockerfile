# Build on the same Debian release the runtime image is based on, so the
# binary's glibc matches.
FROM rust:1.96-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p vpnd

# distroless/cc: glibc and libgcc only. No shell, no package manager.
FROM gcr.io/distroless/cc-debian12
COPY --from=build /src/target/release/vpnd /usr/local/bin/vpnd
# Starts as root because creating the TUN device needs CAP_NET_ADMIN, which a
# non-root process in a container doesn't get. vpnd drops to nonroot (65532)
# with no capabilities as soon as the tunnel is up.
ENTRYPOINT ["/usr/local/bin/vpnd", "up", "--user", "nonroot", "-c", "/etc/vpnd/vpnd.toml"]
