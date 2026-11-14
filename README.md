# vpn

A layer 3 VPN written in Rust. Own UDP wire protocol, Noise `IK` handshake
(via [`snow`](https://crates.io/crates/snow)), TUN device on each end.

Not ready for real traffic yet. The roadmap lives in the
[milestones](https://github.com/JackFurton/vpn/milestones).

## Install

Prebuilt binaries are on the [releases page](https://github.com/JackFurton/vpn/releases):
static Linux builds for x86_64 and aarch64 that run on any distro, plus
macOS on Apple silicon. Each tarball carries signed build provenance, so you
can check it was built by this repo's release workflow:

```sh
gh attestation verify vpnd-*.tar.gz -R JackFurton/vpn
sha256sum -c SHA256SUMS --ignore-missing
```

The macOS binary isn't notarized. If you downloaded it with a browser, clear
the quarantine flag first: `xattr -d com.apple.quarantine vpnd`.

Or build it yourself: `cargo build --release -p vpnd`.

Setting up a server: [docs/server-setup.md](docs/server-setup.md).

## License

MIT
