//! Sans-IO protocol core: wire format, handshake and transport state.
//! Nothing in this crate touches sockets or TUN devices.

pub mod handshake;
pub mod keys;
pub mod replay;
pub mod wire;

/// Same primitives WireGuard uses. Changing this breaks wire compatibility.
pub const NOISE_PARAMS: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
