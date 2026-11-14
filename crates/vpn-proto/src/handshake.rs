//! Noise IK handshake, from the first message to an established `Session`.
//! See the handshake flow in docs/protocol.md.
//!
//! The responder side is split in two (`read_init`, then
//! `InitReceived::accept`) because it needs the initiator's static key to
//! look up per-peer state, and that key only exists after decrypting.

use std::sync::LazyLock;
use std::time::{SystemTime, UNIX_EPOCH};

use snow::params::NoiseParams;
use snow::{Builder, HandshakeState};

use crate::NOISE_PARAMS;
use crate::keys::{KEY_LEN, PrivateKey, PublicKey};
use crate::session::{Role, Session};
use crate::wire::{
    HANDSHAKE_INIT_LEN, HANDSHAKE_INIT_NOISE_LEN, HANDSHAKE_RESPONSE_LEN,
    HANDSHAKE_RESPONSE_NOISE_LEN, HandshakeInit, HandshakeResponse, MAC_LEN, Message,
};

const PROLOGUE: &[u8] = b"JackFurton/vpn v1";
const TIMESTAMP_LEN: usize = 12;
const NO_MAC: [u8; MAC_LEN] = [0; MAC_LEN];

static PARAMS: LazyLock<NoiseParams> = LazyLock::new(|| {
    NOISE_PARAMS
        .parse()
        .expect("NOISE_PARAMS is a valid pattern")
});

#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("noise: {0}")]
    Noise(#[from] snow::Error),
    #[error("handshake payload has unexpected length {0}")]
    BadPayload(usize),
    #[error("initiation timestamp is not newer than the last accepted one")]
    StaleTimestamp,
    #[error("response is addressed to index {got}, expected {expected}")]
    IndexMismatch { expected: u32, got: u32 },
}

/// TAI64N label (https://cr.yp.to/libtai/tai64.html). Big-endian by
/// definition, so the derived byte-wise ordering is chronological.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Tai64N([u8; TIMESTAMP_LEN]);

impl Tai64N {
    // 2^62 marks the TAI64 epoch; the extra 10 is the TAI-UTC offset in 1970,
    // matching what WireGuard sends.
    const EPOCH: u64 = (1 << 62) + 10;

    pub fn from_unix(secs: u64, nanos: u32) -> Self {
        let mut b = [0; TIMESTAMP_LEN];
        b[..8].copy_from_slice(&(Self::EPOCH + secs).to_be_bytes());
        b[8..].copy_from_slice(&nanos.to_be_bytes());
        Self(b)
    }

    pub fn now() -> Self {
        let d = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        Self::from_unix(d.as_secs(), d.subsec_nanos())
    }
}

fn builder(local: &PrivateKey) -> Result<Builder<'_>, snow::Error> {
    Builder::new(PARAMS.clone())
        .prologue(PROLOGUE)?
        .local_private_key(local.as_bytes())
}

pub struct Initiator {
    state: HandshakeState,
    sender_index: u32,
}

impl Initiator {
    /// Starts a handshake with `peer` and writes the initiation into `out`.
    /// `sender_index` must be random and unused by our other live sessions.
    pub fn start(
        local: &PrivateKey,
        peer: &PublicKey,
        sender_index: u32,
        now: Tai64N,
        out: &mut [u8; HANDSHAKE_INIT_LEN],
    ) -> Result<Self, HandshakeError> {
        let mut state = builder(local)?
            .remote_public_key(peer.as_bytes())?
            .build_initiator()?;
        let mut noise = [0; HANDSHAKE_INIT_NOISE_LEN];
        let n = state.write_message(&now.0, &mut noise)?;
        debug_assert_eq!(n, HANDSHAKE_INIT_NOISE_LEN);

        Message::HandshakeInit(HandshakeInit {
            sender_index,
            noise: &noise,
            mac1: &NO_MAC,
            mac2: &NO_MAC,
        })
        .encode(out)
        .expect("buffer is exactly HANDSHAKE_INIT_LEN");
        Ok(Self {
            state,
            sender_index,
        })
    }

    pub fn sender_index(&self) -> u32 {
        self.sender_index
    }

    pub fn finish(mut self, msg: &HandshakeResponse) -> Result<Session, HandshakeError> {
        if msg.receiver_index != self.sender_index {
            return Err(HandshakeError::IndexMismatch {
                expected: self.sender_index,
                got: msg.receiver_index,
            });
        }
        let mut payload = [0; HANDSHAKE_RESPONSE_NOISE_LEN];
        let n = self.state.read_message(msg.noise, &mut payload)?;
        if n != 0 {
            return Err(HandshakeError::BadPayload(n));
        }
        Ok(Session::new(
            self.sender_index,
            msg.sender_index,
            self.state.into_stateless_transport_mode()?,
            Role::Initiator,
        ))
    }
}

/// An initiation that decrypted correctly but isn't accepted yet. The caller
/// must check `peer` against its configuration before calling `accept`.
pub struct InitReceived {
    state: HandshakeState,
    peer: PublicKey,
    timestamp: Tai64N,
    initiator_index: u32,
}

/// Decrypts an initiation addressed to `local`. Succeeding only proves the
/// sender holds the private key for `peer()`, not that we know that peer.
pub fn read_init(local: &PrivateKey, msg: &HandshakeInit) -> Result<InitReceived, HandshakeError> {
    let mut state = builder(local)?.build_responder()?;
    let mut payload = [0; HANDSHAKE_INIT_NOISE_LEN];
    let n = state.read_message(msg.noise, &mut payload)?;
    let timestamp = payload[..n]
        .try_into()
        .map(Tai64N)
        .map_err(|_| HandshakeError::BadPayload(n))?;
    let peer: [u8; KEY_LEN] = state
        .get_remote_static()
        .and_then(|k| k.try_into().ok())
        .expect("IK always transmits the initiator's static key");
    Ok(InitReceived {
        state,
        peer: PublicKey::from_bytes(peer),
        timestamp,
        initiator_index: msg.sender_index,
    })
}

impl InitReceived {
    pub fn peer(&self) -> &PublicKey {
        &self.peer
    }

    pub fn timestamp(&self) -> Tai64N {
        self.timestamp
    }

    /// Writes the response into `out`. `last_accepted` is the timestamp of
    /// the last initiation accepted from this peer; anything not strictly
    /// newer is a replay. Store `timestamp()` as the new value on success.
    pub fn accept(
        mut self,
        last_accepted: Option<Tai64N>,
        sender_index: u32,
        out: &mut [u8; HANDSHAKE_RESPONSE_LEN],
    ) -> Result<Session, HandshakeError> {
        if last_accepted.is_some_and(|last| self.timestamp <= last) {
            return Err(HandshakeError::StaleTimestamp);
        }
        let mut noise = [0; HANDSHAKE_RESPONSE_NOISE_LEN];
        let n = self.state.write_message(&[], &mut noise)?;
        debug_assert_eq!(n, HANDSHAKE_RESPONSE_NOISE_LEN);

        Message::HandshakeResponse(HandshakeResponse {
            sender_index,
            receiver_index: self.initiator_index,
            noise: &noise,
            mac1: &NO_MAC,
            mac2: &NO_MAC,
        })
        .encode(out)
        .expect("buffer is exactly HANDSHAKE_RESPONSE_LEN");
        Ok(Session::new(
            sender_index,
            self.initiator_index,
            self.state.into_stateless_transport_mode()?,
            Role::Responder,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyPair;

    fn parse_init(buf: &[u8]) -> HandshakeInit<'_> {
        match Message::parse(buf).unwrap() {
            Message::HandshakeInit(m) => m,
            other => panic!("expected init, got {other:?}"),
        }
    }

    fn parse_response(buf: &[u8]) -> HandshakeResponse<'_> {
        match Message::parse(buf).unwrap() {
            Message::HandshakeResponse(m) => m,
            other => panic!("expected response, got {other:?}"),
        }
    }

    struct Pair {
        i: KeyPair,
        r: KeyPair,
    }

    impl Pair {
        fn new() -> Self {
            Self {
                i: KeyPair::generate().unwrap(),
                r: KeyPair::generate().unwrap(),
            }
        }

        fn init(&self, now: Tai64N) -> (Initiator, [u8; HANDSHAKE_INIT_LEN]) {
            let mut buf = [0; HANDSHAKE_INIT_LEN];
            let i = Initiator::start(&self.i.private, &self.r.public, 11, now, &mut buf).unwrap();
            (i, buf)
        }
    }

    fn round_trip(s: &Session, to: &Session, nonce: u64) {
        let mut ct = [0; 64];
        let mut pt = [0; 64];
        let n = s.transport.write_message(nonce, b"ping", &mut ct).unwrap();
        let n = to.transport.read_message(nonce, &ct[..n], &mut pt).unwrap();
        assert_eq!(&pt[..n], b"ping");
    }

    #[test]
    fn completes_and_keys_match() {
        let p = Pair::new();
        let (initiator, init) = p.init(Tai64N::now());

        let received = read_init(&p.r.private, &parse_init(&init)).unwrap();
        assert_eq!(received.peer(), &p.i.public);
        let mut resp = [0; HANDSHAKE_RESPONSE_LEN];
        let r_session = received.accept(None, 22, &mut resp).unwrap();
        let i_session = initiator.finish(&parse_response(&resp)).unwrap();

        assert_eq!((i_session.local_index, i_session.remote_index), (11, 22));
        assert_eq!((r_session.local_index, r_session.remote_index), (22, 11));
        round_trip(&i_session, &r_session, 0);
        round_trip(&r_session, &i_session, 0);
    }

    #[test]
    fn wrong_responder_key_fails() {
        let p = Pair::new();
        let (_, init) = p.init(Tai64N::now());
        let other = KeyPair::generate().unwrap();
        assert!(matches!(
            read_init(&other.private, &parse_init(&init)),
            Err(HandshakeError::Noise(_))
        ));
    }

    #[test]
    fn replayed_or_older_timestamp_is_rejected() {
        let p = Pair::new();
        let t = Tai64N::from_unix(1_700_000_000, 500);
        let (_, init) = p.init(t);
        let mut resp = [0; HANDSHAKE_RESPONSE_LEN];
        for last in [t, Tai64N::from_unix(1_700_000_000, 501)] {
            let received = read_init(&p.r.private, &parse_init(&init)).unwrap();
            assert!(matches!(
                received.accept(Some(last), 22, &mut resp),
                Err(HandshakeError::StaleTimestamp)
            ));
        }
        let received = read_init(&p.r.private, &parse_init(&init)).unwrap();
        let older = Tai64N::from_unix(1_699_999_999, 999_999_999);
        assert!(received.accept(Some(older), 22, &mut resp).is_ok());
    }

    #[test]
    fn tampered_messages_fail() {
        let p = Pair::new();
        let (initiator, mut init) = p.init(Tai64N::now());
        let good = init;
        init[60] ^= 1;
        assert!(read_init(&p.r.private, &parse_init(&init)).is_err());

        let received = read_init(&p.r.private, &parse_init(&good)).unwrap();
        let mut resp = [0; HANDSHAKE_RESPONSE_LEN];
        received.accept(None, 22, &mut resp).unwrap();
        resp[20] ^= 1;
        assert!(matches!(
            initiator.finish(&parse_response(&resp)),
            Err(HandshakeError::Noise(_))
        ));
    }

    #[test]
    fn response_for_other_index_is_rejected() {
        let p = Pair::new();
        let (initiator, init) = p.init(Tai64N::now());
        let received = read_init(&p.r.private, &parse_init(&init)).unwrap();
        let mut resp = [0; HANDSHAKE_RESPONSE_LEN];
        received.accept(None, 22, &mut resp).unwrap();
        resp[8..12].copy_from_slice(&99u32.to_le_bytes());
        assert!(matches!(
            initiator.finish(&parse_response(&resp)),
            Err(HandshakeError::IndexMismatch {
                expected: 11,
                got: 99
            })
        ));
    }

    #[test]
    fn timestamps_order_chronologically() {
        let a = Tai64N::from_unix(100, 999_999_999);
        let b = Tai64N::from_unix(101, 0);
        assert!(a < b);
        assert!(Tai64N::from_unix(100, 1) > Tai64N::from_unix(100, 0));
    }
}
