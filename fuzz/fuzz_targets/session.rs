//! The authenticated receive path, which the device target can't reach. A
//! real handshake gives two Sessions; the fuzzer then picks plaintexts, MTUs
//! and the network's behaviour (delivery order, duplicates, corruption), and
//! every outcome is checked against a model of what should happen.
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use vpn_proto::handshake::{Initiator, Tai64N, read_init};
use vpn_proto::keys::PrivateKey;
use vpn_proto::session::{Session, TransportError};
use vpn_proto::wire::{HANDSHAKE_INIT_LEN, HANDSHAKE_RESPONSE_LEN, Message, TAG_LEN};

#[derive(Arbitrary, Debug)]
enum Op {
    /// A encrypts this plaintext towards B.
    Send { plaintext: Vec<u8>, mtu: u16 },
    /// Deliver an in-flight packet to B. It stays in flight, so delivering
    /// it again is a duplicate.
    Deliver { pick: u8 },
    /// Flip bits in one byte of an in-flight packet.
    Corrupt { pick: u8, at: u16, xor: u8 },
}

struct InFlight {
    wire: Vec<u8>,
    /// Compared at delivery: corrupting a byte twice can restore it.
    original: Vec<u8>,
    padded: Vec<u8>,
    delivered: bool,
}

fuzz_target!(|ops: Vec<Op>| {
    let (mut a, mut b) = sessions();
    let mut flight: Vec<InFlight> = Vec::new();
    for op in ops {
        match op {
            Op::Send { plaintext, mtu } => {
                let mtu = usize::from(mtu).clamp(1, 9000);
                let mut wire = vec![0; Session::encrypted_len(plaintext.len(), mtu)];
                match a.encrypt(&plaintext, mtu, &mut wire) {
                    Ok(n) => {
                        let padded_len = n - 16 - TAG_LEN;
                        let mut padded = plaintext.clone();
                        padded.resize(padded_len, 0);
                        assert!(padded_len >= plaintext.len() && padded_len <= mtu.max(plaintext.len()));
                        flight.push(InFlight { original: wire.clone(), wire, padded, delivered: false });
                    }
                    Err(TransportError::TooLarge { .. }) => assert!(plaintext.len() > mtu),
                    Err(e) => panic!("unexpected encrypt error {e}"),
                }
            }
            Op::Corrupt { pick, at, xor } => {
                let Some(p) = pick_mut(&mut flight, pick) else { continue };
                // Bytes 0..16 are the header; corrupting those changes routing
                // or the nonce, which must also fail, so cover them too.
                let at = usize::from(at) % p.wire.len();
                p.wire[at] ^= xor;
            }
            Op::Deliver { pick } => {
                let Some(p) = pick_mut(&mut flight, pick) else { continue };
                let tampered = p.wire != p.original;
                let mut out = vec![0; p.wire.len()];
                let result = match Message::parse(&p.wire) {
                    Ok(Message::Data(d)) => b.decrypt(&d, &mut out).map(<[u8]>::to_vec),
                    // Corrupting the type byte can turn it into something else.
                    _ => {
                        assert!(tampered);
                        continue;
                    }
                };
                if tampered {
                    assert!(result.is_err(), "tampered packet accepted");
                } else if p.delivered {
                    assert_eq!(result, Err(TransportError::Replay));
                } else {
                    assert_eq!(result, expected(&p.padded));
                    p.delivered = true;
                }
            }
        }
    }
});

fn pick_mut(flight: &mut [InFlight], pick: u8) -> Option<&mut InFlight> {
    let len = flight.len();
    (len > 0).then(|| &mut flight[usize::from(pick) % len])
}

/// What the receiver must return for a padded plaintext, written out from
/// the spec rather than calling the code under test.
fn expected(padded: &[u8]) -> Result<Vec<u8>, TransportError> {
    let bad = Err(TransportError::InvalidInnerPacket);
    let Some(&first) = padded.first() else { return Ok(vec![]) };
    let (len, min) = match first >> 4 {
        4 if padded.len() >= 20 => (usize::from(u16::from_be_bytes([padded[2], padded[3]])), 20),
        6 if padded.len() >= 40 => (40 + usize::from(u16::from_be_bytes([padded[4], padded[5]])), 40),
        _ => return bad,
    };
    if len < min || len > padded.len() {
        return bad;
    }
    Ok(padded[..len].to_vec())
}

fn sessions() -> (Session, Session) {
    let (ia, ib) = (PrivateKey::from_bytes([1; 32]), PrivateKey::from_bytes([2; 32]));
    let mut init = [0; HANDSHAKE_INIT_LEN];
    let initiator = Initiator::start(&ia, &ib.public_key(), 1, Tai64N::now(), &mut init).unwrap();
    let Ok(Message::HandshakeInit(m)) = Message::parse(&init) else { unreachable!() };
    let mut resp = [0; HANDSHAKE_RESPONSE_LEN];
    let responder = read_init(&ib, &m).unwrap().accept(None, 2, &mut resp).unwrap();
    let Ok(Message::HandshakeResponse(m)) = Message::parse(&resp) else { unreachable!() };
    (initiator.finish(&m).unwrap(), responder)
}
