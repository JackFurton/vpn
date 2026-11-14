//! An established session: encrypts outgoing IP packets into data messages and
//! authenticates incoming ones, in the order docs/protocol.md requires.

use snow::StatelessTransportState;

use crate::replay::{REJECT_AFTER_MESSAGES, ReplayWindow};
use crate::wire::{BufferTooSmall, DATA_HEADER_LEN, Data, TAG_LEN, encode_data_header};

const PAD_TO: usize = 16;
const IPV4_MIN_HEADER: usize = 20;
const IPV6_HEADER: usize = 40;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TransportError {
    #[error("packet of {len} bytes exceeds MTU {mtu}")]
    TooLarge { len: usize, mtu: usize },
    #[error(transparent)]
    BufferTooSmall(#[from] BufferTooSmall),
    #[error("send counter exhausted, session must rekey")]
    CounterExhausted,
    #[error("responder can't send until the initiator's first packet confirms the session")]
    NotConfirmed,
    #[error("message is for index {got}, this session is {expected}")]
    WrongIndex { expected: u32, got: u32 },
    #[error("counter is a replay or too old")]
    Replay,
    #[error("encryption failed")]
    Encrypt,
    #[error("authentication failed")]
    Decrypt,
    #[error("decrypted payload is not a valid IP packet")]
    InvalidInnerPacket,
}

pub struct Session {
    /// Index we chose. Peers address packets to us with it.
    pub local_index: u32,
    /// Index the peer chose. We address packets to them with it.
    pub remote_index: u32,
    pub(crate) transport: StatelessTransportState,
    pub(crate) send_counter: u64,
    replay: ReplayWindow,
    confirmed: bool,
    pad_buf: Vec<u8>,
}

impl Session {
    pub(crate) fn new(
        local_index: u32,
        remote_index: u32,
        transport: StatelessTransportState,
        role: Role,
    ) -> Self {
        Self {
            local_index,
            remote_index,
            transport,
            send_counter: 0,
            replay: ReplayWindow::new(),
            // The responder can't know the initiator derived the same keys
            // until a packet from it decrypts.
            confirmed: role == Role::Initiator,
            pad_buf: Vec::new(),
        }
    }

    pub fn is_confirmed(&self) -> bool {
        self.confirmed
    }

    /// Size of the data message `encrypt` produces for a packet of `len`.
    pub fn encrypted_len(len: usize, mtu: usize) -> usize {
        DATA_HEADER_LEN + padded_len(len, mtu) + TAG_LEN
    }

    /// Encrypts one IP packet into a complete data message at the front of
    /// `out` and returns its length.
    pub fn encrypt(
        &mut self,
        packet: &[u8],
        mtu: usize,
        out: &mut [u8],
    ) -> Result<usize, TransportError> {
        if !self.confirmed {
            return Err(TransportError::NotConfirmed);
        }
        if packet.len() > mtu {
            return Err(TransportError::TooLarge {
                len: packet.len(),
                mtu,
            });
        }
        let counter = self.send_counter;
        if counter >= REJECT_AFTER_MESSAGES {
            return Err(TransportError::CounterExhausted);
        }

        let len = Self::encrypted_len(packet.len(), mtu);
        let got = out.len();
        let (header, body) = out
            .get_mut(..len)
            .ok_or(BufferTooSmall { need: len, got })?
            .split_first_chunk_mut()
            .expect("len includes the header");
        encode_data_header(self.remote_index, counter, header);

        let padded = padded_len(packet.len(), mtu);
        let plaintext = if padded == packet.len() {
            packet
        } else {
            self.pad_buf.clear();
            self.pad_buf.extend_from_slice(packet);
            self.pad_buf.resize(padded, 0);
            &self.pad_buf
        };
        self.transport
            .write_message(counter, plaintext, body)
            .map_err(|_| TransportError::Encrypt)?;
        self.send_counter += 1;
        Ok(len)
    }

    pub fn keepalive(&mut self, out: &mut [u8]) -> Result<usize, TransportError> {
        self.encrypt(&[], 0, out)
    }

    /// Authenticates and decrypts a data message into `out`. Returns the inner
    /// IP packet with padding removed, or an empty slice for a keepalive.
    pub fn decrypt<'a>(
        &mut self,
        msg: &Data,
        out: &'a mut [u8],
    ) -> Result<&'a [u8], TransportError> {
        if msg.receiver_index != self.local_index {
            return Err(TransportError::WrongIndex {
                expected: self.local_index,
                got: msg.receiver_index,
            });
        }
        if !self.replay.may_accept(msg.counter) {
            return Err(TransportError::Replay);
        }

        let need = msg.ciphertext.len() - TAG_LEN;
        let got = out.len();
        let out = out.get_mut(..need).ok_or(BufferTooSmall { need, got })?;
        self.transport
            .read_message(msg.counter, msg.ciphertext, out)
            .map_err(|_| TransportError::Decrypt)?;

        // Only now is the counter trustworthy enough to move the window.
        if !self.replay.accept(msg.counter) {
            return Err(TransportError::Replay);
        }
        self.confirmed = true;
        let out: &'a [u8] = out;
        strip_padding(out)
    }
}

/// Pads up to the next multiple of 16, but never past the MTU, so a packet
/// near the MTU may stay unaligned.
fn padded_len(len: usize, mtu: usize) -> usize {
    len.next_multiple_of(PAD_TO).min(mtu.max(len))
}

fn strip_padding(plaintext: &[u8]) -> Result<&[u8], TransportError> {
    let Some(&first) = plaintext.first() else {
        return Ok(plaintext);
    };
    let (len, min) = match first >> 4 {
        4 if plaintext.len() >= IPV4_MIN_HEADER => (
            u16::from_be_bytes([plaintext[2], plaintext[3]]) as usize,
            IPV4_MIN_HEADER,
        ),
        6 if plaintext.len() >= IPV6_HEADER => (
            IPV6_HEADER + u16::from_be_bytes([plaintext[4], plaintext[5]]) as usize,
            IPV6_HEADER,
        ),
        _ => return Err(TransportError::InvalidInnerPacket),
    };
    if len < min || len > plaintext.len() {
        return Err(TransportError::InvalidInnerPacket);
    }
    Ok(&plaintext[..len])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::{Initiator, Tai64N, read_init};
    use crate::keys::KeyPair;
    use crate::wire::{HANDSHAKE_INIT_LEN, HANDSHAKE_RESPONSE_LEN, Message};

    const MTU: usize = 1420;

    fn sessions() -> (Session, Session) {
        let (i, r) = (KeyPair::generate().unwrap(), KeyPair::generate().unwrap());
        let mut init = [0; HANDSHAKE_INIT_LEN];
        let initiator =
            Initiator::start(&i.private, &r.public, 1, Tai64N::now(), &mut init).unwrap();
        let Ok(Message::HandshakeInit(m)) = Message::parse(&init) else {
            unreachable!()
        };
        let mut resp = [0; HANDSHAKE_RESPONSE_LEN];
        let responder = read_init(&r.private, &m)
            .unwrap()
            .accept(None, 2, &mut resp)
            .unwrap();
        let Ok(Message::HandshakeResponse(m)) = Message::parse(&resp) else {
            unreachable!()
        };
        (initiator.finish(&m).unwrap(), responder)
    }

    fn ipv4(len: usize) -> Vec<u8> {
        let mut p: Vec<u8> = (0..len).map(|i| i as u8).collect();
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        p
    }

    fn ipv6(payload: usize) -> Vec<u8> {
        let mut p = vec![0xaa; IPV6_HEADER + payload];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&(payload as u16).to_be_bytes());
        p
    }

    fn seal(s: &mut Session, packet: &[u8]) -> Vec<u8> {
        let mut buf = vec![0; Session::encrypted_len(packet.len(), MTU)];
        let n = s.encrypt(packet, MTU, &mut buf).unwrap();
        assert_eq!(n, buf.len());
        buf
    }

    fn open(s: &mut Session, wire: &[u8]) -> Result<Vec<u8>, TransportError> {
        let Ok(Message::Data(d)) = Message::parse(wire) else {
            panic!("not a data message")
        };
        let mut buf = vec![0; d.ciphertext.len() - TAG_LEN];
        s.decrypt(&d, &mut buf).map(<[u8]>::to_vec)
    }

    #[test]
    fn responder_waits_for_confirmation() {
        let (mut i, mut r) = sessions();
        let mut ka = [0; 64];
        assert_eq!(r.keepalive(&mut ka), Err(TransportError::NotConfirmed));

        let n = i.keepalive(&mut ka).unwrap();
        assert_eq!(n, 32);
        assert_eq!(open(&mut r, &ka[..n]).unwrap(), b"");
        assert!(r.is_confirmed());

        let packet = ipv4(60);
        let wire = seal(&mut r, &packet);
        assert_eq!(open(&mut i, &wire).unwrap(), packet);
    }

    #[test]
    fn out_of_order_delivery_and_replays() {
        let (mut i, mut r) = sessions();
        let packets: Vec<_> = (0..5).map(|n| ipv4(20 + n)).collect();
        let wires: Vec<_> = packets.iter().map(|p| seal(&mut i, p)).collect();
        for (p, w) in packets.iter().zip(&wires).rev() {
            assert_eq!(&open(&mut r, w).unwrap(), p);
        }
        for w in &wires {
            assert_eq!(open(&mut r, w), Err(TransportError::Replay));
        }
    }

    #[test]
    fn forged_packets_do_not_poison_the_window() {
        let (mut i, mut r) = sessions();
        let wire = seal(&mut i, &ipv4(40));

        let mut tampered = wire.clone();
        tampered[20] ^= 1;
        assert_eq!(open(&mut r, &tampered), Err(TransportError::Decrypt));

        let mut far_ahead = wire.clone();
        far_ahead[8..16].copy_from_slice(&(1u64 << 40).to_le_bytes());
        assert_eq!(open(&mut r, &far_ahead), Err(TransportError::Decrypt));

        assert_eq!(open(&mut r, &wire).unwrap(), ipv4(40));
    }

    #[test]
    fn pads_to_16_and_strips_on_receive() {
        let (mut i, mut r) = sessions();
        for packet in [ipv4(21), ipv4(32), ipv6(1), ipv4(MTU - 1)] {
            let wire = seal(&mut i, &packet);
            let body = wire.len() - DATA_HEADER_LEN - TAG_LEN;
            assert_eq!(body, packet.len().next_multiple_of(16).min(MTU));
            assert_eq!(open(&mut r, &wire).unwrap(), packet);
        }
    }

    #[test]
    fn rejects_oversized_and_bad_inner_packets() {
        let (mut i, mut r) = sessions();
        let mut buf = vec![0; 2000];
        assert_eq!(
            i.encrypt(&ipv4(MTU + 1), MTU, &mut buf),
            Err(TransportError::TooLarge {
                len: MTU + 1,
                mtu: MTU
            })
        );

        let mut too_long = ipv4(30);
        too_long[2..4].copy_from_slice(&64u16.to_be_bytes());
        let mut too_short = ipv4(30);
        too_short[2..4].copy_from_slice(&10u16.to_be_bytes());
        for bad in [vec![0x50; 32], too_long, too_short] {
            let wire = seal(&mut i, &bad);
            assert_eq!(open(&mut r, &wire), Err(TransportError::InvalidInnerPacket));
        }
    }

    #[test]
    fn rejects_wrong_index_and_exhausted_counter() {
        let (mut i, mut r) = sessions();
        let mut wire = seal(&mut i, &ipv4(20));
        wire[4..8].copy_from_slice(&77u32.to_le_bytes());
        assert_eq!(
            open(&mut r, &wire),
            Err(TransportError::WrongIndex {
                expected: 2,
                got: 77
            })
        );

        i.send_counter = REJECT_AFTER_MESSAGES;
        assert_eq!(
            i.encrypt(&ipv4(20), MTU, &mut [0; 64]),
            Err(TransportError::CounterExhausted)
        );
    }
}
