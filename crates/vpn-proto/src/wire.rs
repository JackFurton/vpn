//! Byte layout of every message on the wire. See docs/protocol.md.
//!
//! Parsing borrows from the input buffer and never allocates, so it is safe
//! to run on every datagram before anything is authenticated.

pub const HEADER_LEN: usize = 4;
pub const INDEX_LEN: usize = 4;
pub const MAC_LEN: usize = 16;
pub const TAG_LEN: usize = 16;

pub const HANDSHAKE_INIT_NOISE_LEN: usize = 108;
pub const HANDSHAKE_INIT_LEN: usize =
    HEADER_LEN + INDEX_LEN + HANDSHAKE_INIT_NOISE_LEN + 2 * MAC_LEN;

pub const HANDSHAKE_RESPONSE_NOISE_LEN: usize = 48;
pub const HANDSHAKE_RESPONSE_LEN: usize =
    HEADER_LEN + 2 * INDEX_LEN + HANDSHAKE_RESPONSE_NOISE_LEN + 2 * MAC_LEN;

pub const COOKIE_LEN: usize = 16;
pub const COOKIE_NONCE_LEN: usize = 24;
pub const COOKIE_REPLY_LEN: usize =
    HEADER_LEN + INDEX_LEN + COOKIE_NONCE_LEN + COOKIE_LEN + TAG_LEN;

pub const DATA_HEADER_LEN: usize = HEADER_LEN + INDEX_LEN + 8;
/// A keepalive: header plus the tag over an empty payload.
pub const DATA_MIN_LEN: usize = DATA_HEADER_LEN + TAG_LEN;

const _: () = assert!(HANDSHAKE_INIT_LEN == 148);
const _: () = assert!(HANDSHAKE_RESPONSE_LEN == 92);
const _: () = assert!(DATA_MIN_LEN == 32);
const _: () = assert!(COOKIE_REPLY_LEN == 64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    HandshakeInit = 1,
    HandshakeResponse = 2,
    CookieReply = 3,
    Data = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("datagram shorter than the {HEADER_LEN}-byte header")]
    Truncated,
    #[error("unknown message type {0}")]
    UnknownType(u8),
    #[error("reserved header bytes are not zero")]
    ReservedNotZero,
    #[error("{message:?} message has invalid length {len}")]
    InvalidLength { message: MessageType, len: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("output buffer is {got} bytes, need {need}")]
pub struct BufferTooSmall {
    pub need: usize,
    pub got: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Message<'a> {
    HandshakeInit(HandshakeInit<'a>),
    HandshakeResponse(HandshakeResponse<'a>),
    CookieReply(CookieReply<'a>),
    Data(Data<'a>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeInit<'a> {
    pub sender_index: u32,
    pub noise: &'a [u8; HANDSHAKE_INIT_NOISE_LEN],
    pub mac1: &'a [u8; MAC_LEN],
    pub mac2: &'a [u8; MAC_LEN],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeResponse<'a> {
    pub sender_index: u32,
    pub receiver_index: u32,
    pub noise: &'a [u8; HANDSHAKE_RESPONSE_NOISE_LEN],
    pub mac1: &'a [u8; MAC_LEN],
    pub mac2: &'a [u8; MAC_LEN],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CookieReply<'a> {
    /// The `sender_index` of the handshake message this answers.
    pub receiver_index: u32,
    pub nonce: &'a [u8; COOKIE_NONCE_LEN],
    /// Encrypted cookie, followed by its tag.
    pub cookie: &'a [u8; COOKIE_LEN],
    pub tag: &'a [u8; TAG_LEN],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Data<'a> {
    pub receiver_index: u32,
    pub counter: u64,
    /// Encrypted, padded inner packet followed by the Poly1305 tag.
    pub ciphertext: &'a [u8],
}

impl<'a> Message<'a> {
    pub fn parse(buf: &'a [u8]) -> Result<Self, ParseError> {
        let Some((header, body)) = buf.split_first_chunk::<HEADER_LEN>() else {
            return Err(ParseError::Truncated);
        };
        let message = match header[0] {
            1 => MessageType::HandshakeInit,
            2 => MessageType::HandshakeResponse,
            3 => MessageType::CookieReply,
            4 => MessageType::Data,
            other => return Err(ParseError::UnknownType(other)),
        };
        if header[1..] != [0; 3] {
            return Err(ParseError::ReservedNotZero);
        }
        let bad_len = ParseError::InvalidLength {
            message,
            len: buf.len(),
        };

        let mut r = Reader(body);
        let parsed = match message {
            MessageType::HandshakeInit if buf.len() == HANDSHAKE_INIT_LEN => {
                Message::HandshakeInit(HandshakeInit {
                    sender_index: r.u32(),
                    noise: r.array(),
                    mac1: r.array(),
                    mac2: r.array(),
                })
            }
            MessageType::HandshakeResponse if buf.len() == HANDSHAKE_RESPONSE_LEN => {
                Message::HandshakeResponse(HandshakeResponse {
                    sender_index: r.u32(),
                    receiver_index: r.u32(),
                    noise: r.array(),
                    mac1: r.array(),
                    mac2: r.array(),
                })
            }
            MessageType::CookieReply if buf.len() == COOKIE_REPLY_LEN => {
                Message::CookieReply(CookieReply {
                    receiver_index: r.u32(),
                    nonce: r.array(),
                    cookie: r.array(),
                    tag: r.array(),
                })
            }
            MessageType::Data if buf.len() >= DATA_MIN_LEN => Message::Data(Data {
                receiver_index: r.u32(),
                counter: r.u64(),
                ciphertext: r.rest(),
            }),
            _ => return Err(bad_len),
        };
        Ok(parsed)
    }

    pub fn encoded_len(&self) -> usize {
        match self {
            Message::HandshakeInit(_) => HANDSHAKE_INIT_LEN,
            Message::HandshakeResponse(_) => HANDSHAKE_RESPONSE_LEN,
            Message::CookieReply(_) => COOKIE_REPLY_LEN,
            Message::Data(d) => DATA_HEADER_LEN + d.ciphertext.len(),
        }
    }

    /// Writes the message to the front of `out` and returns its length.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, BufferTooSmall> {
        let len = self.encoded_len();
        let got = out.len();
        let out = out
            .get_mut(..len)
            .ok_or(BufferTooSmall { need: len, got })?;
        let mut w = Writer(out);
        match self {
            Message::HandshakeInit(m) => {
                w.header(MessageType::HandshakeInit);
                w.put(&m.sender_index.to_le_bytes());
                w.put(m.noise);
                w.put(m.mac1);
                w.put(m.mac2);
            }
            Message::HandshakeResponse(m) => {
                w.header(MessageType::HandshakeResponse);
                w.put(&m.sender_index.to_le_bytes());
                w.put(&m.receiver_index.to_le_bytes());
                w.put(m.noise);
                w.put(m.mac1);
                w.put(m.mac2);
            }
            Message::CookieReply(m) => {
                w.header(MessageType::CookieReply);
                w.put(&m.receiver_index.to_le_bytes());
                w.put(m.nonce);
                w.put(m.cookie);
                w.put(m.tag);
            }
            Message::Data(m) => {
                encode_data_header(m.receiver_index, m.counter, w.take());
                w.put(m.ciphertext);
            }
        }
        Ok(len)
    }
}

/// Writes just the data header, so the transport can encrypt straight into
/// the bytes after it instead of copying the ciphertext.
pub fn encode_data_header(receiver_index: u32, counter: u64, out: &mut [u8; DATA_HEADER_LEN]) {
    let mut w = Writer(out);
    w.header(MessageType::Data);
    w.put(&receiver_index.to_le_bytes());
    w.put(&counter.to_le_bytes());
}

// Lengths are validated before a Reader or Writer is built, so running out of
// bytes inside one is a bug in this module, not bad input.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn array<const N: usize>(&mut self) -> &'a [u8; N] {
        let (head, rest) = self.0.split_first_chunk().expect("length checked");
        self.0 = rest;
        head
    }

    fn u32(&mut self) -> u32 {
        u32::from_le_bytes(*self.array())
    }

    fn u64(&mut self) -> u64 {
        u64::from_le_bytes(*self.array())
    }

    fn rest(self) -> &'a [u8] {
        self.0
    }
}

struct Writer<'a>(&'a mut [u8]);

impl<'a> Writer<'a> {
    fn put(&mut self, bytes: &[u8]) {
        let (head, rest) = std::mem::take(&mut self.0).split_at_mut(bytes.len());
        head.copy_from_slice(bytes);
        self.0 = rest;
    }

    fn header(&mut self, t: MessageType) {
        self.put(&[t as u8, 0, 0, 0]);
    }

    fn take<const N: usize>(&mut self) -> &'a mut [u8; N] {
        let (head, rest) = std::mem::take(&mut self.0)
            .split_first_chunk_mut()
            .expect("length checked");
        self.0 = rest;
        head
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOISE1: [u8; HANDSHAKE_INIT_NOISE_LEN] = [0xa1; HANDSHAKE_INIT_NOISE_LEN];
    const NOISE2: [u8; HANDSHAKE_RESPONSE_NOISE_LEN] = [0xb2; HANDSHAKE_RESPONSE_NOISE_LEN];
    const MAC1: [u8; MAC_LEN] = [0x11; MAC_LEN];
    const MAC2: [u8; MAC_LEN] = [0x22; MAC_LEN];
    const CIPHERTEXT: [u8; 48] = [0xcc; 48];
    const NONCE: [u8; COOKIE_NONCE_LEN] = [0x33; COOKIE_NONCE_LEN];
    const COOKIE: [u8; COOKIE_LEN] = [0x44; COOKIE_LEN];

    fn samples() -> [Message<'static>; 4] {
        [
            Message::HandshakeInit(HandshakeInit {
                sender_index: 0xdead_beef,
                noise: &NOISE1,
                mac1: &MAC1,
                mac2: &MAC2,
            }),
            Message::HandshakeResponse(HandshakeResponse {
                sender_index: 7,
                receiver_index: 0xdead_beef,
                noise: &NOISE2,
                mac1: &MAC1,
                mac2: &MAC2,
            }),
            Message::Data(Data {
                receiver_index: 7,
                counter: u64::MAX - 1,
                ciphertext: &CIPHERTEXT,
            }),
            Message::CookieReply(CookieReply {
                receiver_index: 0xdead_beef,
                nonce: &NONCE,
                cookie: &COOKIE,
                tag: &MAC1,
            }),
        ]
    }

    fn encode(m: &Message) -> Vec<u8> {
        let mut buf = vec![0; m.encoded_len()];
        assert_eq!(m.encode(&mut buf).unwrap(), buf.len());
        buf
    }

    #[test]
    fn round_trips_every_type() {
        for m in samples() {
            assert_eq!(Message::parse(&encode(&m)).unwrap(), m);
        }
    }

    #[test]
    fn fields_are_little_endian_at_spec_offsets() {
        let [init, _, data, _] = samples();
        let init = encode(&init);
        assert_eq!(init[..8], [1, 0, 0, 0, 0xef, 0xbe, 0xad, 0xde]);
        assert_eq!(init[8..116], NOISE1);
        assert_eq!(init[116..132], MAC1);

        let data = encode(&data);
        assert_eq!(data[..8], [4, 0, 0, 0, 7, 0, 0, 0]);
        assert_eq!(data[8..16], (u64::MAX - 1).to_le_bytes());
        assert_eq!(data[16..], CIPHERTEXT);
    }

    #[test]
    fn rejects_truncated_and_oversized_handshakes() {
        for m in [&samples()[0], &samples()[1], &samples()[3]] {
            let buf = encode(m);
            let mut long = buf.clone();
            long.push(0);
            for bad in [&buf[..buf.len() - 1], &long[..]] {
                assert!(matches!(
                    Message::parse(bad),
                    Err(ParseError::InvalidLength { len, .. }) if len == bad.len()
                ));
            }
        }
    }

    #[test]
    fn data_length_boundaries() {
        let mut buf = [0u8; DATA_MIN_LEN];
        buf[0] = 4;
        let Ok(Message::Data(keepalive)) = Message::parse(&buf) else {
            panic!("keepalive should parse");
        };
        assert_eq!(keepalive.ciphertext.len(), TAG_LEN);

        assert_eq!(
            Message::parse(&buf[..DATA_MIN_LEN - 1]),
            Err(ParseError::InvalidLength {
                message: MessageType::Data,
                len: DATA_MIN_LEN - 1
            })
        );
    }

    #[test]
    fn rejects_bad_headers() {
        assert_eq!(Message::parse(&[]), Err(ParseError::Truncated));
        assert_eq!(Message::parse(&[4, 0, 0]), Err(ParseError::Truncated));
        for t in [0, 5, 255] {
            assert_eq!(
                Message::parse(&[t, 0, 0, 0]),
                Err(ParseError::UnknownType(t))
            );
        }
        let mut buf = encode(&samples()[2]);
        buf[3] = 1;
        assert_eq!(Message::parse(&buf), Err(ParseError::ReservedNotZero));
    }

    #[test]
    fn encode_rejects_short_buffer() {
        let m = &samples()[0];
        let mut buf = [0u8; HANDSHAKE_INIT_LEN - 1];
        assert_eq!(
            m.encode(&mut buf),
            Err(BufferTooSmall {
                need: HANDSHAKE_INIT_LEN,
                got: HANDSHAKE_INIT_LEN - 1
            })
        );
    }

    #[test]
    fn encode_writes_only_its_prefix() {
        let m = &samples()[1];
        let mut buf = [0xffu8; 128];
        let n = m.encode(&mut buf).unwrap();
        assert!(buf[n..].iter().all(|&b| b == 0xff));
    }
}
