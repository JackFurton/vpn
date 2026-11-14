//! Handshake DoS protection, after WireGuard section 5.4. See the "DoS
//! protection" section of docs/protocol.md.
//!
//! Every handshake message ends with mac1 and mac2. mac1 is keyed by the
//! recipient's public key, so it proves the sender knows who it's talking to
//! and lets the recipient drop junk before spending a DH operation. Under
//! load, the responder also wants mac2, keyed by a cookie only the real
//! owner of the source address can have received.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use blake2::digest::consts::U16;
use blake2::digest::{Digest, KeyInit, Mac};
use blake2::{Blake2s256, Blake2sMac};
use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use zeroize::Zeroizing;

use crate::keys::PublicKey;
use crate::wire::{COOKIE_LEN, COOKIE_REPLY_LEN, CookieReply, MAC_LEN, Message, TAG_LEN};

const LABEL_MAC1: &[u8] = b"mac1----";
const LABEL_COOKIE: &[u8] = b"cookie--";

/// The responder's cookie secret rotates this often, which bounds how long
/// a cookie stays valid.
pub const COOKIE_SECRET_LIFETIME: Duration = Duration::from_secs(120);
/// An initiator stops using a cookie a little before the responder would
/// stop accepting it.
pub const COOKIE_USE_LIFETIME: Duration = Duration::from_secs(115);

pub type Cookie = [u8; COOKIE_LEN];

type Mac128 = Blake2sMac<U16>;

fn hash(label: &[u8], key: &PublicKey) -> [u8; 32] {
    Blake2s256::new()
        .chain_update(label)
        .chain_update(key.as_bytes())
        .finalize()
        .into()
}

fn mac(key: &[u8], data: &[u8]) -> [u8; MAC_LEN] {
    <Mac128 as KeyInit>::new_from_slice(key)
        .expect("keys are at most 32 bytes")
        .chain_update(data)
        .finalize()
        .into_bytes()
        .into()
}

fn mac_matches(key: &[u8], data: &[u8], tag: &[u8; MAC_LEN]) -> bool {
    <Mac128 as KeyInit>::new_from_slice(key)
        .expect("keys are at most 32 bytes")
        .chain_update(data)
        .verify_slice(tag)
        .is_ok()
}

/// Keys derived from one public key. A device holds one set for itself (to
/// check what peers send it) and one per peer (to stamp what it sends them).
#[derive(Clone)]
pub struct MacKeys {
    mac1: [u8; 32],
    cookie: [u8; 32],
}

impl MacKeys {
    pub fn new(key: &PublicKey) -> Self {
        Self {
            mac1: hash(LABEL_MAC1, key),
            cookie: hash(LABEL_COOKIE, key),
        }
    }

    /// Fills in mac1, and mac2 if we hold a cookie, on an encoded handshake
    /// message. Returns mac1, which a cookie reply to this message is bound to.
    pub fn stamp(&self, msg: &mut [u8], cookie: Option<&Cookie>) -> [u8; MAC_LEN] {
        let (mac1_at, mac2_at) = mac_offsets(msg);
        let mac1 = mac(&self.mac1, &msg[..mac1_at]);
        msg[mac1_at..mac2_at].copy_from_slice(&mac1);
        let mac2 = cookie.map_or([0; MAC_LEN], |c| mac(c, &msg[..mac2_at]));
        msg[mac2_at..].copy_from_slice(&mac2);
        mac1
    }

    /// Checks mac1 on a handshake message addressed to the owner of these keys.
    pub fn verify_mac1(&self, msg: &[u8]) -> bool {
        let (mac1_at, mac2_at) = mac_offsets(msg);
        let tag = msg[mac1_at..mac2_at].try_into().expect("16 bytes");
        mac_matches(&self.mac1, &msg[..mac1_at], tag)
    }

    /// Opens a cookie reply sent to us by the owner of these keys. `sent_mac1`
    /// is mac1 of the initiation it answers; a reply for anything else fails.
    pub fn open_reply(&self, reply: &CookieReply, sent_mac1: &[u8; MAC_LEN]) -> Option<Cookie> {
        let mut cookie = *reply.cookie;
        let tag = reply.tag.as_slice().try_into().ok()?;
        XChaCha20Poly1305::new_from_slice(&self.cookie)
            .expect("32-byte key")
            .decrypt_inout_detached(
                &XNonce::from(*reply.nonce),
                sent_mac1,
                cookie.as_mut_slice().into(),
                tag,
            )
            .ok()?;
        Some(cookie)
    }
}

fn mac_offsets(msg: &[u8]) -> (usize, usize) {
    let mac2_at = msg.len() - MAC_LEN;
    (mac2_at - MAC_LEN, mac2_at)
}

/// Responder side: issues cookies and checks mac2.
pub struct CookieJar {
    keys: MacKeys,
    secret: Zeroizing<[u8; 32]>,
    secret_born: Instant,
}

impl CookieJar {
    pub fn new(own: &MacKeys, now: Instant) -> Self {
        Self {
            keys: own.clone(),
            secret: Zeroizing::new(random()),
            secret_born: now,
        }
    }

    fn cookie_for(&mut self, from: SocketAddr, now: Instant) -> Cookie {
        if now.saturating_duration_since(self.secret_born) >= COOKIE_SECRET_LIFETIME {
            self.secret = Zeroizing::new(random());
            self.secret_born = now;
        }
        let mut addr = [0u8; 18];
        let ip_len = match from.ip() {
            std::net::IpAddr::V4(ip) => {
                addr[..4].copy_from_slice(&ip.octets());
                4
            }
            std::net::IpAddr::V6(ip) => {
                addr[..16].copy_from_slice(&ip.octets());
                16
            }
        };
        addr[ip_len..ip_len + 2].copy_from_slice(&from.port().to_be_bytes());
        mac(&*self.secret, &addr[..ip_len + 2])
    }

    /// Checks mac2 on a handshake message from `from`.
    pub fn verify_mac2(&mut self, msg: &[u8], from: SocketAddr, now: Instant) -> bool {
        let cookie = self.cookie_for(from, now);
        let (_, mac2_at) = mac_offsets(msg);
        let tag = msg[mac2_at..].try_into().expect("16 bytes");
        mac_matches(&cookie, &msg[..mac2_at], tag)
    }

    /// Builds the cookie reply for a handshake message we won't process yet.
    /// No DH involved, and 64 bytes is smaller than what it answers.
    pub fn reply(
        &mut self,
        msg: &[u8],
        receiver_index: u32,
        from: SocketAddr,
        now: Instant,
        out: &mut [u8; COOKIE_REPLY_LEN],
    ) {
        let (mac1_at, mac2_at) = mac_offsets(msg);
        let mut cookie = self.cookie_for(from, now);
        let nonce: [u8; 24] = random();
        let tag = XChaCha20Poly1305::new_from_slice(&self.keys.cookie)
            .expect("32-byte key")
            .encrypt_inout_detached(
                &XNonce::from(nonce),
                &msg[mac1_at..mac2_at],
                cookie.as_mut_slice().into(),
            )
            .expect("16 bytes is within AEAD limits");
        let tag: [u8; TAG_LEN] = tag.into();
        Message::CookieReply(CookieReply {
            receiver_index,
            nonce: &nonce,
            cookie: &cookie,
            tag: &tag,
        })
        .encode(out)
        .expect("buffer is exactly COOKIE_REPLY_LEN");
    }
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0; N];
    getrandom::fill(&mut b).expect("OS random source failed");
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyPair;
    use crate::wire::HANDSHAKE_INIT_LEN;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn message() -> [u8; HANDSHAKE_INIT_LEN] {
        let mut m = [0x42; HANDSHAKE_INIT_LEN];
        m[..4].copy_from_slice(&[1, 0, 0, 0]);
        m
    }

    #[test]
    fn mac1_binds_recipient_and_contents() {
        let r = KeyPair::generate().unwrap().public;
        let keys = MacKeys::new(&r);
        let mut m = message();
        keys.stamp(&mut m, None);
        assert!(keys.verify_mac1(&m));
        assert_eq!(m[HANDSHAKE_INIT_LEN - 16..], [0; 16], "no cookie, no mac2");

        let other = MacKeys::new(&KeyPair::generate().unwrap().public);
        assert!(!other.verify_mac1(&m), "mac1 for someone else");
        m[10] ^= 1;
        assert!(!keys.verify_mac1(&m), "tampered body");
    }

    #[test]
    fn cookie_round_trip_proves_source_address() {
        let now = Instant::now();
        let responder = MacKeys::new(&KeyPair::generate().unwrap().public);
        let mut jar = CookieJar::new(&responder, now);
        let from = addr("198.51.100.7:40000");

        let mut init = message();
        let sent_mac1 = responder.stamp(&mut init, None);
        assert!(!jar.verify_mac2(&init, from, now));

        let mut reply = [0; COOKIE_REPLY_LEN];
        jar.reply(&init, 99, from, now, &mut reply);
        let Ok(Message::CookieReply(parsed)) = Message::parse(&reply) else {
            panic!("reply should parse")
        };
        assert_eq!(parsed.receiver_index, 99);
        let cookie = responder.open_reply(&parsed, &sent_mac1).expect("opens");

        let mut retry = message();
        responder.stamp(&mut retry, Some(&cookie));
        assert!(jar.verify_mac2(&retry, from, now));
        assert!(
            !jar.verify_mac2(&retry, addr("198.51.100.7:40001"), now),
            "other port"
        );
        assert!(
            !jar.verify_mac2(&retry, addr("198.51.100.8:40000"), now),
            "other host"
        );
    }

    #[test]
    fn reply_only_opens_for_the_message_it_answers() {
        let now = Instant::now();
        let responder = MacKeys::new(&KeyPair::generate().unwrap().public);
        let mut jar = CookieJar::new(&responder, now);
        let mut init = message();
        responder.stamp(&mut init, None);
        let mut reply = [0; COOKIE_REPLY_LEN];
        jar.reply(&init, 1, addr("198.51.100.7:1"), now, &mut reply);
        let Ok(Message::CookieReply(parsed)) = Message::parse(&reply) else {
            unreachable!()
        };
        assert!(responder.open_reply(&parsed, &[0; 16]).is_none());
        let stranger = MacKeys::new(&KeyPair::generate().unwrap().public);
        let real_mac1 = init[HANDSHAKE_INIT_LEN - 32..HANDSHAKE_INIT_LEN - 16]
            .try_into()
            .unwrap();
        assert!(stranger.open_reply(&parsed, real_mac1).is_none());
    }

    #[test]
    fn cookies_stop_working_after_secret_rotates() {
        let now = Instant::now();
        let responder = MacKeys::new(&KeyPair::generate().unwrap().public);
        let mut jar = CookieJar::new(&responder, now);
        let from = addr("[2001:db8::1]:51820");
        let mut init = message();
        let mac1 = responder.stamp(&mut init, None);
        let mut reply = [0; COOKIE_REPLY_LEN];
        jar.reply(&init, 1, from, now, &mut reply);
        let Ok(Message::CookieReply(parsed)) = Message::parse(&reply) else {
            unreachable!()
        };
        let cookie = responder.open_reply(&parsed, &mac1).unwrap();
        let mut retry = message();
        responder.stamp(&mut retry, Some(&cookie));

        assert!(jar.verify_mac2(
            &retry,
            from,
            now + COOKIE_SECRET_LIFETIME - Duration::from_millis(1)
        ));
        assert!(!jar.verify_mac2(&retry, from, now + COOKIE_SECRET_LIFETIME));
    }
}
