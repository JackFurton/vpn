//! The per-packet ChaCha20-Poly1305 work, split out so it can run on another
//! thread. `Device` makes every decision in order (counters, replay checks,
//! routing) and leaves the cipher work in the `Outbox`;
//! `Outbox::run_crypto` does it, anywhere; `Device::finish` then completes
//! each packet in order.

use std::sync::Arc;

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce};

use crate::wire::{DATA_HEADER_LEN, TAG_LEN};

pub(crate) enum Kind {
    /// A whole data message: header, padded plaintext, room for the tag.
    Seal,
    /// Ciphertext and tag, decrypted in place.
    Open,
}

pub(crate) struct Crypt {
    pub(crate) key: Arc<LessSafeKey>,
    pub(crate) counter: u64,
    pub(crate) kind: Kind,
}

/// Same layout snow uses, which keeps the wire format unchanged: 4 zero
/// bytes, then the counter little-endian.
pub(crate) fn nonce(counter: u64) -> Nonce {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_le_bytes());
    Nonce::assume_unique_for_key(n)
}

impl Crypt {
    /// False only if an Open fails to authenticate.
    pub(crate) fn run(&self, msg: &mut [u8]) -> bool {
        let nonce = nonce(self.counter);
        match self.kind {
            Kind::Seal => {
                let body_len = msg.len() - DATA_HEADER_LEN - TAG_LEN;
                let (body, tag_out) = msg[DATA_HEADER_LEN..].split_at_mut(body_len);
                let tag = self
                    .key
                    .seal_in_place_separate_tag(nonce, Aad::empty(), body)
                    // Only fails past 256 GiB in one message.
                    .expect("message fits ChaCha20");
                tag_out.copy_from_slice(tag.as_ref());
                true
            }
            Kind::Open => self.key.open_in_place(nonce, Aad::empty(), msg).is_ok(),
        }
    }
}
