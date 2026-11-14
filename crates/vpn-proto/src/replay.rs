//! Sliding-window replay protection for data packet counters, after RFC 6479
//! (https://datatracker.ietf.org/doc/html/rfc6479).
//!
//! The bitmap is a ring of 64-bit words indexed by `counter % TOTAL_BITS`.
//! Moving the window forward clears whole words rather than shifting bits,
//! so a jump of any size costs at most `WORDS` writes.

const WORDS: usize = 32;
const WORD_BITS: u64 = u64::BITS as u64;
const TOTAL_BITS: u64 = WORDS as u64 * WORD_BITS;

/// How far behind the highest accepted counter a packet may arrive and still
/// be accepted. One word less than the bitmap, because the word holding the
/// window's lower edge is shared with counters that already fell out of it.
pub const WINDOW_SIZE: u64 = TOTAL_BITS - WORD_BITS;

/// Counters at or past this are never accepted; the session must rekey first.
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13);

#[derive(Debug, Clone)]
pub struct ReplayWindow {
    bitmap: [u64; WORDS],
    highest: u64,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    pub fn new() -> Self {
        // highest = 0 with an empty bitmap still accepts counter 0 exactly
        // once, so no separate "nothing seen yet" state is needed.
        Self {
            bitmap: [0; WORDS],
            highest: 0,
        }
    }

    /// Cheap pre-check before decrypting. Never mutates, so it is safe to run
    /// on unauthenticated packets. `accept` must still be called afterwards.
    pub fn may_accept(&self, counter: u64) -> bool {
        if counter >= REJECT_AFTER_MESSAGES || counter + WINDOW_SIZE < self.highest {
            return false;
        }
        counter > self.highest || !self.is_set(counter)
    }

    /// Records `counter` as seen. Call only after the packet authenticated,
    /// or a forged high counter would push genuine packets out of the window.
    /// Returns false if the packet is a replay or too old.
    pub fn accept(&mut self, counter: u64) -> bool {
        if !self.may_accept(counter) {
            return false;
        }
        if counter > self.highest {
            let from = self.highest / WORD_BITS;
            let to = counter / WORD_BITS;
            for word in (from + 1..=to).take(WORDS) {
                self.bitmap[word as usize % WORDS] = 0;
            }
            self.highest = counter;
        }
        let (word, bit) = Self::position(counter);
        self.bitmap[word] |= bit;
        true
    }

    fn is_set(&self, counter: u64) -> bool {
        let (word, bit) = Self::position(counter);
        self.bitmap[word] & bit != 0
    }

    fn position(counter: u64) -> (usize, u64) {
        let slot = counter % TOTAL_BITS;
        ((slot / WORD_BITS) as usize, 1 << (slot % WORD_BITS))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn accepts_in_order_once() {
        let mut w = ReplayWindow::new();
        for c in 0..5000 {
            assert!(w.accept(c), "counter {c}");
            assert!(!w.accept(c), "duplicate {c}");
        }
    }

    #[test]
    fn accepts_out_of_order_inside_window() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(100));
        assert!(w.accept(3));
        assert!(w.accept(99));
        assert!(w.accept(0));
        assert!(!w.accept(3));
        assert!(!w.accept(100));
    }

    #[test]
    fn window_edge_is_exact() {
        let mut w = ReplayWindow::new();
        let top = 10 * TOTAL_BITS + 17;
        assert!(w.accept(top));
        assert!(!w.may_accept(top - WINDOW_SIZE - 1));
        assert!(w.accept(top - WINDOW_SIZE));
        assert!(!w.accept(top - WINDOW_SIZE));
    }

    #[test]
    fn far_jump_forgets_old_bits() {
        let mut w = ReplayWindow::new();
        for c in 0..TOTAL_BITS {
            assert!(w.accept(c));
        }
        // These land on the same bitmap slots as 1..64 did. They must read
        // as fresh, not as replays of the counters that used to live there.
        let jump = 1_000 * TOTAL_BITS;
        assert!(w.accept(jump));
        for c in jump - 63..jump {
            assert!(w.accept(c), "counter {c}");
        }
        assert!(!w.accept(0));
    }

    #[test]
    fn rejects_at_message_limit() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(REJECT_AFTER_MESSAGES - 1));
        assert!(!w.accept(REJECT_AFTER_MESSAGES));
        assert!(!w.accept(u64::MAX));
    }

    #[test]
    fn may_accept_does_not_mutate() {
        let mut w = ReplayWindow::new();
        assert!(w.may_accept(1 << 40));
        assert!(w.accept(5));
        assert!(w.accept(4));
    }

    // Checks random sequences against the obvious definition: accept a
    // counter iff it was never accepted and is within WINDOW_SIZE of the
    // highest one accepted so far.
    #[test]
    fn matches_reference_model() {
        let mut rng = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = move || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };
        for _ in 0..200 {
            let mut w = ReplayWindow::new();
            let mut seen = HashSet::new();
            let mut highest = 0u64;
            let mut base = 0u64;
            for _ in 0..2_000 {
                let r = next();
                // Mostly small moves around a creeping base, some big jumps.
                base += match r % 100 {
                    0 => r >> 52,
                    1..=60 => 1,
                    _ => 0,
                };
                let spread = 2 * TOTAL_BITS;
                let c = (base + (next() % spread)).saturating_sub(TOTAL_BITS);
                let expect = !seen.contains(&c) && c + WINDOW_SIZE >= highest;
                assert_eq!(w.may_accept(c), expect, "may_accept({c})");
                assert_eq!(w.accept(c), expect, "accept({c})");
                if expect {
                    seen.insert(c);
                    highest = highest.max(c);
                }
            }
        }
    }
}
