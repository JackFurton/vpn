//! Differential: the bitmap window must agree with the obvious HashSet
//! definition on every counter sequence the fuzzer can find.
#![no_main]

use std::collections::HashSet;

use libfuzzer_sys::fuzz_target;
use vpn_proto::replay::{REJECT_AFTER_MESSAGES, ReplayWindow, WINDOW_SIZE};

fuzz_target!(|data: &[u8]| {
    let mut window = ReplayWindow::new();
    let mut seen = HashSet::new();
    let mut highest = 0u64;
    let mut base = 0u64;
    for step in data.chunks_exact(3) {
        // First byte moves the base: mostly small creeps, sometimes a big
        // jump or a leap to just under the message limit.
        base = match step[0] {
            0xff => base.saturating_add(1 << 20),
            0xfe => REJECT_AFTER_MESSAGES - 4_000,
            b => base.saturating_add(u64::from(b % 4)),
        };
        let offset = u64::from(u16::from_le_bytes([step[1], step[2]]));
        let counter = base.saturating_add(offset).saturating_sub(2_048);

        let expect = counter < REJECT_AFTER_MESSAGES
            && !seen.contains(&counter)
            && counter + WINDOW_SIZE >= highest;
        assert_eq!(window.may_accept(counter), expect, "may_accept({counter})");
        assert_eq!(window.accept(counter), expect, "accept({counter})");
        if expect {
            seen.insert(counter);
            highest = highest.max(counter);
        }
    }
});
