//! Parsing must never panic, and anything that parses must encode back to
//! exactly the bytes it came from.
#![no_main]

use libfuzzer_sys::fuzz_target;
use vpn_proto::wire::Message;

fuzz_target!(|data: &[u8]| {
    if let Ok(m) = Message::parse(data) {
        let mut buf = vec![0; m.encoded_len()];
        let n = m.encode(&mut buf).expect("encoded_len is enough");
        assert_eq!(&buf[..n], data);
    }
});
