#![no_main]
//! Fuzz public-key parsing and serialization.
//!
//! Two invariants:
//! 1. `PublicKey::from_bytes` never panics on arbitrary bytes, and rejects any
//!    input whose length is not the canonical key length
//!    (NOTE: an invalid encoding at the correct length can't be classified without
//!    reimplementing the parser, so it is only checked for panics.)
//! 2. Any key the library itself produces round-trips through `to_bytes` /
//!    `from_bytes` and compares equal.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use quantum_box::{Error, PublicKey, SecretKey};

#[derive(Debug, Arbitrary)]
struct Input {
    /// Seed for a well-formed key that must round-trip.
    seed: [u8; 32],
    /// Untrusted bytes handed straight to the parser.
    raw: Vec<u8>,
}

fuzz_target!(|input: Input| {
    // A key the library produces must round-trip, and its length is the
    // canonical wire length we classify untrusted input against.
    let pk = SecretKey::from_seed(&input.seed).public_key();
    let bytes = pk.to_bytes();
    let Ok(parsed) = PublicKey::from_bytes(&bytes) else {
        panic!("a key produced by to_bytes must parse back");
    };
    assert_eq!(parsed, pk, "public key must round-trip through bytes");

    // Untrusted bytes must never panic the parser. Any wrong-length input is
    // provably not a valid key and must be rejected with `KeyFormat`
    let result = PublicKey::from_bytes(&input.raw);
    if input.raw.len() != bytes.len() {
        assert_eq!(
            result,
            Err(Error::KeyFormat),
            "from_bytes accepted a {}-byte input (canonical key length is {})",
            input.raw.len(),
            bytes.len(),
        );
    }
});
