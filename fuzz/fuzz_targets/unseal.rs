#![no_main]
//! Feed arbitrary, attacker-controlled bytes to `SecretKey::unseal`.
//!
//! `unseal` parses fully untrusted input (the wire header, the encapsulated
//! key, and the AEAD ciphertext). Two invariants:
//! 1. It never panics or over-reads on arbitrary input — every rejection path
//!    returns a `Result`.
//! 2. Definitely-malformed input is rejected with an `Err` for every `info`
//!    value. "Definitely malformed" is the subset we can prove

use libfuzzer_sys::fuzz_target;
use quantum_box::{PublicKey, SecretKey};
use std::sync::LazyLock;

/// A fixed recipient. Key material is not the fuzzed surface here — the
/// ciphertext bytes are — so we build the keypair once to keep throughput high.
static RECIPIENT: LazyLock<SecretKey> = LazyLock::new(|| SecretKey::from_seed(&[0x42; 32]));

/// The smallest possible sealed message: header + encapsulated key + AEAD tag
/// over an empty plaintext
static MIN_SEALED: LazyLock<Vec<u8>> = LazyLock::new(|| {
    PublicKey::seal(&RECIPIENT.public_key(), b"", None)
        .expect("sealing an empty plaintext to a valid recipient must succeed")
});

fuzz_target!(|data: &[u8]| {
    let recipient: &SecretKey = &RECIPIENT;
    let min_len = MIN_SEALED.len();

    // Classify inputs we can prove are malformed regardless of key or AEAD:
    let too_short = data.len() < min_len;
    let wrong_version = data.len() >= min_len && data[0] != MIN_SEALED[0];
    let provably_malformed = too_short || wrong_version;

    // One unseal per info variant, reused for both the no-panic check and the
    // rejection assertion.
    for info in [None, Some(&b"quantum-box-fuzz"[..])] {
        let result = SecretKey::unseal(recipient, data, info);
        assert!(
            !provably_malformed || result.is_err(),
            "unseal accepted a provably malformed {}-byte message (minimum valid length is {})",
            data.len(),
            min_len,
        );
    }
});
