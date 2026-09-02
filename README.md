<img src="header-image.jpg" alt="" width="250px" />

# Quantum Box

> [!WARNING]
> This code is currently **UNAUDITED**. Please be careful with any use. Furthermore, the underlying `hpke` library has only undergone an informal review in version 0.8 and the `x-wing` library has also not been independently audited.

This is a sealed box with a hybrid key encapsulation mechanism (post-quantum and classic elliptic curve). This is inspired by libsodium's [Sealed Boxes](https://libsodium.gitbook.io/doc/public-key_cryptography/sealed_boxes) where a message can be anonymously sent to a recipient given their public key.

The motivation for this implementation is to follow libsodium's design but implementing a key encapsulation mechanism that already incorporates a quantum-resistant algorithm. The (few) design choices made here follow the principle that the ciphertext will remain secure as long as the security of either the classical **OR** post-quantum algorithms holds.

This implementation does not roll its own cryptography, there are no cryptographic algorithms or ciphers being implemented here, this is rather a reference implementation of a specific standardized ciphersuite choice and the wiring/encoding format.

## Design Choices

1. The primary scheme is **Hybrid Public Key Encryption (HPKE)** from [RFC 9180](https://www.rfc-editor.org/info/rfc9180) which defines the glue between a KEM, a KDF and authenticated encryption (AEAD). This is implemented through the [hpke](https://github.com/rozbb/rust-hpke) crate. HPKE is already used in some TLS schemes, MLS and OHTTP.
2. The Key Encapsulation Mechanism (KEM) choice is `X-Wing` [draft-connolly-cfrg-xwing-kem-06](https://datatracker.ietf.org/doc/html/draft-connolly-cfrg-xwing-kem-06) and [paper](https://eprint.iacr.org/2024/039) which is IND-CCA secure (internally it uses `ML-KEM-768` prev. `Kyber-768` and `X25519` curve). The X-Wing implementation comes from `RustCrypto`'s [crate](https://github.com/RustCrypto/KEMs/tree/master/x-wing).
3. The KDF is `HKDF-SHA-256`, whose 128-bit security level is consistent with the strength of `X-Wing`'s components: its `X25519` half provides roughly 128-bit classical security, and its `ML-KEM-768` half targets NIST PQC security category 3.
4. The AEAD is `ChaCha20-Poly1305` which is constant time on any hardware. The decision is to maximize portability.


## Example

The library owns its randomness: sealing and key generation draw from the operating system CSPRNG internally, so there is no RNG to pass in or misuse.

```rust
use quantum_box::{SecretKey, PublicKey};

let sk = SecretKey::generate().unwrap();
let pk = sk.public_key();

let msg: &[u8] = b"execute order 66";

let sealed = PublicKey::seal(&pk, msg, None).unwrap();

let unsealed = SecretKey::unseal(&sk, &sealed, None).unwrap();

assert_eq!(unsealed, msg);
```

## Platform support

Randomness comes from the operating system CSPRNG via [`getrandom`](https://docs.rs/getrandom). Particularly for the browser (`wasm32-unknown-unknown` target) an explicit backend must be specified for the randomness source. For web targets, enable the `wasm_js` feature flag which uses [`Crypto.getRandomValues`](https://www.w3.org/TR/WebCryptoAPI/#Crypto-method-getRandomValues) under the hood. More information on the [getrandom](https://carates.io/getrandom/index.html#webassembly-support) crate.
