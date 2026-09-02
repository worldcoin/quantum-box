# Fuzzing Quantum Box

Fuzzy testing with [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz). Requires a nightly toolchain:

```sh
rustup toolchain install nightly
cargo install cargo-fuzz --locked
```

## Targets

| Target       | Invariant |
|--------------|-----------|
| `unseal`     | `SecretKey::unseal` never panics on arbitrary ciphertext; malformed input is always rejected with an `Error`. |
| `public_key` | `PublicKey::from_bytes` never panics on arbitrary bytes; keys the library produces round-trip through `to_bytes`/`from_bytes`. |
| `roundtrip`  | For arbitrary plaintext, `info`, and keys, `seal` followed by `unseal` returns the original plaintext. |

## Running

```sh
cargo +nightly fuzz run unseal -- -dict=holocron.dict

cargo +nightly fuzz run public_key
cargo +nightly fuzz run roundtrip
```

A discovered crash is written to `fuzz/artifacts/<target>/`. Reproduce it with:

```sh
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<crash-file>
```
