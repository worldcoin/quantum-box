#![doc = include_str!("../README.md")]

use hpke::{
    Deserializable, HpkeError, OpModeR, OpModeS, Serializable,
    aead::ChaCha20Poly1305,
    kdf::HkdfSha256,
    kem::{Kem as KemTrait, XWing},
    single_shot_open, single_shot_seal_with_rng,
};

mod keys;
mod rng;
pub use keys::{PublicKey, SecretKey};

/// The KEM (Key Encapsulation Mechanism) used: X-Wing is chosen
/// for its IND-CCA security. Reference: <https://eprint.iacr.org/2024/039.pdf>
pub(crate) type XKem = XWing;
/// The Authenticated Encryption (AEAD) algorithm used. `ChaCha20Poly1305` is selected
/// over AES-GCM because `ChaCha20` is constant-time on any hardware and generally more portable. Also
/// inspired on libsodium's sealed box choice (`Salsa20-Poly1305`).
pub(crate) type Aead = ChaCha20Poly1305;
/// The key derivation function. `HKDF-SHA256` is used because its 128-bit security level
/// matches the 128-bit (NIST PQC Level 1) target of the X-Wing KEM.
pub(crate) type Kdf = HkdfSha256;

/// Internal wire format version. Applicable only to this implementation.
///
/// Bumped when existing ciphertext can no longer be opened.
const VERSION: u8 = 0x02;
/// The HPKE algorithm ID: X-Wing (ML-KEM-768 and X25519)
///
/// The explicit ID (`0x647A`) is assigned in the [IANA HPKE KEM Identifiers Registry](https://www.iana.org/assignments/hpke/hpke.xhtml).
const KEM_ID: u16 = 0x647A;
/// The explicit Key Derivation Function: HKDF-SHA256 (RFC 5869)
///
/// The explicit ID (`0x0001`) is defined in [RFC 9180](https://www.rfc-editor.org/info/rfc9180/#section-7.2) and IANA registry.
const KDF_ID: u16 = 0x0001;
/// The AEAD Cipher: ChaCha20-Poly1305
///
/// The explicit ID (`0x0003`) is defined in [RFC 9180](https://www.rfc-editor.org/info/rfc9180/#section-7.3) and IANA registry.
const AEAD_ID: u16 = 0x0003;

/// The header is attached as a prefix to all sealed ciphertext.
///
/// [RFC-9180](https://datatracker.ietf.org/doc/rfc9180/) does not specify a
/// wire format, so this implementation incorporates it to define encoding. The
/// header format is inspired by the OHTTP RFC ([RFC 9458](https://www.ietf.org/rfc/rfc9458.html#section-4.3)).
///
/// All values are encoded big-endian.
///
/// # Security
/// The header is authenticated as HPKE associated data but is not encrypted.
struct Header {
    version: u8,
    kem: u16,
    kdf: u16,
    aead: u16,
}

impl Default for Header {
    fn default() -> Self {
        Self {
            version: VERSION,
            kem: KEM_ID,
            kdf: KDF_ID,
            aead: AEAD_ID,
        }
    }
}

impl Header {
    const LEN: usize = 7;

    fn as_bytes(&self) -> [u8; Self::LEN] {
        let kem = self.kem.to_be_bytes();
        let kdf = self.kdf.to_be_bytes();
        let aead = self.aead.to_be_bytes();
        [
            self.version,
            kem[0],
            kem[1],
            kdf[0],
            kdf[1],
            aead[0],
            aead[1],
        ]
    }

    fn from_bytes(bytes: [u8; Self::LEN]) -> Result<Self, Error> {
        let [version, kem0, kem1, kdf0, kdf1, aead0, aead1] = bytes;

        if version != VERSION {
            return Err(Error::UnsupportedVersion(version));
        }

        let (kem, kdf, aead) = (
            u16::from_be_bytes([kem0, kem1]),
            u16::from_be_bytes([kdf0, kdf1]),
            u16::from_be_bytes([aead0, aead1]),
        );

        if (kem, kdf, aead) != (KEM_ID, KDF_ID, AEAD_ID) {
            return Err(Error::UnsupportedSuite);
        }

        Ok(Self {
            version,
            kem,
            kdf,
            aead,
        })
    }
}

/// X-Wing encapsulated key size: ML-KEM-768 ciphertext (1088) + X25519 (32).
///
/// See also `XWing::EncappedKey::OutputSize`
const ENC_LEN: usize = 1120;
/// Maximum permitted `info` length.
///
/// hpke's key schedule panics when `info.len() + psk_id.len() + 5 ≥ 2^16`
const MAX_INFO_LEN: usize = (1 << 16) - 1 - 5;

impl PublicKey {
    /// Seal `plaintext` to the `recipient`'s public key. This is analogous to
    /// libsodium's [Sealed Box](https://libsodium.gitbook.io/doc/public-key_cryptography/sealed_boxes) where
    /// a message is sent anonymously to a recipient's public key. The important difference is that a hybrid KEM
    /// is used.
    ///
    /// With the choice of X-Wing, the ciphertext remains IND-CCA secure as long as either the security
    /// properties of `X25519` or `ML-KEM-768` (Kyber768) holds.
    ///
    /// # Arguments
    /// - `recipient`: The public key of the recipient.
    /// - `plaintext`: The plaintext message to be encrypted.
    /// - `info`: Optional application-supplied information. This is usually global
    ///   context (e.g. "a backup of X app"). The exact same `info` must be provided
    ///   for sealing and unsealing, otherwise unsealing will fail.
    ///
    /// # Errors
    /// - [`Error::Rng`] if the operating system CSPRNG is unavailable.
    /// - [`Error::InfoExceedsSize`] if `info` is larger than the permitted maximum.
    /// - [`Error::Seal`] if HPKE encapsulation or AEAD sealing unexpectedly fails.
    ///
    /// # Panics
    /// An unavailable OS CSPRNG is reported as [`Error::Rng`] via an internal
    /// readiness check. A panic is only reachable in the residual window where
    /// the CSPRNG passes that check and then fails mid-encapsulation.
    ///
    /// # Wire Format
    /// ```plaintext
    /// HEADER || ENCAPSULATED_KEY || CIPHERTEXT
    /// ```
    pub fn seal(
        recipient: &PublicKey,
        plaintext: &[u8],
        info: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        if info.unwrap_or_default().len() > MAX_INFO_LEN {
            return Err(Error::InfoExceedsSize);
        }

        let header = Header::default().as_bytes();
        let (enc, ciphertext) = single_shot_seal_with_rng::<Aead, Kdf, XKem>(
            &OpModeS::Base,
            recipient.as_hpke(),
            info.unwrap_or_default(),
            plaintext,
            // The header is authenticated as AAD in the AEAD
            &header,
            &mut rng::os_csprng()?,
        )?;
        let enc = enc.to_bytes();
        let mut out = Vec::with_capacity(Header::LEN + enc.len() + ciphertext.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(enc.as_slice());
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }
}

impl SecretKey {
    /// Unseal `ciphertext` with the `recipient`'s secret key.
    ///
    /// # Returns
    /// The opened plaintext.
    ///
    /// # Errors
    /// - [`Error::EmptyCiphertext`] if the ciphertext is empty.
    /// - [`Error::Decode`] if the ciphertext is too short or malformed.
    /// - [`Error::UnsupportedVersion`] if the header specifies an unsupported version.
    /// - [`Error::UnsupportedSuite`] if the header specifices an unsupported cryptographic suite.
    /// - [`Error::Unseal`] if the ciphertext cannot be unsealed.
    pub fn unseal(
        recipient: &SecretKey,
        ciphertext: &[u8],
        info: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        if info.unwrap_or_default().len() > MAX_INFO_LEN {
            return Err(Error::InfoExceedsSize);
        }

        if ciphertext.is_empty() {
            return Err(Error::EmptyCiphertext);
        }

        let Some((header, ciphertext)) = ciphertext.split_first_chunk::<{ Header::LEN }>() else {
            return Err(Error::Decode);
        };

        let header = Header::from_bytes(*header)?;

        let Some((enc_bytes, ciphertext)) = ciphertext.split_first_chunk::<ENC_LEN>() else {
            return Err(Error::Decode);
        };

        let enc = <XKem as KemTrait>::EncappedKey::from_bytes(enc_bytes)?;

        let plaintext = single_shot_open::<Aead, Kdf, XKem>(
            &OpModeR::Base,
            recipient.as_hpke(),
            &enc,
            info.unwrap_or_default(),
            ciphertext,
            &header.as_bytes(),
        )?;

        Ok(plaintext)
    }
}

/// Failure modes with encryption or keys
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Provided key is malformed: bad encoding, checksum, HRP, or length.
    #[error("provided key is malformed")]
    KeyFormat,
    /// The sealed message is too short or malformed.
    #[error("sealed message is malformed")]
    Decode,
    /// KEM decapsulation failed.
    #[error("decapsulation failed")]
    Decap,
    /// AEAD authentication failed: tampered ciphertext, wrong recipient, wrong `info`.
    #[error("unable to unseal: AEAD authentication failed")]
    Unseal,
    /// Sealing the message failed.
    #[error("seal unexpectedly failed")]
    Seal,
    /// The operating system CSPRNG is unavailable, so no secure randomness
    /// could be drawn.
    #[error("operating system CSPRNG is unavailable")]
    Rng,
    /// An HPKE state that this construction never produces. Critical library bug.
    #[error("internal critical bug")]
    Internal,
    /// The provided ciphertext contains an invalid or unsupported version.
    #[error("unsupported version: {0}")]
    UnsupportedVersion(u8),
    /// The provided ciphertext specifies an unsupported cryptographic suite.
    #[error("unsupported suite")]
    UnsupportedSuite,
    /// The provided `info` exceeds the max size
    #[error("info exceeds max size")]
    InfoExceedsSize,
    /// The provided ciphertext is empty
    #[error("empty ciphertext")]
    EmptyCiphertext,
}

impl From<HpkeError> for Error {
    fn from(e: HpkeError) -> Self {
        match e {
            HpkeError::OpenError => Error::Unseal,
            HpkeError::DecapError => Error::Decap,
            HpkeError::EncapError | HpkeError::SealError => Error::Seal,
            HpkeError::ValidationError | HpkeError::IncorrectInputLength(_, _) => Error::Decode,
            HpkeError::MessageLimitReached
            | HpkeError::KdfOutputTooLong
            | HpkeError::InvalidPskBundle => Error::Internal,
        }
    }
}

#[expect(clippy::unwrap_used, reason = "clearer in tests")]
#[cfg(test)]
mod tests {
    use super::{ENC_LEN, Error, Header, MAX_INFO_LEN, PublicKey, SecretKey};
    use hpke::{OpModeS, Serializable, single_shot_seal_with_rng};
    use std::collections::HashSet;

    /// `Poly-1305` authentication tag length
    ///
    /// Reference: <https://en.wikipedia.org/wiki/Poly1305>
    const TAG_LEN: usize = 16;

    fn keypair(seed: &[u8; 32]) -> (SecretKey, PublicKey) {
        let sk = SecretKey::from_seed(seed);
        let pk = sk.public_key();
        (sk, pk)
    }

    #[test]
    fn seal_unseal_roundtrip() {
        let (sk, pk) = keypair(&[7u8; 32]);
        let msg: &[u8] = b"execute order 66";

        let sealed = PublicKey::seal(&pk, msg, None).unwrap();

        let unsealed = SecretKey::unseal(&sk, &sealed, None).unwrap();

        assert_eq!(unsealed, msg);
    }

    #[test]
    fn roundtrips_empty_plaintext() {
        let (sk, pk) = keypair(&[0u8; 32]);

        let sealed = PublicKey::seal(&pk, &[], None).unwrap();
        assert!(!sealed.is_empty());

        let unsealed = SecretKey::unseal(&sk, &sealed, None).unwrap();

        assert!(unsealed.is_empty());
    }

    #[test]
    fn roundtrips_with_matching_info() {
        let (sk, pk) = keypair(&[3u8; 32]);
        let msg: &[u8] = b"never tell me the odds";
        let info: &[u8] = b"com.example";

        let sealed = PublicKey::seal(&pk, msg, Some(info)).unwrap();

        let unsealed = SecretKey::unseal(&sk, &sealed, Some(info)).unwrap();

        assert_eq!(unsealed, msg);
    }

    #[test]
    fn unseal_fails_with_mismatched_info() {
        let (sk, pk) = keypair(&[4u8; 32]);

        let sealed = PublicKey::seal(&pk, b"it's a trap", Some(b"context-a")).unwrap();

        assert_eq!(
            SecretKey::unseal(&sk, &sealed, Some(b"context-b")),
            Err(Error::Unseal)
        );
    }

    #[test]
    fn unseal_fails_with_wrong_recipient() {
        let (_sk, pk) = keypair(&[1u8; 32]);
        let (other_sk, _other_pk) = keypair(&[2u8; 32]);

        let sealed = PublicKey::seal(&pk, b"for my eyes only", None).unwrap();

        assert_eq!(
            SecretKey::unseal(&other_sk, &sealed, None),
            Err(Error::Unseal)
        );
    }

    #[test]
    fn unseal_fails_on_tampered_ciphertext() {
        let (sk, pk) = keypair(&[9u8; 32]);

        let sealed = PublicKey::seal(&pk, b"execute order 66", None).unwrap();

        let mut tampered = sealed.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;

        assert_eq!(SecretKey::unseal(&sk, &tampered, None), Err(Error::Unseal));
    }

    #[test]
    fn unseal_rejects_empty_ciphertext() {
        let (sk, _pk) = keypair(&[1u8; 32]);

        assert_eq!(
            SecretKey::unseal(&sk, b"", None),
            Err(Error::EmptyCiphertext)
        );
    }

    #[test]
    fn unseal_rejects_ciphertext_shorter_than_header() {
        let (sk, _pk) = keypair(&[1u8; 32]);

        assert_eq!(SecretKey::unseal(&sk, b"short", None), Err(Error::Decode));
    }

    #[test]
    fn unseal_rejects_truncated_encapsulated_key() {
        let (sk, pk) = keypair(&[6u8; 32]);

        let sealed = PublicKey::seal(&pk, b"this message will self-destruct", None).unwrap();

        // Valid header, but the encapsulated key is cut short.
        let truncated = &sealed[..Header::LEN + 10];

        assert_eq!(SecretKey::unseal(&sk, truncated, None), Err(Error::Decode));
    }

    #[test]
    fn unseal_rejects_unsupported_version() {
        let (sk, pk) = keypair(&[1u8; 32]);

        let sealed = PublicKey::seal(&pk, b"hello there", None).unwrap();
        let mut bad = sealed.clone();
        let bad_version = 1;
        bad[0] = bad_version;

        assert_eq!(
            SecretKey::unseal(&sk, &bad, None),
            Err(Error::UnsupportedVersion(bad_version))
        );
    }

    #[test]
    fn unseal_rejects_unsupported_suite() {
        let (sk, pk) = keypair(&[1u8; 32]);

        let sealed = PublicKey::seal(&pk, b"hello there", None).unwrap();
        for offset in [1, 3, 5] {
            let mut bad = sealed.clone();
            bad[offset] ^= 0xFF;

            assert_eq!(
                SecretKey::unseal(&sk, &bad, None),
                Err(Error::UnsupportedSuite),
                "suite field at offset {offset} must be rejected"
            );
        }
    }

    #[test]
    fn unseal_rejects_ciphertext_without_authenticated_header() {
        let (sk, pk) = keypair(&[1u8; 32]);
        let (enc, ciphertext) = single_shot_seal_with_rng::<super::Aead, super::Kdf, super::XKem>(
            &OpModeS::Base,
            pk.as_hpke(),
            &[],
            b"hello there",
            &[],
            &mut super::rng::os_csprng().unwrap(),
        )
        .unwrap();
        let mut sealed = Header::default().as_bytes().to_vec();
        sealed.extend_from_slice(&enc.to_bytes());
        sealed.extend_from_slice(&ciphertext);

        assert_eq!(SecretKey::unseal(&sk, &sealed, None), Err(Error::Unseal));
    }

    #[test]
    fn seal_prepends_wire_header() {
        let (_sk, pk) = keypair(&[1u8; 32]);
        let expected = [0x02, 0x64, 0x7A, 0x00, 0x01, 0x00, 0x03];

        let sealed = PublicKey::seal(&pk, b"hello there", None).unwrap();

        assert_eq!(Header::default().as_bytes(), expected);
        assert_eq!(Header::from_bytes(expected).unwrap().as_bytes(), expected);
        assert_eq!(&sealed[..Header::LEN], &expected);
    }

    #[test]
    fn seal_output_has_expected_length() {
        let (_sk, pk) = keypair(&[1u8; 32]);
        let msg: &[u8] = b"hello there";

        let sealed = PublicKey::seal(&pk, msg, None).unwrap();

        // HEADER || ENCAPSULATED_KEY || len(plaintext + authentication tag)
        assert_eq!(sealed.len(), Header::LEN + ENC_LEN + msg.len() + TAG_LEN);
    }

    #[test]
    fn seal_is_non_deterministic() {
        let (_sk, pk) = keypair(&[1u8; 32]);
        let msg: &[u8] = b"same message";

        let sealed = PublicKey::seal(&pk, msg, None).unwrap();
        let sealed2 = PublicKey::seal(&pk, msg, None).unwrap();

        assert_ne!(sealed, sealed2);
    }

    /// Regression guard for encapsulation-randomness reuse: sealing the same
    /// plaintext to the same recipient with the same `info` must draw fresh
    /// X-Wing encapsulation randomness every call. A repeated encapsulated key
    /// would mean a repeated AEAD key and base nonce (nonce reuse).
    #[test]
    fn seal_draws_fresh_encapsulation_randomness_each_call() {
        let (_sk, pk) = keypair(&[1u8; 32]);
        let msg: &[u8] = b"same message, same recipient, same info";
        let info: &[u8] = b"com.example";

        let mut enc_keys = HashSet::new();
        for _ in 0..64 {
            let sealed = PublicKey::seal(&pk, msg, Some(info)).unwrap();
            let enc = sealed[Header::LEN..Header::LEN + ENC_LEN].to_vec();
            assert!(
                enc_keys.insert(enc),
                "encapsulated key repeated: encapsulation randomness was reused"
            );
        }
        assert_eq!(enc_keys.len(), 64);
    }

    #[test]
    fn seal_and_unseal_accept_info_at_max_len() {
        let (sk, pk) = keypair(&[1u8; 32]);
        let msg: &[u8] = b"boundary";
        let info = vec![0x2a; 2_usize.pow(16) - 5 - 1];

        let sealed = PublicKey::seal(&pk, msg, Some(&info)).unwrap();
        let unsealed = SecretKey::unseal(&sk, &sealed, Some(&info)).unwrap();

        assert_eq!(unsealed, msg);
    }

    #[test]
    fn seal_rejects_info_over_max_len() {
        let (_sk, pk) = keypair(&[1u8; 32]);
        let info = vec![0x2a; MAX_INFO_LEN + 1];

        assert_eq!(
            PublicKey::seal(&pk, b"nope", Some(&info)),
            Err(Error::InfoExceedsSize)
        );
    }

    #[test]
    fn unseal_rejects_info_over_max_len() {
        let (sk, pk) = keypair(&[1u8; 32]);
        let sealed = PublicKey::seal(&pk, b"nope", None).unwrap();
        let info = vec![0x2a; MAX_INFO_LEN + 1];

        assert_eq!(
            SecretKey::unseal(&sk, &sealed, Some(&info)),
            Err(Error::InfoExceedsSize)
        );
    }
}
