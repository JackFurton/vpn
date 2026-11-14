use std::fmt;
use std::str::FromStr;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use curve25519_dalek::MontgomeryPoint;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const KEY_LEN: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("invalid base64: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("key must be {KEY_LEN} bytes, got {0}")]
    Length(usize),
    #[error("key generation failed: {0}")]
    Generate(getrandom::Error),
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PublicKey([u8; KEY_LEN]);

/// Wiped from memory on drop. Copies handed to snow are not: snow keeps its
/// own key material and doesn't zeroize it.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey([u8; KEY_LEN]);

pub struct KeyPair {
    pub private: PrivateKey,
    pub public: PublicKey,
}

impl KeyPair {
    pub fn generate() -> Result<Self, KeyError> {
        let mut private = PrivateKey([0; KEY_LEN]);
        getrandom::fill(&mut private.0).map_err(KeyError::Generate)?;
        let public = private.public_key();
        Ok(Self { private, public })
    }
}

impl PrivateKey {
    /// X25519 base-point multiplication, clamping the scalar as RFC 7748
    /// requires (the same thing snow does when it uses the key).
    pub fn public_key(&self) -> PublicKey {
        let scalar = Zeroizing::new(self.0);
        PublicKey(MontgomeryPoint::mul_base_clamped(*scalar).to_bytes())
    }
}

fn to_array(bytes: &[u8]) -> Result<[u8; KEY_LEN], KeyError> {
    bytes.try_into().map_err(|_| KeyError::Length(bytes.len()))
}

macro_rules! key_impls {
    ($t:ident) => {
        impl $t {
            pub const fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
                Self(bytes)
            }

            pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
                &self.0
            }

            pub fn to_base64(&self) -> String {
                STANDARD.encode(self.0)
            }
        }

        impl FromStr for $t {
            type Err = KeyError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let bytes = Zeroizing::new(STANDARD.decode(s.trim())?);
                Ok(Self(to_array(&bytes)?))
            }
        }
    };
}

key_impls!(PublicKey);
key_impls!(PrivateKey);

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.to_base64())
    }
}

// Keeps private keys out of logs and panic messages.
impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_round_trip_through_base64() {
        let kp = KeyPair::generate().unwrap();
        let public: PublicKey = kp.public.to_base64().parse().unwrap();
        let private: PrivateKey = kp.private.to_base64().parse().unwrap();
        assert_eq!(public, kp.public);
        assert_eq!(private.as_bytes(), kp.private.as_bytes());
    }

    #[test]
    fn derives_public_from_private() {
        let kp = KeyPair::generate().unwrap();
        assert_eq!(kp.private.public_key(), kp.public);
    }

    #[test]
    fn matches_rfc7748_test_vector() {
        // RFC 7748 section 6.1, Alice.
        let private: [u8; 32] =
            hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let public = hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        assert_eq!(PrivateKey(private).public_key().as_bytes(), &public);
    }

    fn hex(s: &str) -> [u8; 32] {
        let v: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        v.try_into().unwrap()
    }

    #[test]
    fn private_key_wipes_itself() {
        fn wiped_on_drop<T: ZeroizeOnDrop>() {}
        wiped_on_drop::<PrivateKey>();
        let mut k = KeyPair::generate().unwrap().private;
        k.zeroize();
        assert_eq!(k.as_bytes(), &[0; KEY_LEN]);
    }

    #[test]
    fn rejects_wrong_length() {
        let err = STANDARD.encode([0u8; 16]).parse::<PublicKey>().unwrap_err();
        assert!(matches!(err, KeyError::Length(16)));
    }

    #[test]
    fn private_key_debug_is_redacted() {
        let kp = KeyPair::generate().unwrap();
        assert!(!format!("{:?}", kp.private).contains(&kp.private.to_base64()));
    }
}
