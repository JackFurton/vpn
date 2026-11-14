use std::fmt;
use std::str::FromStr;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::NOISE_PARAMS;

pub const KEY_LEN: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("invalid base64: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("key must be {KEY_LEN} bytes, got {0}")]
    Length(usize),
    #[error("key generation failed: {0}")]
    Generate(#[from] snow::Error),
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PublicKey([u8; KEY_LEN]);

#[derive(Clone)]
pub struct PrivateKey([u8; KEY_LEN]);

pub struct KeyPair {
    pub private: PrivateKey,
    pub public: PublicKey,
}

impl KeyPair {
    pub fn generate() -> Result<Self, KeyError> {
        let kp = snow::Builder::new(NOISE_PARAMS.parse()?).generate_keypair()?;
        Ok(Self {
            private: PrivateKey(to_array(&kp.private)?),
            public: PublicKey(to_array(&kp.public)?),
        })
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
                Ok(Self(to_array(&STANDARD.decode(s.trim())?)?))
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
