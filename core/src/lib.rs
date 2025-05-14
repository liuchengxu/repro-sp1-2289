pub mod babylon;
pub mod bitcoin;

use sha2::{Digest, Sha256};

pub fn sha256_hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
