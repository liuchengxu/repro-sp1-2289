pub mod block;
pub mod consensus;
pub mod inclusion;

use self::consensus::ConsensusVerifierPublicInput;
use self::inclusion::InclusionPublicInput;
use crate::sha256_hash;
use serde::{Deserialize, Serialize};

pub const MIN_TRUSTED_BLOCK_NUMBER: usize = 11;
pub const M_CONFIRMATION: usize = 3;
pub const MAX_BLOCKS: usize = 3000;
pub const EPOCH_BLOCK_NUMBER: u32 = 2016;
pub const BLOCK_TIMEVAL: u32 = 600;
pub const EXPECTED_EPOCH_SECONDS: u32 = EPOCH_BLOCK_NUMBER * BLOCK_TIMEVAL;

pub const GENESIS_BLOCK_HEIGHT: u64 = 0u64;
pub const GENESIS_BLOCK_HASH: [u8; 32] = [0u8; 32];
pub const GENESIS_TARGET_BITS: [u8; 4] = [0u8; 4];

#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct AggregationPublicInput {
    pub consensus_verifier_public_input: ConsensusVerifierPublicInput,
    pub inclusion_public_input: InclusionPublicInput,
}

#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct AggregationWitness {}

#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct AggregationInput {
    pub consensus_vkey_u32_hash: [u32; 8],
    pub public_input: AggregationPublicInput,
    pub witness: AggregationWitness,
}

impl AggregationInput {
    pub fn new(
        consensus_vkey_u32_hash: [u32; 8],
        consensus_verifier_public_input: ConsensusVerifierPublicInput,
        inclusion_public_input: InclusionPublicInput,
    ) -> Self {
        Self {
            consensus_vkey_u32_hash,
            public_input: AggregationPublicInput {
                consensus_verifier_public_input,
                inclusion_public_input,
            },
            witness: AggregationWitness::default(),
        }
    }
}

/// Converts a big-endian hash to little-endian byte order.
pub fn to_little_endian_bytes(hash: [u8; 32]) -> [u8; 32] {
    let mut le = hash;
    le.reverse();
    le
}

pub fn double_sha256_hash(tx: &[u8]) -> [u8; 32] {
    to_little_endian_bytes(sha256_hash(&sha256_hash(tx)))
}

pub fn hash_pairs(hash_1: [u8; 32], hash_2: [u8; 32]) -> [u8; 32] {
    // [0] & [1] Combine hashes into one 64 byte array, reversing byte order
    let combined_hashes: [u8; 64] = hash_1
        .into_iter()
        .rev()
        .chain(hash_2.into_iter().rev())
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap();
    double_sha256_hash(&combined_hashes)
}

pub fn get_merkle_root(leaves: Vec<[u8; 32]>) -> [u8; 32] {
    let mut current_level = leaves;
    while current_level.len() > 1 {
        let mut next_level = Vec::new();
        let mut i = 0;

        while i < current_level.len() {
            let left = current_level[i];
            let right = if i + 1 < current_level.len() {
                current_level[i + 1]
            } else {
                left
            };

            let parent_hash = hash_pairs(left, right);
            next_level.push(parent_hash);

            i += 2;
        }
        current_level = next_level;
    }
    current_level[0]
}
