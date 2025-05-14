use crate::bitcoin::consensus::ConsensusBlockPublicInput;
use crate::bitcoin::{
    EXPECTED_EPOCH_SECONDS, M_CONFIRMATION, MIN_TRUSTED_BLOCK_NUMBER, double_sha256_hash,
    to_little_endian_bytes,
};
use crypto_bigint::{CheckedMul, U256};
use serde::{Deserialize, Serialize};

/// A circuit-friendly representation of a Bitcoin block header.
///
/// This struct is designed for use inside zkVM programs (e.g., RISC-V code compiled by SP1),
/// where each field must be a fixed-size byte array to enable deterministic encoding and decoding,
/// and to simplify circuit constraint generation.
///
/// Unlike the host-side `bitcoin::block::BlockHeader`, all numeric values here are serialized using
/// little-endian byte arrays. This avoids implicit conversions and helps ensure consistent
/// interpretation across both host and guest environments.
#[derive(Default, Serialize, Deserialize, Clone, Copy, Debug)]
pub struct CircuitBlock {
    pub height: u64,
    pub version: [u8; 4],
    pub prev_blockhash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub time: [u8; 4],
    pub bits: [u8; 4],
    pub nonce: [u8; 4],
}

impl CircuitBlock {
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(80);
        bytes.extend_from_slice(&self.version);
        bytes.extend_from_slice(&self.prev_blockhash);
        bytes.extend_from_slice(&self.merkle_root);
        bytes.extend_from_slice(&self.time);
        bytes.extend_from_slice(&self.bits);
        bytes.extend_from_slice(&self.nonce);
        assert_eq!(bytes.len(), 80, "Header must be exactly 80 bytes");
        bytes
    }

    pub fn compute_block_hash(&self) -> [u8; 32] {
        let header = self.serialize();
        double_sha256_hash(&header)
    }
}

// taken from rust-bitcoin
fn bits_to_target(bits: [u8; 4]) -> U256 {
    let bits = u32::from_le_bytes(bits);
    let (mant, expt) = {
        let unshifted_expt = bits >> 24;
        if unshifted_expt <= 3 {
            ((bits & 0xFFFFFF) >> (8 * (3 - unshifted_expt as usize)), 0)
        } else {
            (bits & 0xFFFFFF, 8 * ((bits >> 24) - 3))
        }
    };
    if mant > 0x7F_FFFF {
        U256::ZERO
    } else {
        U256::from(mant) << expt as usize
    }
}

#[sp1_derive::cycle_tracker]
fn assert_new_target_bits(
    last_epoch_begin_block: &CircuitBlock,
    last_epoch_end_block: &CircuitBlock,
    new_epoch_begin_block: &CircuitBlock,
) {
    let old_target_difficulty = bits_to_target(last_epoch_begin_block.bits);
    let new_target_difficulty = old_target_difficulty
        .checked_mul(&U256::from_u32(
            u32::from_le_bytes(last_epoch_end_block.time)
                - u32::from_le_bytes(last_epoch_begin_block.time),
        ))
        .unwrap()
        .checked_div(&U256::from_u32(EXPECTED_EPOCH_SECONDS))
        .unwrap();

    let new_bits = u32::from_le_bytes(new_epoch_begin_block.bits);
    let (mant, mut expt) = (new_bits >> 24, new_bits & 0xFFFFFF);
    // upper bound of expt
    if expt > 0x7fffff {
        expt >>= 8
    };
    if mant <= 3 {
        assert_eq!(
            new_target_difficulty,
            U256::from_u32(expt) >> (8 * (3 - mant) as usize),
            "Block: new target bits not matched"
        );
    } else {
        assert_eq!(
            new_target_difficulty >> (8 * (mant - 3) as usize),
            U256::from_u32(expt),
            "Block: new target bits not matched"
        );
    }
}

/// Note:
///     1) prev_block_hash, proposed_block_hash, retarget_block_hash, median_block_hash, proposed_tx_merkle_root, proposed_block_height
///       all these need to be asserted with the help of proposed_chain, and retarget_block
///     2) current proposed block header should be the last one of proposed_chain
pub fn validate_block(
    proposed_chain: Vec<CircuitBlock>,
    retarget_block: CircuitBlock,
    block_public_input: ConsensusBlockPublicInput,
) {
    let ConsensusBlockPublicInput {
        prev_block_hash,
        proposed_block_hash,
        retarget_block_hash,
        median_block_hash,
        m_deep_tx_merkle_root,
        proposed_block_height,
    } = block_public_input;

    // 1) assertion of length of proposed chain
    let minimum_chain_len = MIN_TRUSTED_BLOCK_NUMBER + 1;
    assert!(
        proposed_chain.len() >= minimum_chain_len,
        "The proposed chain is too short; it must have at least 12 blocks."
    );
    let proposed_block = *proposed_chain.last().unwrap();
    let previous_block = proposed_chain[proposed_chain.len() - 2];
    let m_deep_block = proposed_chain[proposed_chain.len() - M_CONFIRMATION - 1];

    // 2) assertion of proposed block height
    assert!(
        proposed_block_height >= (MIN_TRUSTED_BLOCK_NUMBER + 1) as u64,
        "The proposed block height must be at least 1."
    );
    assert!(
        proposed_block_height >= retarget_block.height,
        "The proposed block height is below the retarget block height."
    );
    assert_eq!(
        proposed_block_height, proposed_block.height,
        "The proposed block height does not match the current witness block height."
    );
    assert_eq!(
        proposed_block_height,
        previous_block.height + 1,
        "The proposed block height does not match with previous witness block height."
    );
    assert_eq!(
        proposed_block_height,
        m_deep_block.height + M_CONFIRMATION as u64,
        "The proposed block height does not match the m-deep witness block height."
    );

    // 3) assertion of proposed block hash
    assert_eq!(
        proposed_block_hash,
        proposed_block.compute_block_hash(),
        "The proposed block hash does not match the expected value."
    );

    // 4) check previous block hash
    assert_eq!(
        prev_block_hash,
        previous_block.compute_block_hash(),
        "The previous block hash does not match the expected value."
    );
    assert_eq!(
        prev_block_hash,
        to_little_endian_bytes(proposed_block.prev_blockhash),
        "The block hashes are not properly chained."
    );

    // 5) check retarget block hash
    assert_eq!(
        retarget_block_hash,
        retarget_block.compute_block_hash(),
        "The retarget block hash does not match the expected value."
    );
    assert_ne!(
        retarget_block_hash, proposed_block_hash,
        "The retarget block hash does not match the expected value."
    );

    // 6) check target bits
    if proposed_block_height % 2016 == 0 {
        assert_new_target_bits(&retarget_block, &previous_block, &proposed_block);
    } else {
        assert_eq!(
            retarget_block.bits, proposed_block.bits,
            "The target bits of proposed block is invalid."
        );
    }

    // 7) check PoW
    let proposed_target = bits_to_target(proposed_block.bits);
    assert!(
        U256::from_be_slice(&proposed_block_hash).le(&proposed_target),
        "The proof-of-work of proposed block is invalid."
    );

    // 8) check timestamp
    let median_block = {
        let median_idx = if MIN_TRUSTED_BLOCK_NUMBER % 2 == 0 {
            MIN_TRUSTED_BLOCK_NUMBER / 2
        } else {
            (MIN_TRUSTED_BLOCK_NUMBER - 1) / 2
        };
        let (start_idx, end_idx) = (
            proposed_chain.len() - minimum_chain_len,
            proposed_chain.len() - 1,
        );
        let mut observing_blocks = proposed_chain[start_idx..end_idx].to_vec(); // exactly 11 blocks
        observing_blocks
            .sort_by(|&a, &b| u32::from_le_bytes(a.time).cmp(&u32::from_le_bytes(b.time)));
        observing_blocks[median_idx]
    };
    assert_eq!(
        median_block_hash,
        median_block.compute_block_hash(),
        "The median block hash does not match the expected value."
    );
    assert!(
        u32::from_le_bytes(proposed_block.time) >= u32::from_le_bytes(median_block.time),
        "The timestamp of proposed block is not invalid."
    );

    // 9) check tx merkle root
    assert_eq!(
        m_deep_tx_merkle_root, m_deep_block.merkle_root,
        "The merkle root of proposed block's transactions is invalid."
    );
}
