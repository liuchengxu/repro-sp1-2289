//! This module defines the primitives used in the consensus program.

use crate::bitcoin::block::CircuitBlock;
use crate::sha256_hash;
use serde::{Deserialize, Serialize};

/// Public values of consensus proving for individual blocks.
///
/// Note that, public values need to be committed by prover.
#[derive(Default, Serialize, Deserialize, Clone, Copy, Debug)]
pub struct ConsensusBlockPublicInput {
    /// Little-endian bytes of previous block hash
    pub prev_block_hash: [u8; 32],
    /// Little-endian bytes of proposed block hash
    pub proposed_block_hash: [u8; 32],
    /// Little-endian bytes of retargeted block (the very beginning block of current epoch) hash
    pub retarget_block_hash: [u8; 32],
    /// Little-endian bytes of median block (previous 11 blocks) hash
    pub median_block_hash: [u8; 32],
    /// Transaction merkle root of proposed block.
    pub m_deep_tx_merkle_root: [u8; 32],
    /// Absolute block height of proposed block
    pub proposed_block_height: u64,
}

impl ConsensusBlockPublicInput {
    pub fn new(
        prev_block_hash: [u8; 32],
        proposed_block_hash: [u8; 32],
        retarget_block_hash: [u8; 32],
        median_block_hash: [u8; 32],
        m_deep_tx_merkle_root: [u8; 32],
        proposed_block_height: u64,
    ) -> Self {
        Self {
            prev_block_hash,
            proposed_block_hash,
            retarget_block_hash,
            median_block_hash,
            m_deep_tx_merkle_root,
            proposed_block_height,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(168);
        bytes.extend_from_slice(&self.prev_block_hash);
        bytes.extend_from_slice(&self.proposed_block_hash);
        bytes.extend_from_slice(&self.retarget_block_hash);
        bytes.extend_from_slice(&self.median_block_hash);
        bytes.extend_from_slice(&self.m_deep_tx_merkle_root);
        bytes.extend_from_slice(&self.proposed_block_height.to_le_bytes());
        bytes
    }

    pub fn compute_hash(&self) -> [u8; 32] {
        sha256_hash(&self.serialize())
    }
}

/// Note that, current proposed block is last block of `proposed_chain`, and `block_public_input` is all
/// public values of blocks which have been proved already
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ConsensusWitness {
    /// Several trusted block headers (e.g. `N`, at least 11 block headers) and proposed block headers (such as `N + m`),
    /// once a new block is proved, it will be appended after proposed_chain.
    pub proposed_chain: Vec<CircuitBlock>,
    /// Current epoch's retarget block when `proposed_block_height % 2016 != 0`,
    /// last epoch's retarget block when `proposed_block_height % 2016 == 0`
    pub retarget_block: CircuitBlock,
}

impl ConsensusWitness {
    pub fn new(proposed_chain: Vec<CircuitBlock>, retarget_block: CircuitBlock) -> Self {
        Self {
            proposed_chain,
            retarget_block,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, Copy)]
pub struct ConsensusVerifierPublicInput {
    /// SHA256 compressed of all block public inputs.
    ///
    /// In recursive proving mode, to keep public inputs small, we commit to a hash
    /// of per-block public values instead of including them directly.
    pub compressed_block_public_input: [u8; 32],
    /// Transaction merkle root of m-deep block.
    pub m_deep_tx_merkle_root: [u8; 32],
    /// Current block height.
    pub current_block_height: u64,
}

impl ConsensusVerifierPublicInput {
    pub fn new(
        compressed_block_public_input: [u8; 32],
        m_deep_tx_merkle_root: [u8; 32],
        current_block_height: u64,
    ) -> Self {
        Self {
            compressed_block_public_input,
            m_deep_tx_merkle_root,
            current_block_height,
        }
    }

    pub fn compute_hash(&self) -> [u8; 32] {
        let mut bytes = Vec::with_capacity(72);
        bytes.extend_from_slice(&self.compressed_block_public_input);
        bytes.extend_from_slice(&self.m_deep_tx_merkle_root);
        bytes.extend_from_slice(&self.current_block_height.to_le_bytes());
        sha256_hash(&bytes)
    }
}

/// Input to the consensus circuit for proving the block consensus validity.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ConsensusInput {
    /// Sequence number of the proved blocks.
    ///
    /// The initial block is trusted and starts with sequence 0.
    pub seq: u32,
    /// Hash of the circuit's verification key.
    pub circuit_vkey_u32_hash: [u32; 8],
    /// Committed public values from the previous proof.
    pub parent_proof_commitment: ConsensusVerifierPublicInput,
    /// Public values of an individual block.
    pub block_public_input: ConsensusBlockPublicInput,
    /// Witness for proving an individual block in recursive prover mode.
    pub witness: ConsensusWitness,
}

impl ConsensusInput {
    pub fn new(
        seq: u32,
        circuit_vkey_u32_hash: [u32; 8],
        parent_proof_commitment: ConsensusVerifierPublicInput,
        block_public_input: ConsensusBlockPublicInput,
        witness: ConsensusWitness,
    ) -> Self {
        Self {
            seq,
            circuit_vkey_u32_hash,
            parent_proof_commitment,
            block_public_input,
            witness,
        }
    }
}
