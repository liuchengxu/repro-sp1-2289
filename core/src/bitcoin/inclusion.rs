//! This module defines the primitives used in the inclusion program.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Default, Serialize, Deserialize, Clone, Copy, Debug)]
pub struct MerkleProofStep {
    pub hash: [u8; 32],
    pub direction: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct InclusionPublicInput {
    pub tx_merkle_root: [u8; 32],
    pub tx_id: [u8; 32],
}

impl InclusionPublicInput {
    pub fn compute_hash(&self) -> [u8; 32] {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&self.tx_merkle_root);
        bytes.extend_from_slice(&self.tx_id);
        Sha256::digest(bytes).into()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct InclusionWitness {
    /// Serialized Bitcoin transaction using the legacy format (only input and output, no witness).
    pub legacy_tx: Vec<u8>,
    pub tx_merkle_proof: Vec<MerkleProofStep>,
    // TODO: extract pubkey and txid from `legacy_tx`, which already contains these data.
    pub operator_pubkey: Vec<u8>,
    pub pegin_txid: [u8; 32],
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct InclusionInput {
    pub public_input: InclusionPublicInput,
    pub witness: InclusionWitness,
}

impl InclusionInput {
    pub fn new(
        legacy_tx: Vec<u8>,
        tx_merkle_proof: Vec<MerkleProofStep>,
        tx_id: [u8; 32],
        tx_merkle_root: [u8; 32],
    ) -> Self {
        Self {
            public_input: InclusionPublicInput {
                tx_id,
                tx_merkle_root,
            },
            witness: InclusionWitness {
                legacy_tx,
                tx_merkle_proof,
                // TODO: proper value
                operator_pubkey: Vec::from([0u8; 33]),
                pegin_txid: [0u8; 32],
            },
        }
    }
}
