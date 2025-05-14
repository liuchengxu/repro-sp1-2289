//! This module provides the primitives used in the babylon programs.

use crate::sha256_hash;
use bincode::{Decode, Encode};
use ibc_core_commitment_types::commitment::CommitmentRoot;
use ibc_core_commitment_types::merkle::{MerklePath, MerkleProof};
use ibc_core_commitment_types::proto::ics23::HostFunctionsManager;
use ibc_core_commitment_types::specs::ProofSpecs;
use ibc_core_host_types::path::PathBytes;
use ibc_proto::Protobuf;
use serde::{Deserialize, Serialize};
use tendermint_light_client_verifier::types::LightBlock;

/// Output data committed by the Tendermint light client proof.
// TODO: remove unused fields.
#[derive(Encode, Decode, Serialize, Deserialize, Clone, Default, Debug)]
pub struct TendermintOutput {
    /// Height of the last trusted block, used as the root of trust for verification.
    pub trusted_height: u64,
    /// Height of the block whose validity was proven by this proof.
    pub target_height: u64,
    /// Hash of the trusted block at `trusted_height`.
    pub trusted_header_hash: [u8; 32],
    /// Hash of the header at `target_height`, which has been successfully verified.
    pub target_header_hash: [u8; 32],
    /// A commitment to the recursive proof used to verify the target header.
    pub compressed_block_public_input: [u8; 32],
    /// Application state root in the verified header.
    pub app_hash: [u8; 32],
}

impl TendermintOutput {
    const BYTE_SIZE: usize = 8 + 8 + 32 + 32 + 32 + 32;

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::BYTE_SIZE);
        out.extend_from_slice(&self.trusted_height.to_le_bytes());
        out.extend_from_slice(&self.target_height.to_le_bytes());
        out.extend_from_slice(&self.trusted_header_hash);
        out.extend_from_slice(&self.target_header_hash);
        out.extend_from_slice(&self.compressed_block_public_input);
        out.extend_from_slice(&self.app_hash);
        out
    }

    #[allow(dead_code)]
    pub fn decode(data: &[u8]) -> std::io::Result<Self> {
        if data.len() != Self::BYTE_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid data length for TendermintOutput",
            ));
        }

        let trusted_height = u64::from_le_bytes(data[0..8].try_into().unwrap());
        let target_height = u64::from_le_bytes(data[8..16].try_into().unwrap());
        let trusted_header_hash = data[16..48].try_into().unwrap();
        let target_header_hash = data[48..80].try_into().unwrap();
        let compressed_block_public_input = data[80..112].try_into().unwrap();
        let app_hash = data[112..144].try_into().unwrap();

        Ok(Self {
            trusted_height,
            target_height,
            trusted_header_hash,
            target_header_hash,
            compressed_block_public_input,
            app_hash,
        })
    }

    pub fn compute_hash(&self) -> [u8; 32] {
        sha256_hash(&self.encode())
    }
}

/// Public input known to the verifier.
#[derive(Encode, Decode, Serialize, Deserialize, Clone, Debug)]
pub struct VerifierPublicInput {
    /// Compressed public input committed by the last prover.
    // TODO: should parent_compressed_block_public_input be included? If true, should we check it against
    // the value of `parent_public_input.compressed_block_public_input` within the program?
    pub parent_compressed_block_public_input: [u8; 32],
    /// Application state root in the verified header.
    pub app_hash: [u8; 32],
    /// Height of the block being proven.
    pub target_height: u64,
    /// Hash of the header at `target_height`.
    pub target_header_hash: [u8; 32],
}

impl VerifierPublicInput {
    const BYTE_SIZE: usize = 32 + 8 + 32;

    pub fn compute_hash(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(Self::BYTE_SIZE);
        buf.extend(self.parent_compressed_block_public_input);
        buf.extend(self.app_hash);
        buf.extend(self.target_height.to_le_bytes());
        buf.extend(self.target_header_hash);
        sha256_hash(&buf)
    }
}

/// Private input to the circuit for verifying the Tendermint light client.
///
/// This input links the a previously trusted block to a new target
/// block to be proven.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ConsensusWitness {
    /// The last trusted (already proven) light block.
    pub trusted_block: LightBlock,
    /// The new light block that is being proven.
    pub untrusted_block: LightBlock,
}

impl ConsensusWitness {
    pub fn compute_hash(&self) -> [u8; 32] {
        let mut buf = Vec::new();

        let trusted_block_hash = self.trusted_block.signed_header.header.hash();
        assert_eq!(trusted_block_hash.as_bytes().len() as u32, 32);
        buf.extend(trusted_block_hash.as_bytes());

        let untrusted_block_hash = self.untrusted_block.signed_header.header.hash();
        assert_eq!(untrusted_block_hash.as_bytes().len() as u32, 32);
        buf.extend(untrusted_block_hash.as_bytes());

        sha256_hash(&buf)
    }
}

/// Complete circuit input for the Babylon consensus program.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ConsensusInput {
    /// This index represents the position in the recursive proof sequence,
    /// starting from 0 for the first proven block. Each subsequent proven block
    /// increases the index by 1.
    pub proving_block_index: u64,
    /// Hash of this circuit's verification key.
    pub circuit_vkey_u32_hash: [u32; 8],
    /// Public values committed from the parent proof.
    ///
    /// The parent proof corresponds to the previous block in the sequence.
    /// Note: proofs are generated on an epoch basis if no Burn transactions occurred,
    /// intermediate blocks without Burn events will be skipped.
    pub parent_public_input: TendermintOutput,
    /// Public input for the current proof.
    pub current_public_input: VerifierPublicInput,
    /// Private input for proving the current block.
    pub witness: ConsensusWitness,
}

/// Represents a key-value pair in the state of a Cosmos chain.
#[derive(Encode, Decode, Serialize, Deserialize, Clone, Debug)]
pub struct KVPair {
    pub keys: Vec<Vec<u8>>,
    pub value: Vec<u8>,
}

impl KVPair {
    pub fn into_merkle_path_and_value(self) -> (MerklePath, Vec<u8>) {
        let Self { keys, value } = self;
        (
            MerklePath::new(keys.into_iter().map(PathBytes::from_bytes).collect()),
            value,
        )
    }
}

pub type RawMerkleProof = Vec<u8>;

/// Verifies whether the merkle proofs are valid against the given `app_hash`.
pub fn verify_membership_proof(app_hash: [u8; 32], proofs: &[(KVPair, RawMerkleProof)]) {
    let commitment_root = CommitmentRoot::from_bytes(&app_hash);

    for (kv_pair, raw_merkle_proof) in proofs {
        let (merkle_path, value) = kv_pair.clone().into_merkle_path_and_value();
        let merkle_proof =
            MerkleProof::decode_vec(raw_merkle_proof).expect("Failed to decode Merkle proof");
        merkle_proof
            .verify_membership::<HostFunctionsManager>(
                &ProofSpecs::cosmos(),
                commitment_root.clone().into(),
                merkle_path,
                value,
                0,
            )
            .expect("Failed to verify membership");
    }
}

/// The input to the membership program.
///
/// `app_hash` is the Merkle root of the application state.
/// Each proof is a tuple of a key-value pair and its corresponding raw Merkle proof.
#[derive(Encode, Decode, Serialize, Deserialize, Debug)]
pub struct MembershipInput {
    pub app_hash: [u8; 32],
    pub merkle_proofs: Vec<(KVPair, RawMerkleProof)>,
}

/// The public input committed by the zkVM.
///
/// It contains the verified `app_hash` and the corresponding key-value pairs.
#[derive(Encode, Decode, Serialize, Deserialize, Debug)]
pub struct MembershipOutput {
    pub app_hash: [u8; 32],
    pub kv_pairs: Vec<KVPair>,
}

impl MembershipOutput {
    pub fn compute_hash(&self) -> [u8; 32] {
        let mut buf = Vec::new();
        buf.extend(self.app_hash);
        self.kv_pairs.iter().for_each(|KVPair { keys, value }| {
            buf.extend(keys.iter().flatten());
            buf.extend(value);
        });
        sha256_hash(&buf)
    }

    pub fn encode(&self) -> Vec<u8> {
        bincode::encode_to_vec(self, bincode::config::standard()).unwrap()
    }
}

/// The input to the aggregation program.
#[derive(Serialize, Deserialize, Debug)]
pub struct AggregationInput {
    /// Verification key used for the consensus proof.
    pub consensus_vkey_u32_hash: [u32; 8],
    /// Encoded [`TendermintOutput`] committed from the consensus proof.
    pub consensus_public_input: Vec<u8>,
    /// Verification key used for the membership proof.
    pub membership_vkey_u32_hash: [u32; 8],
    /// Encoded [`MembershipOutput`] committed from the consensus proof.
    pub membership_public_input: Vec<u8>,
}
