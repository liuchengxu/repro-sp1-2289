pub use baby_aggregation_program_script::BABY_AGGREGATION_PROGRAM_ELF;
pub use baby_consensus_program_script::BABY_CONSENSUS_PROGRAM_ELF;
pub use baby_membership_program_script::BABY_MEMBERSHIP_PROGRAM_ELF;
use bitcoin::Transaction;
use bitcoin::consensus::encode::Encodable;
use bitcoin::hashes::Hash;
use bitcoin::hashes::hex::FromHex;
use zk_light_client_core::bitcoin::block::CircuitBlock;
use zk_light_client_core::bitcoin::hash_pairs;
use zk_light_client_core::bitcoin::inclusion::MerkleProofStep;

pub fn load_hex_bytes(file: &str) -> Vec<u8> {
    let hex_string = std::fs::read_to_string(file).expect("Failed to read file");
    Vec::<u8>::from_hex(&hex_string).expect("Failed to parse hex")
}

/// Serializes a Bitcoin transaction using the legacy pre-SegWit format.
///
/// This excludes any witness data. If the transaction includes witnesses,
/// they will be silently ignored unless explicitly checked.
///
/// # Panics
///
/// This function panics if encoding any field fails.
pub fn serialize_legacy_tx(tx: &Transaction) -> Vec<u8> {
    let mut buffer = Vec::new();
    tx.version
        .consensus_encode(&mut buffer)
        .expect("Encoding version failed");
    tx.input
        .consensus_encode(&mut buffer)
        .expect("Encoding inputs failed");
    tx.output
        .consensus_encode(&mut buffer)
        .expect("Encoding outputs failed");
    tx.lock_time
        .consensus_encode(&mut buffer)
        .expect("Encoding lock_time failed");
    buffer
}

/// Converts a [`bitcoin::block::Header`] into a [`CircuitBlock`].
pub fn to_circuit_block(header: &bitcoin::block::Header, height: u64) -> CircuitBlock {
    CircuitBlock {
        height,
        version: header.version.to_consensus().to_le_bytes(),
        prev_blockhash: header.prev_blockhash.to_raw_hash().to_byte_array(),
        merkle_root: header.merkle_root.to_raw_hash().to_byte_array(),
        time: header.time.to_le_bytes(),
        bits: header.bits.to_consensus().to_le_bytes(),
        nonce: header.nonce.to_le_bytes(),
    }
}

// Expects leaves to be in little-endian format (as shown on explorers)
pub fn generate_merkle_proof_and_root(
    leaves: Vec<[u8; 32]>,
    desired_leaf: [u8; 32],
) -> (Vec<MerkleProofStep>, [u8; 32]) {
    let mut current_level = leaves;
    let mut proof: Vec<MerkleProofStep> = Vec::new();
    let mut desired_index = current_level
        .iter()
        .position(|&leaf| leaf == desired_leaf)
        .expect("Desired leaf not found in the list of leaves");

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

            if i == desired_index || i + 1 == desired_index {
                let proof_step = if i == desired_index {
                    MerkleProofStep {
                        hash: right,
                        direction: true,
                    }
                } else {
                    MerkleProofStep {
                        hash: left,
                        direction: false,
                    }
                };
                proof.push(proof_step);
                desired_index /= 2;
            }

            i += 2;
        }

        current_level = next_level;
    }

    let merkle_root = current_level[0];
    (proof, merkle_root)
}
