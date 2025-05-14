mod babylon;

pub use self::babylon::{
    ConsensusProver as BabyConsensusProver, MembershipProver as BabyMembershipProver,
};
use ark_bn254::{Bn254, G1Affine, G2Affine};
use ark_groth16::r1cs_to_qap::LibsnarkReduction;
use ark_groth16::{Groth16, Proof};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use serde::Serialize;
use serde::de::DeserializeOwned;
use sp1_core_executor::SP1ReduceProof;
use sp1_sdk::{
    EnvProver, HashableKey, ProverClient, SP1Proof, SP1ProofWithPublicValues, SP1ProvingKey,
    SP1Stdin, SP1VerifyingKey,
};
use sp1_stark::baby_bear_poseidon2::BabyBearPoseidon2;
use sp1_verifier::{
    ArkGroth16Error, decode_sp1_vkey_hash, hash_public_inputs,
    load_ark_groth16_verifying_key_from_bytes, load_ark_proof_from_bytes,
    load_ark_public_inputs_from_bytes,
};
use std::path::Path;

type CompressedProof = Box<sp1_core_executor::SP1ReduceProof<sp1_prover::InnerSC>>;

#[derive(Debug, thiserror::Error)]
pub enum ProverError {
    #[error("Failed to load proof: {0}")]
    LoadProof(String),
    #[error("Expected compressed proof")]
    BadProofType,
    #[error("Failed to save proof: {0:?}")]
    SaveProof(anyhow::Error),
    #[error("Failed to generate proof: {0:?}")]
    GenerateProof(anyhow::Error),
    #[error("Witness chain is empty")]
    EmptyWitnessChain,
    #[error("Tendermint block hash is invalid: {0}")]
    InvalidTendermintBlockHash(tendermint::Hash),
    #[error("Block height too low: the first provable Tendermint block is height 2")]
    BlockHeightTooLowForTendermint,
    #[error("Failed to verify groth16 proof: {0}")]
    VerifyGroth16Proof(String),
    #[error("Proof height mismatch, got: {got}, expected: {expected}")]
    TendermintProofHeightMismatch { got: u64, expected: u64 },
    #[error("Proof key mismatch")]
    TendermintProofKeyMismatch,
    #[error("proof vk hash mismatches the one embedded in public values")]
    Sp1VkeyHashMismatch,
    #[error("other: {0}")]
    Other(String),
    #[error(transparent)]
    IO(#[from] std::io::Error),
    #[error(transparent)]
    ArkGroth16(#[from] sp1_verifier::ArkGroth16Error),
    #[error(transparent)]
    ArkSerialize(#[from] ark_serialize::SerializationError),
    #[error(transparent)]
    SerdeCbor(#[from] serde_cbor::Error),
    #[error(transparent)]
    Tendermint(#[from] tendermint::Error),
    #[error(transparent)]
    TendermintRpc(#[from] tendermint_rpc::Error),
    #[error(transparent)]
    Prost(#[from] prost::DecodeError),
}

/// Generates a proof in the Compressed mode.
fn generate_compressed_proof(
    prover: &EnvProver,
    pkey: &SP1ProvingKey,
    stdin: &SP1Stdin,
) -> Result<SP1ProofWithPublicValues, ProverError> {
    prover
        .prove(pkey, stdin)
        .compressed()
        .run()
        .map_err(ProverError::GenerateProof)
}

fn generate_and_save_compressed_proof(
    prover: &EnvProver,
    pkey: &SP1ProvingKey,
    stdin: &SP1Stdin,
    output_file_path: impl AsRef<Path>,
) -> Result<u64, ProverError> {
    let now = std::time::Instant::now();
    let proof = generate_compressed_proof(prover, pkey, stdin)?;
    let proof_generation_time = now.elapsed().as_secs();

    proof.save(output_file_path.as_ref()).map_err(|err| {
        ProverError::SaveProof(anyhow::anyhow!(
            "Failed to save proof at {}: {err:?}",
            output_file_path.as_ref().display()
        ))
    })?;

    Ok(proof_generation_time)
}

/// Loads a sp1 proof and its associated public values from disk.
fn load_sp1_proof_and_public_values(
    proof_file_path: impl AsRef<Path>,
) -> Result<SP1ProofWithPublicValues, ProverError> {
    let proof_file_path = proof_file_path.as_ref();

    // Manually check if the proof file exists, because `SP1ProofWithPublicValues::load`
    // does not handle "file not found" properly.
    if !std::fs::exists(proof_file_path)? {
        return Err(std::io::Error::other(format!(
            "Consensus proof file {} not found",
            proof_file_path.display()
        ))
        .into());
    }

    SP1ProofWithPublicValues::load(proof_file_path).map_err(|err| {
        ProverError::LoadProof(format!(
            "Consensus proof file {} not found: {err:?}",
            proof_file_path.display()
        ))
    })
}

/// Loads a compressed proof and typed public values from disk.
fn load_compressed_proof<PV: Serialize + DeserializeOwned>(
    proof_file_path: impl AsRef<Path>,
) -> Result<(CompressedProof, PV), ProverError> {
    let mut proof_with_public_values = load_sp1_proof_and_public_values(proof_file_path)?;

    let SP1Proof::Compressed(proof) = proof_with_public_values.proof else {
        return Err(ProverError::BadProofType);
    };

    let public_values = proof_with_public_values.public_values.read::<PV>();

    Ok((proof, public_values))
}

fn aggregate_stark_proofs_to_groth16<T: serde::Serialize>(
    stark_proofs: Vec<(SP1ReduceProof<BabyBearPoseidon2>, SP1VerifyingKey)>,
    aggregation_circuit_input: T,
    aggregation_elf: &[u8],
) -> Result<(Groth16Proof, u64), ProverError> {
    let mut stdin = SP1Stdin::new();

    stdin.write(&aggregation_circuit_input);

    for (stark_proof, vkey) in stark_proofs {
        stdin.write_proof(stark_proof, vkey.vk);
    }

    let client = ProverClient::from_env();

    let (aggregation_pkey, aggregation_vkey) = client.setup(aggregation_elf);

    let now = std::time::Instant::now();

    let aggregation_proof = client
        .prove(&aggregation_pkey, &stdin)
        .groth16() // Must use groth16() as this is the only algo supported in BitVM.
        .run()
        .map_err(ProverError::GenerateProof)?;

    let groth16_proof = Groth16Proof {
        proof: to_arkworks_groth16_proof_bytes(&aggregation_proof)?,
        public_values: aggregation_proof.public_values.to_vec(),
        vkey: aggregation_vkey.bytes32(),
    };

    let proving_time_secs = now.elapsed().as_secs();

    Ok((groth16_proof, proving_time_secs))
}

/// Converts the gnark_groth16 to arkworks format.
fn to_arkworks_groth16_proof_bytes(
    gnark_groth16: &SP1ProofWithPublicValues,
) -> Result<Vec<u8>, ProverError> {
    let ark_proof = load_ark_proof_from_bytes(&gnark_groth16.bytes()[4..])?;

    let mut proof = vec![0u8; 256];
    ark_proof
        .a
        .serialize_with_mode(&mut proof[..64], Compress::No)?;
    ark_proof
        .b
        .serialize_with_mode(&mut proof[64..192], Compress::No)?;
    ark_proof
        .c
        .serialize_with_mode(&mut proof[192..256], Compress::No)?;

    Ok(proof)
}

/// Represents a Groth16 proof structure compatible with BitVM verification.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Groth16Proof {
    /// gnark versioned groth16 proof bytes
    pub proof: Vec<u8>,
    /// public input bytes of aggregation circuit
    pub public_values: Vec<u8>,
    /// vkey hash of aggregation circuit
    pub vkey: String,
}

impl Groth16Proof {
    pub fn verify(&self) -> Result<bool, ProverError> {
        let Self {
            proof: proof_bytes,
            public_values: public_input_bytes,
            vkey: vkey_hash,
        } = self;

        // arkworks verifier
        let vkey = load_ark_groth16_verifying_key_from_bytes(&sp1_verifier::GROTH16_VK_BYTES)?;

        let proof = {
            let a = G1Affine::deserialize_with_mode(
                &*[&proof_bytes[..64], &[0u8][..]].concat(),
                Compress::No,
                Validate::Yes,
            )
            .map_err(|_| ArkGroth16Error::G1CompressionError)?;
            let b = G2Affine::deserialize_with_mode(
                &*[&proof_bytes[64..192], &[0u8][..]].concat(),
                Compress::No,
                Validate::Yes,
            )
            .map_err(|_| ArkGroth16Error::G2CompressionError)?;
            let c = G1Affine::deserialize_with_mode(
                &*[&proof_bytes[192..256], &[0u8][..]].concat(),
                Compress::No,
                Validate::Yes,
            )
            .map_err(|_| ArkGroth16Error::G1CompressionError)?;
            Proof::<Bn254> { a, b, c }
        };

        let public_inputs = load_ark_public_inputs_from_bytes(
            &decode_sp1_vkey_hash(vkey_hash.as_str()).unwrap(),
            &hash_public_inputs(public_input_bytes),
        );

        Groth16::<Bn254, LibsnarkReduction>::verify_proof(&vkey.into(), &proof, &public_inputs)
            .map_err(|e| ProverError::VerifyGroth16Proof(e.to_string()))
    }
}
