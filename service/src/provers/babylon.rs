use crate::provers::{
    Groth16Proof, ProverError, aggregate_stark_proofs_to_groth16,
    generate_and_save_compressed_proof, generate_compressed_proof, load_compressed_proof,
    load_sp1_proof_and_public_values,
};
use ibc_core_commitment_types::merkle::MerkleProof;
use ibc_core_commitment_types::proto::ics23::CommitmentProof;
use ibc_proto::Protobuf;
use p3_baby_bear::BabyBear;
use prost::Message;
use sp1_recursion_core::air::RecursionPublicValues;
use sp1_sdk::{HashableKey, ProverClient, SP1Proof, SP1ProofWithPublicValues, SP1Stdin};
use std::borrow::Borrow;
use std::path::PathBuf;
use std::sync::Arc;
use tendermint::block::Height;
use tendermint::validator::Set;
use tendermint_light_client_verifier::types::{LightBlock, PeerId};
use tendermint_rpc::{Client, HttpClient, Paging};
use zk_light_client_core::babylon::{
    AggregationInput, ConsensusInput, ConsensusWitness, KVPair, MembershipInput, TendermintOutput,
    VerifierPublicInput, verify_membership_proof,
};
use zk_light_client_programs::{
    BABY_AGGREGATION_PROGRAM_ELF, BABY_CONSENSUS_PROGRAM_ELF, BABY_MEMBERSHIP_PROGRAM_ELF,
};

/// Prover for generating consensus proof for Babylon blocks.
#[derive(Clone)]
pub struct ConsensusProver {
    initial_height: u64,
    consensus_proof_path: PathBuf,
    client: Arc<HttpClient>,
}

impl ConsensusProver {
    /// Constructs a new instance of [`ConsensusProver`].
    pub fn new(
        initial_height: u64,
        consensus_proof_path: PathBuf,
        client: Arc<HttpClient>,
    ) -> Self {
        Self {
            initial_height,
            consensus_proof_path,
            client,
        }
    }

    /// Proves the consensus for the block at `block_height`.
    pub async fn prove(&mut self, block_height: u64) -> Result<u64, ProverError> {
        if block_height < 2 {
            return Err(ProverError::BlockHeightTooLowForTendermint);
        }

        let target_block = self.fetch_light_block(block_height).await?;
        let trusted_block = self.fetch_light_block(block_height - 1).await?;
        self.prove_from_blocks(target_block, trusted_block)
    }

    async fn fetch_light_block(&self, block_height: u64) -> Result<LightBlock, ProverError> {
        let height = Height::from(block_height as u32);
        let signed_header = self.client.commit(height).await?.signed_header;
        let validators = self
            .client
            .validators(height, Paging::All)
            .await?
            .validators;
        let next_validators = self
            .client
            .validators(Height::from(block_height as u32 + 1), Paging::All)
            .await?
            .validators;
        Ok(LightBlock {
            signed_header,
            validators: Set::new(validators, None),
            next_validators: Set::new(next_validators, None),
            // Dummy peer id is fine here, update to proper value when it's not.
            provider: PeerId::new([0u8; 20]),
        })
    }

    /// Proves consensus from given blocks.
    fn prove_from_blocks(
        &mut self,
        target_block: LightBlock,
        trusted_block: LightBlock,
    ) -> Result<u64, ProverError> {
        let client = ProverClient::from_env();
        let (pkey, vkey) = client.setup(BABY_CONSENSUS_PROGRAM_ELF);

        let target_height = target_block.height().value();

        // TODO: currently the blocks are proved one by one, we should prove them on epoch basis.
        let proving_block_index = target_height - self.initial_height - 1;

        let (parent_public_input, maybe_parent_proof) = if proving_block_index == 0 {
            // The first block to be proven does not have a parent proof.
            (TendermintOutput::default(), None)
        } else {
            // TODO: calculate the height of last proven block correctly after upgrading to epoch
            // basis or should we store the metadata on disk?
            let (parent_proof, public_input) =
                load_compressed_proof(self.proof_file_path(target_height - 1))?;
            (public_input, Some(parent_proof))
        };

        let target_header = &target_block.signed_header.header;

        let app_hash: [u8; 32] = target_header
            .app_hash
            .as_bytes()
            .try_into()
            .map_err(|_| ProverError::InvalidTendermintBlockHash(target_header.hash()))?;

        let target_header_hash: [u8; 32] = target_header
            .hash()
            .as_bytes()
            .try_into()
            .map_err(|_| ProverError::InvalidTendermintBlockHash(target_header.hash()))?;

        let parent_compressed_block_public_input =
            parent_public_input.compressed_block_public_input;

        let circuit_input = ConsensusInput {
            proving_block_index,
            circuit_vkey_u32_hash: vkey.hash_u32(),
            parent_public_input,
            current_public_input: VerifierPublicInput {
                parent_compressed_block_public_input,
                app_hash,
                target_height,
                target_header_hash,
            },
            witness: ConsensusWitness {
                trusted_block,
                untrusted_block: target_block,
            },
        };

        let mut stdin = SP1Stdin::new();
        stdin.write_vec(serde_cbor::to_vec(&circuit_input)?);

        if let Some(proof) = maybe_parent_proof {
            stdin.write_proof(*proof, vkey.vk);
        }

        let proof_generation_time = generate_and_save_compressed_proof(
            &client,
            &pkey,
            &stdin,
            self.proof_file_path(target_height),
        )?;

        Ok(proof_generation_time)
    }

    #[inline]
    fn proof_file_path(&self, block_height: u64) -> PathBuf {
        self.consensus_proof_path
            .join(format!("{block_height}.bin"))
    }
}

/// Prover responsible for generating a bare membership proof.
#[derive(Clone)]
struct BareMembershipProver {
    client: Arc<HttpClient>,
}

impl BareMembershipProver {
    fn new(client: Arc<HttpClient>) -> Self {
        Self { client }
    }

    async fn prove(
        &self,
        key_paths: Vec<Vec<Vec<u8>>>,
        block_height: u64,
    ) -> Result<SP1ProofWithPublicValues, ProverError> {
        let membership_input = self
            .prepare_membership_input(key_paths, block_height)
            .await?;
        let client = ProverClient::from_env();
        let (pkey, _) = client.setup(BABY_MEMBERSHIP_PROGRAM_ELF);
        let mut stdin = SP1Stdin::new();
        stdin.write(&membership_input);
        generate_compressed_proof(&client, &pkey, &stdin)
    }

    /// Fetch the membership proofs.
    async fn prepare_membership_input(
        &self,
        key_paths: Vec<Vec<Vec<u8>>>,
        block_height: u64,
    ) -> Result<MembershipInput, ProverError> {
        let merkle_proofs = futures::future::try_join_all(key_paths.into_iter().map(|key_path| {
            let client = self.client.clone();

            async move {
                let (value, proof) =
                    prove_storage_key_existence(&client, &key_path, block_height).await?;

                let kv_pair = KVPair {
                    keys: key_path,
                    value,
                };

                Ok::<_, ProverError>((kv_pair, proof.encode_vec()))
            }
        }))
        .await?;

        let app_hash = self
            .client
            .block(block_height as u32)
            .await?
            .block
            .header
            .app_hash;

        let app_hash: [u8; 32] = Vec::<u8>::from(app_hash)
            .try_into()
            .map_err(|_| ProverError::Other("Invalid app_hash length".to_string()))?;

        // sanity check.
        verify_membership_proof(app_hash, &merkle_proofs);

        Ok(MembershipInput {
            app_hash,
            merkle_proofs,
        })
    }
}

async fn prove_storage_key_existence(
    client: &Arc<HttpClient>,
    key_path: &[Vec<u8>],
    height: u64,
) -> Result<(Vec<u8>, MerkleProof), ProverError> {
    let store_name = std::str::from_utf8(&key_path[0])
        .map_err(|_| ProverError::Other("Invalid UTF-8 in store name".to_string()))?;
    let key = key_path[1..].concat();

    // The `app_hash` in Cosmos chain block H reflects the state after applying all transactions in
    // block H-1. So to prove inclusion against the `app_hash` in block H, we must query state at
    // height H-1.
    let query_height = Height::from(height as u32 - 1);

    let res = client
        .abci_query(
            Some(format!("store/{store_name}/key")),
            key.clone(),
            Some(query_height),
            true,
        )
        .await?;

    if res.height.value() != query_height.value() {
        if res.height.value() == 0 {
            tracing::debug!("Queried key may not exist or the state has been pruned");
        }

        return Err(ProverError::TendermintProofHeightMismatch {
            got: res.height.value(),
            expected: query_height.value(),
        });
    }

    if res.key != key {
        return Err(ProverError::TendermintProofKeyMismatch);
    }

    if res.value.is_empty() {
        return Err(ProverError::Other(
            "Queried key returned empty value: expected non-empty for membership existence proof"
                .to_string(),
        ));
    }

    let tendermint_proof = res
        .proof
        .ok_or_else(|| ProverError::Other("Missing proof in ABCI response".to_string()))?;

    // Convert tendermint proof to ics merkle proof.
    let ics_merkle_proof = MerkleProof {
        proofs: tendermint_proof
            .ops
            .into_iter()
            .map(|op| CommitmentProof::decode(op.data.as_slice()))
            .collect::<Result<_, _>>()?,
    };

    Ok((res.value, ics_merkle_proof))
}

#[derive(Debug)]
pub struct MembershipProof {
    pub groth16: Groth16Proof,
    /// Aggregation proof generation time in seconds.
    pub proving_time_secs: u64,
}

/// Final prover that aggregates the consensus proof and the bare membership proof into a Groth16
/// proof.
pub struct MembershipProver {
    bare_membership_prover: BareMembershipProver,
    consensus_proof_path: PathBuf,
}

impl MembershipProver {
    pub fn new(client: Arc<HttpClient>, consensus_proof_path: PathBuf) -> Self {
        Self {
            bare_membership_prover: BareMembershipProver::new(client),
            consensus_proof_path,
        }
    }

    /// Generates an aggregated Groth16 proof for a set of storage keys at the given block height.
    pub async fn prove(
        &self,
        key_paths: Vec<Vec<Vec<u8>>>,
        block_height: u64,
    ) -> Result<MembershipProof, ProverError> {
        let consensus_proof_file_path = self
            .consensus_proof_path
            .join(format!("{block_height}.bin"));

        // Load the consensus proof from disk.
        let consensus_proof = load_sp1_proof_and_public_values(consensus_proof_file_path)?;

        // Generate the bare membership proof.
        let bare_membership_proof = self
            .bare_membership_prover
            .prove(key_paths, block_height)
            .await?;

        let SP1Proof::Compressed(compressed_bare_membership_proof) = bare_membership_proof.proof
        else {
            return Err(ProverError::BadProofType);
        };

        let SP1Proof::Compressed(compressed_consensus_proof) = consensus_proof.proof else {
            return Err(ProverError::BadProofType);
        };

        // Aggregate both proofs into a Groth16 proof.
        let (groth16_proof, proving_time_secs) = {
            let client = ProverClient::from_env();

            let (_, consensus_vkey) = client.setup(BABY_CONSENSUS_PROGRAM_ELF);
            let (_, membership_vkey) = client.setup(BABY_MEMBERSHIP_PROGRAM_ELF);

            let aggregation_input = AggregationInput {
                consensus_vkey_u32_hash: consensus_vkey.vk.hash_u32(),
                consensus_public_input: consensus_proof.public_values.to_vec(),
                membership_vkey_u32_hash: membership_vkey.vk.hash_u32(),
                membership_public_input: bare_membership_proof.public_values.to_vec(),
            };

            // Sanity check: verify that consensus proof vk hash matches expected vk.
            let public_values_to_validate: &RecursionPublicValues<BabyBear> =
                compressed_consensus_proof
                    .proof
                    .public_values
                    .as_slice()
                    .borrow();
            let vk_digest_in_public_values = public_values_to_validate.sp1_vk_digest;
            let consensus_vk_hash = consensus_vkey.vk.hash_babybear();
            // https://github.com/succinctlabs/sp1/blob/7889ae8ba292f916ef1b0dd74735472f19167c80/crates/prover/src/verify.rs#L327
            if vk_digest_in_public_values != consensus_vk_hash {
                tracing::error!(
                    ?vk_digest_in_public_values,
                    ?consensus_vk_hash,
                    "sp1 vk hash mismatch"
                );
                return Err(ProverError::Sp1VkeyHashMismatch);
            }

            aggregate_stark_proofs_to_groth16(
                vec![
                    (*compressed_consensus_proof, consensus_vkey),
                    (*compressed_bare_membership_proof, membership_vkey),
                ],
                aggregation_input,
                BABY_AGGREGATION_PROGRAM_ELF,
            )?
        };

        Ok(MembershipProof {
            groth16: groth16_proof,
            proving_time_secs,
        })
    }
}
