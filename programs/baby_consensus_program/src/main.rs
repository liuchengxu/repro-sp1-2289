#![no_main]
sp1_zkvm::entrypoint!(main);

use core::time::Duration;
use tendermint_light_client_verifier::options::Options;
use tendermint_light_client_verifier::types::{LightBlock, TrustThreshold};
use tendermint_light_client_verifier::{ProdVerifier, Verdict, Verifier};
use zk_light_client_core::babylon::{ConsensusInput, TendermintOutput};
use zk_light_client_core::sha256_hash;

fn verify_header(trusted_block: &LightBlock, untrusted_block: &LightBlock) {
    let vp = ProdVerifier::default();
    // TODO: double check the values below, trusting_period in particular.
    let opt = Options {
        trust_threshold: TrustThreshold::TWO_THIRDS,
        // 2 week trusting period.
        trusting_period: Duration::from_secs(14 * 24 * 60 * 60),
        clock_drift: Default::default(),
    };

    // Verify update header doesn't check this property.
    assert_eq!(
        trusted_block.next_validators.hash(),
        trusted_block.as_trusted_state().next_validators_hash
    );

    let verify_time = untrusted_block.time() + Duration::from_secs(20);
    let verdict = vp.verify_update_header(
        untrusted_block.as_untrusted_state(),
        trusted_block.as_trusted_state(),
        &opt,
        verify_time.unwrap(),
    );

    match verdict {
        Verdict::Success => {}
        v => panic!("Failed to verify light client update: {v:?}"),
    }
}

fn main() {
    // Read the entire circuit input from the zkVM's stdin.
    let raw_input = sp1_zkvm::io::read_vec();

    let ConsensusInput {
        proving_block_index,
        circuit_vkey_u32_hash,
        parent_public_input,
        current_public_input,
        witness,
    } = serde_cbor::from_slice(&raw_input).unwrap();

    // Verify proof output by the last prover.
    let current_public_input_hash = current_public_input.compute_hash();

    let compressed_block_public_input = if proving_block_index == 0 {
        sha256_hash(&current_public_input_hash)
    } else {
        // Verify STARK proof output by last STARK prover with committed public values and vkey hash.
        sp1_zkvm::lib::verify::verify_sp1_proof(
            &circuit_vkey_u32_hash,
            &parent_public_input.compute_hash(),
        );

        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&parent_public_input.compressed_block_public_input);
        bytes.extend_from_slice(&current_public_input_hash);
        sha256_hash(&bytes)
    };

    let trusted_block = witness.trusted_block;
    let untrusted_block = witness.untrusted_block;

    verify_header(&trusted_block, &untrusted_block);

    // Now that we have verified our proof, we commit the header hashes to the zkVM to expose
    // them as public values.
    let trusted_header_hash = trusted_block.signed_header.header.hash();
    let trusted_header_hash: [u8; 32] = trusted_header_hash.as_bytes().to_vec().try_into().unwrap();
    let target_header_hash = untrusted_block.signed_header.header.hash();
    let target_header_hash: [u8; 32] = target_header_hash.as_bytes().to_vec().try_into().unwrap();
    let app_hash = untrusted_block.signed_header.header.app_hash;
    let app_hash: [u8; 32] = app_hash.as_bytes().to_vec().try_into().unwrap();

    let output = TendermintOutput {
        trusted_height: trusted_block.signed_header.header.height.value(),
        target_height: untrusted_block.signed_header.header.height.value(),
        trusted_header_hash,
        target_header_hash,
        compressed_block_public_input,
        app_hash,
    };

    sp1_zkvm::io::commit(&output);
}
