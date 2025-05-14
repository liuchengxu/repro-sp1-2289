//! Aggregation Program for Babylon Genesis Verification
//!
//! This zkVM program aggregates two SP1 proofs:
//! 1. A **consensus validity proof**, verifying that a given block header is valid.
//! 2. A **membership proof**, showing that a set of key-value pairs exists under the application state (`app_hash`) of that header.
//!
//! Together, these two proofs establish that some state was indeed committed in a valid Babylon Genesis block.

#![no_main]
sp1_zkvm::entrypoint!(main);

use zk_light_client_core::babylon::{AggregationInput, MembershipOutput, TendermintOutput};
use zk_light_client_core::sha256_hash;

pub fn main() {
    let AggregationInput {
        consensus_vkey_u32_hash,
        membership_vkey_u32_hash,
        consensus_public_input,
        membership_public_input,
    } = sp1_zkvm::io::read::<AggregationInput>();

    sp1_zkvm::lib::verify::verify_sp1_proof(
        &consensus_vkey_u32_hash,
        &sha256_hash(&consensus_public_input),
    );

    sp1_zkvm::lib::verify::verify_sp1_proof(
        &membership_vkey_u32_hash,
        &sha256_hash(&membership_public_input),
    );

    // Once sp1 upgrades their bincode dep to bincode 2.0, we should use
    // `bincode::config::standard()` instead.
    let (consensus_public_input, _): (TendermintOutput, _) =
        bincode::decode_from_slice(&consensus_public_input, bincode::config::legacy())
            .expect("failed to decode consensus public input");

    let (membership_public_input, _): (MembershipOutput, _) =
        bincode::decode_from_slice(&membership_public_input, bincode::config::legacy())
            .expect("failed to decode membership public input");

    // Check that the app_hash in the membership proof matches the one in the consensus block header.
    assert_eq!(
        consensus_public_input.app_hash,
        membership_public_input.app_hash
    );

    // TODO: Decide what to commit as public output:
    // - Likely candidates: the header hash, state root, key(s), value(s).
}
