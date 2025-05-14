//! A program that verifies memership proofs for key-value pairs against a state root (`app_hash`)
//! from a Cosmos-based chain.
//!
//! The program takes as input:
//! - An `app_hash`: the root of the state tree
//! - A set of key-value pairs and their associated Merkle proofs
//!
//! If all proofs are valid, the program commits a public output containing
//! the `app_hash` and the verified key-value pairs.

#![no_main]
sp1_zkvm::entrypoint!(main);

use zk_light_client_core::babylon::{MembershipInput, MembershipOutput, verify_membership_proof};

fn main() {
    // Read the entire circuit input from the input stream.
    let MembershipInput {
        app_hash,
        merkle_proofs,
    } = sp1_zkvm::io::read();

    verify_membership_proof(app_hash, &merkle_proofs);

    let kv_pairs = merkle_proofs
        .into_iter()
        .map(|(kv_pair, _raw_proof)| kv_pair)
        .collect::<Vec<_>>();

    // Commit the public input.
    let output = MembershipOutput { app_hash, kv_pairs };
    sp1_zkvm::io::commit(&output);
}
