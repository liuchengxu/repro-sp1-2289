## To reproduce https://github.com/succinctlabs/sp1/issues/2289

```bash
rm -rf tmp && RUSTFLAGS="-C target-cpu=native" cargo run --release --bin zk-prover-service -- --base-path=tmp --log=prover=debug,zk_prover_service=debug bench babylon
2025-05-14T01:25:38.947510Z  INFO zk_prover_service: Set env variable SP1_PROVER to cpu
2025-05-14T01:30:19.599167Z  WARN prove_core: sp1_core_executor::executor: Not all proofs were read. Proving will fail during recursion. Did you pass too
        many proofs in or forget to call verify_sp1_proof?
2025-05-14T01:34:14.134414Z  WARN prove_core: sp1_core_executor::executor: Not all proofs were read. Proving will fail during recursion. Did you pass too
        many proofs in or forget to call verify_sp1_proof?

=== Babylon Consensus Proof Time Results ===
Total blocks processed: 3
Lowest time:  block 2 => 206s
Highest time: block 4 => 226s
Average time (excluding min/max): 226.00s
[sp1] groth16 circuit artifacts already seem to exist at /Users/xuliucheng/.sp1/circuits/groth16/v4.0.0-rc.3. if you want to re-download them, delete the directory
2025-05-14T01:41:02.545355Z  INFO wrap_groth16_bn254: sp1_recursion_gnark_ffi::ffi::docker: Running prove in docker
2025-05-14T01:41:47.439388Z  INFO wrap_groth16_bn254: sp1_recursion_gnark_ffi::ffi::docker: Running verify in docker
Proving time: 252s
```
