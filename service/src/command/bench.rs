use crate::Args;
use crate::provers::{BabyConsensusProver, BabyMembershipProver};
use clap::Parser;
use std::sync::Arc;
use tendermint_rpc::{Client, HttpClient};

#[derive(Debug)]
struct ProofInfo {
    block_height: u64,
    proving_time_secs: u64,
}

struct ProvingStats {
    stats: Vec<ProofInfo>,
}

impl ProvingStats {
    fn new(capacity: usize) -> Self {
        Self {
            stats: Vec::with_capacity(capacity),
        }
    }

    fn push(&mut self, block_height: u64, proving_time_secs: u64) {
        self.stats.push(ProofInfo {
            block_height,
            proving_time_secs,
        });
    }

    fn print_summary(&mut self, label: &str) {
        if self.stats.len() < 3 {
            println!("Not enough data points for {label} summary (need at least 3).");
            return;
        }

        self.stats.sort_by_key(|info| info.proving_time_secs);

        let trimmed = &self.stats[1..self.stats.len() - 1];
        let avg =
            trimmed.iter().map(|i| i.proving_time_secs).sum::<u64>() as f64 / trimmed.len() as f64;

        let lowest = &self.stats[0];
        let highest = &self.stats[self.stats.len() - 1];

        println!("\n=== {label} Proof Time Results ===");
        println!("Total blocks processed: {}", self.stats.len());
        println!(
            "Lowest time:  block {} => {}s",
            lowest.block_height, lowest.proving_time_secs
        );
        println!(
            "Highest time: block {} => {}s",
            highest.block_height, highest.proving_time_secs
        );
        println!("Average time (excluding min/max): {avg:.2}s");
    }
}

#[derive(Parser, Debug)]
pub struct BabyProvingBench {
    /// The Babylon RPC URL to connect to for fetching block data.
    ///
    /// Defaults to a public endpoint. You can override it to point to your own full node.
    #[clap(long, default_value = "https://babylon-archive-rpc.polkachu.com")]
    pub rpc_url: String,

    /// The block height to start benchmarking from (exclusive).
    ///
    /// The first block to be proven will be `initial_height + 1`.
    // block#1 instead of block#0 is used as the genesis block since Cosmos SDK v0.50.
    #[clap(long, default_value_t = 1)]
    pub initial_height: u64,

    /// The number of blocks to process during benchmarking.
    ///
    /// Must be at least 3 to compute meaningful statistics.
    #[clap(long, value_parser = clap::value_parser!(u64).range(3..), default_value = "3")]
    pub total_blocks: u64,
}

impl BabyProvingBench {
    async fn run(self, args: Args) -> anyhow::Result<()> {
        let client = Arc::new(HttpClient::new(self.rpc_url.as_str()).unwrap());
        let chain_id = client.genesis::<serde_json::Value>().await?.chain_id;

        let base_path = args.base_path();
        let consensus_proof_path = base_path.baby_consensus_proof_path(chain_id);

        let mut prover = BabyConsensusProver::new(
            self.initial_height,
            consensus_proof_path.clone(),
            client.clone(),
        );

        let start_height = self.initial_height + 1;
        let end_height = self.initial_height + self.total_blocks;

        let mut stats = ProvingStats::new(self.total_blocks as usize);

        for block_height in start_height..=end_height {
            let proving_time = prover.prove(block_height).await?;
            stats.push(block_height, proving_time);
        }

        stats.print_summary("Babylon Consensus");

        let membership_prover = BabyMembershipProver::new(client, consensus_proof_path);

        // TODO: Support specifying the key and the height from CLI.
        let mut storage_key = vec![0x11];
        storage_key.extend(1u64.to_be_bytes());
        let key_path = vec![b"epoching".to_vec(), storage_key];

        let membership_proof = membership_prover.prove(vec![key_path], end_height).await?;

        println!("Proving time: {}s", membership_proof.proving_time_secs);

        if !membership_proof.groth16.verify()? {
            anyhow::bail!("Failed to verify the generated Groth16 proof");
        }

        Ok(())
    }
}

#[derive(clap::Subcommand, Debug)]
pub enum BenchCmd {
    /// Bench the proving time for Babylon proofs.
    Babylon(BabyProvingBench),
}

impl BenchCmd {
    pub async fn run(self, args: Args) -> anyhow::Result<()> {
        match self {
            Self::Babylon(cmd) => cmd.run(args).await,
        }
    }
}
