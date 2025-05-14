use self::base_path::BasePath;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, Subcommand)]
pub enum Cmd {
    /// Run the prover service
    Run(self::command::run::RunCmd),
    /// Measure the time for ZK proof generation.
    Bench(self::command::bench::BenchCmd),
}

/// Shared CLI arguments across all commands.
#[derive(Debug, clap::Args)]
pub struct Args {
    /// Specify the base path used to handle the location of everything that needs to be written
    /// on-disk.
    #[clap(long, value_parser)]
    pub base_path: Option<PathBuf>,

    /// Sets custom logging filters in the form `<target>=<level>`.
    ///
    /// Log levels (from least to most verbose): `error`, `warn`, `info`, `debug`, `trace`.
    ///
    /// Defaults to `info`.
    ///
    /// Multiple filters can be separated by commas, e.g.: `--log debug,bitvm_bridge=trace`
    #[clap(long, value_name = "LOG_PATTERN", num_args = 1..)]
    pub log: Vec<String>,

    /// Specify the SP1 prover to be used.
    // This is added to avoid the annoying 
    #[clap(long, env = "SP1_PROVER", default_value = "cpu")]
    pub sp1_prover: String
}

impl Args {
    pub fn btc_rpc_auth(&self) -> anyhow::Result<bitcoincore_rpc::Auth> {
        let auth = match &self.btc_rpc_auth {
            Some(auth) => {
                let auth = auth.split(':').collect::<Vec<_>>();
                if auth.len() != 2 {
                    return Err(anyhow::anyhow!(
                        "Invalid input for --btc-rpc-auth, expected user:password"
                    ));
                }
                bitcoincore_rpc::Auth::UserPass(auth[0].to_string(), auth[1].to_string())
            }
            None => bitcoincore_rpc::Auth::None,
        };

        Ok(auth)
    }

    pub fn btc_rpc_client(&self) -> anyhow::Result<Arc<bitcoincore_rpc::Client>> {
        let auth = self.btc_rpc_auth()?;

        let bitcoin_rpc_client =
            bitcoincore_rpc::Client::new(&self.btc_rpc_url, auth).map_err(|err| {
                tracing::error!(?err, "Failed to create Bitcoin Core RPC Client");
                anyhow::anyhow!(
                    "Failed to create Bitcoin Core RPC Client, url: {:?}, rpcauth: {:?}",
                    self.btc_rpc_url,
                    self.btc_rpc_auth
                )
            })?;

        Ok(Arc::new(bitcoin_rpc_client))
    }

    pub fn base_path(&self, chain: bitcoin::Network) -> BasePath {
        match &self.base_path {
            Some(path) => BasePath::new(path.to_path_buf(), chain),
            None => BasePath::from_project(chain),
        }
    }
}

/// Prover Service CLI.
#[derive(Debug, Parser)]
pub struct Cli {
    #[clap(flatten)]
    pub args: Args,

    #[command(subcommand)]
    pub cmd: Cmd,
}
