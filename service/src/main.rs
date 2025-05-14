mod base_path;
mod command;
mod provers;

use self::base_path::BasePath;
use clap::{Parser, ValueEnum};
use std::path::PathBuf;
use strum::{Display, EnumString};

#[derive(Debug, Parser)]
pub enum Cmd {
    /// Measure the time for ZK proof generation.
    #[clap(subcommand)]
    Bench(self::command::bench::BenchCmd),
}

/// Supported SP1 Prover type.
#[derive(Debug, Clone, ValueEnum, EnumString, Display)]
#[strum(serialize_all = "lowercase")]
pub enum SP1Prover {
    Mock,
    Cpu,
    Cuda,
    Network,
}

/// Shared CLI arguments across all commands.
#[derive(Debug, clap::Args)]
pub struct Args {
    /// Specify the RPC URL of Bitcoind node.
    #[clap(long, default_value = "http://127.0.0.1:8332")]
    pub btc_rpc_url: String,

    /// Specify the RPC auth config for Bitcoind node we are connecting to.
    #[clap(long)]
    pub btc_rpc_auth: Option<String>,

    /// Specify the endpoint for Bitcoind node's ZMQ service.
    ///
    /// Example: `tcp:127.0.0.1:28332`
    // TODO: Add poll-based stream in bitcoin-chain-events so that this argument can be truly
    // optional.
    #[clap(long)]
    pub zmq_endpoint: Option<String>,

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
    #[clap(long, env = "SP1_PROVER", default_value = "cpu")]
    pub sp1_prover: SP1Prover,
}

impl Args {
    pub fn base_path(&self) -> BasePath {
        match &self.base_path {
            Some(path) => BasePath::new(path.to_path_buf()),
            None => BasePath::from_project(),
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

fn initialize_logger(args: &Args) {
    let mut env_filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
        .from_env_lossy();

    let parse_default_directive = |d: &str| -> tracing_subscriber::filter::Directive {
        d.parse().expect("provided static directive is valid")
    };

    // Reduce verbosity for known noisy modules.
    //
    // For example, `sp1_core_executor` from SP1 logs excessive info-level messages
    // that are typically not useful in normal runs. We suppress them by default here.
    env_filter = env_filter.add_directive(parse_default_directive("sp1_core_executor=warn"));

    if !args.log.is_empty() {
        for dir in args.log.iter().flat_map(|l| l.split(',')) {
            match dir.parse() {
                Ok(directive) => {
                    env_filter = env_filter.add_directive(directive);
                }
                Err(err) => {
                    eprintln!("Invalid log directive '{dir}': {err}");
                }
            }
        }
    }

    tracing_subscriber::FmtSubscriber::builder()
        .with_env_filter(env_filter)
        .try_init()
        .expect("Failed to set default subscriber");
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let Cli { args, cmd } = Cli::parse();

    initialize_logger(&args);

    // SAFETY: This env variable is set on startup before any threads are spawned, and the
    // value is guaranteed to be valid due to clap's `ValueEnum` constraint.
    unsafe {
        // Avoid too many SP1 SDK warnings by explicitly setting SP1_PROVER to a known-good value.
        // 2025-04-29T02:11:18.605132Z  WARN sp1_sdk::env: SP1_PROVER environment variable not set, defaulting to 'cpu'
        std::env::set_var("SP1_PROVER", args.sp1_prover.to_string());
        tracing::info!("Set env variable SP1_PROVER to {}", args.sp1_prover);
    };

    match cmd {
        Cmd::Bench(bench_cmd) => {
            bench_cmd.run(args).await?;
        }
    }

    Ok(())
}
