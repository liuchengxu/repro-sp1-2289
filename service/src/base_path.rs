use std::fmt::Display;
use std::path::PathBuf;
use tendermint::chain::Id as ChainId;

/// Represents a base path used for everything that needs to be written on-disk.
#[derive(Debug, Clone)]
pub struct BasePath {
    path: PathBuf,
}

impl Display for BasePath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.path.display())
    }
}

// Extracts the file name from `std::env::current_exe()`.
// Fall back to the env var `CARGO_PKG_NAME` in case of error.
fn executable_name() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|e| e.file_name().map(|s| s.to_os_string()))
        .and_then(|w| w.into_string().ok())
        .unwrap_or_else(|| env!("CARGO_PKG_NAME").into())
}

impl BasePath {
    /// Constructs a new instance of [`BasePath`] using an existing path.
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Creates a base path using the project description.
    pub fn from_project() -> Self {
        Self {
            path: directories::ProjectDirs::from("", "babylonlabs", &executable_name())
                .expect("app directories exist on all supported platforms; qed")
                .data_local_dir()
                .to_path_buf(),
        }
    }

    /// Returns the directory for storing consensus proof of Babylon blocks.
    ///
    /// The path looks like `$base_path/proofs/babylon/$chain_id/block`.
    pub fn baby_consensus_proof_path(&self, chain_id: ChainId) -> PathBuf {
        let path = self
            .path
            .join("proofs")
            .join("babylon")
            .join(chain_id.as_str())
            .join("block");
        std::fs::create_dir_all(&path).unwrap_or_else(|e| {
            panic!(
                "Failed to create directory for BTC consensus proofs at {}: {e}",
                path.display(),
            )
        });
        path
    }
}
