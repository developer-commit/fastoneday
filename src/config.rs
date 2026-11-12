//! Runtime settings. Everything that would otherwise be a scattered constant or
//! environment lookup lives here so it can be shown in the UI and overridden.

use std::{env, path::PathBuf, time::Duration};

/// Environment variable that overrides the workspace root.
pub const WORKSPACE_ENV: &str = "FASTONEDAY_HOME";

#[derive(Debug, Clone)]
pub struct Settings {
    /// Root of everything we write: `cache/`, `cases/`, `history.json`.
    pub workspace: PathBuf,
    /// Sent with every HTTP request.
    pub user_agent: String,
    /// Timeout for metadata requests (MSRC, Catalog pages, symbol probes).
    pub request_timeout: Duration,
    /// Also download the matching PDBs next to the binaries.
    pub fetch_pdbs: bool,
}

impl Settings {
    /// Settings from the environment, falling back to `./fastoneday-workspace`.
    pub fn from_env() -> Self {
        let workspace = env::var_os(WORKSPACE_ENV)
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("fastoneday-workspace"));
        Self {
            workspace,
            user_agent: format!("fastoneday/{}", env!("CARGO_PKG_VERSION")),
            request_timeout: Duration::from_secs(60),
            fetch_pdbs: true,
        }
    }

    pub fn with_workspace(mut self, workspace: impl Into<PathBuf>) -> Self {
        self.workspace = workspace.into();
        self
    }

    pub fn cache_dir(&self) -> PathBuf {
        self.workspace.join("cache")
    }

    pub fn cases_dir(&self) -> PathBuf {
        self.workspace.join("cases")
    }

    pub fn history_file(&self) -> PathBuf {
        self.workspace.join("history.json")
    }
}
