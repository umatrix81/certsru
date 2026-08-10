//! Command line surface.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Manage name-constrained cross-certificates for third-party CAs.
#[derive(Debug, Parser)]
#[command(name = "rucerts", version, about, long_about = None)]
pub struct Cli {
    /// Workspace directory holding roots/, constrained/ and rucerts.toml.
    #[arg(long, global = true)]
    pub dir: Option<PathBuf>,

    /// Skip regenerating the installable artifacts.
    #[arg(long, global = true)]
    pub no_artifacts: bool,

    /// What to do.
    #[command(subcommand)]
    pub command: Command,
}

/// Top level commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create a local root and configuration in an empty workspace.
    Init {
        /// Common Name for the local root.
        #[arg(long, default_value = "Local Constraining Root")]
        cn: String,
    },
    /// Manage the permitted domain list.
    Domain {
        /// Domain operation.
        #[command(subcommand)]
        action: DomainAction,
    },
    /// Manage the foreign CA roots being constrained.
    Ca {
        /// CA operation.
        #[command(subcommand)]
        action: CaAction,
    },
    /// Manage the local root.
    Root {
        /// Root operation.
        #[command(subcommand)]
        action: RootAction,
    },
    /// Re-sign every cross-certificate without changing the domain list.
    Resign,
    /// Regenerate the installable artifacts without re-signing.
    Artifacts,
    /// Audit the generated cross-certificates.
    Verify,
}

/// Operations on the permitted domain list.
#[derive(Debug, Subcommand)]
pub enum DomainAction {
    /// Add domains, then re-sign and stage.
    Add {
        /// Domains to permit. A pasted URL is reduced to its host.
        #[arg(required = true)]
        domains: Vec<String>,
    },
    /// Remove domains, then re-sign and stage.
    Remove {
        /// Domains to stop permitting. Only exact entries are removed.
        #[arg(required = true)]
        domains: Vec<String>,
    },
    /// Print the permitted domains.
    List,
}

/// Operations on the foreign CA roots.
#[derive(Debug, Subcommand)]
pub enum CaAction {
    /// Add a root, or report that its key is already managed.
    Add {
        /// Certificate files, PEM or DER.
        #[arg(required = true)]
        files: Vec<PathBuf>,
    },
    /// Print the managed roots with their key fingerprints.
    List,
    /// Stop constraining a root, moving it to roots/retired/.
    Retire {
        /// Name as shown by `rucerts ca list`.
        name: String,
    },
}

/// Operations on the local root.
#[derive(Debug, Subcommand)]
pub enum RootAction {
    /// Generate a new local root with the given Common Name.
    ///
    /// This mints a new key pair; everything already trusting the old root must be
    /// updated.
    SetCn {
        /// The new Common Name.
        cn: String,
        /// Skip the confirmation prompt.
        #[arg(short = 'y', long)]
        yes: bool,
    },
}
