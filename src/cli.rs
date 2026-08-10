//! Command line surface.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Manage name-constrained cross-certificates for third-party CAs.
///
/// Trusting a third-party CA normally lets it vouch for any hostname.
/// This narrows it: the CA's root is re-issued under a locally generated
/// root carrying an X.509 nameConstraints extension, and only the local
/// root is trusted.
///
/// First run, in this order:
///
///   rucerts init --cn "My Root"      create the local root
///   rucerts ca add <root.cer>        the CA to constrain
///   rucerts domain add example.com   what it may vouch for
///   rucerts verify                   prove it before trusting it
///
/// Then install: run install-certs.cmd, or install-certs.ps1 from
/// PowerShell with -ExecutionPolicy Bypass.
///
/// Afterwards, domain and ca are the commands you reach for; each
/// re-signs and regenerates the installable files on its own.
#[derive(Debug, Parser)]
#[command(name = "rucerts", version, about, verbatim_doc_comment)]
#[expect(
    clippy::doc_markdown,
    reason = "verbatim_doc_comment renders this as terminal help, so backticks and other \
              markdown would be shown to the user literally rather than formatted"
)]
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
///
/// Declaration order is what clap prints, so these are ordered as a first run proceeds:
/// create the root, add the CA, permit domains, verify. `ca` must precede `domain` --
/// there is nothing to sign against until a CA exists. Maintenance commands follow.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// 1. Create a local root and configuration in an empty workspace.
    Init {
        /// Common Name for the local root.
        #[arg(long, default_value = "!Root to bypass Russian certificates")]
        cn: String,
    },
    /// 2. Manage the foreign CA roots being constrained.
    Ca {
        /// CA operation.
        #[command(subcommand)]
        action: CaAction,
    },
    /// 3. Manage the permitted domain list.
    Domain {
        /// Domain operation.
        #[command(subcommand)]
        action: DomainAction,
    },
    /// 4. Audit the generated cross-certificates.
    Verify,
    /// Re-sign every cross-certificate without changing the domain list.
    Resign,
    /// Regenerate the installable artifacts without re-signing.
    Artifacts,
    /// Rename or replace the local root.
    Root {
        /// Root operation.
        #[command(subcommand)]
        action: RootAction,
    },
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
