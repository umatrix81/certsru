//! Filesystem layout of a rucerts workspace.
//!
//! A workspace is a directory holding the local root (`myroot.pem` / `myroot.key`), the
//! foreign roots being constrained (`roots/`), one cross-certificate per root
//! (`constrained/`), and `rucerts.toml`. Retired roots move to `roots/retired/` and are
//! deliberately excluded from every enumeration.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Directory holding the certificates and configuration this tool manages.
#[derive(Debug, Clone)]
pub struct Workspace {
    dir: PathBuf,
}

impl Workspace {
    /// Opens the workspace rooted at `dir`.
    pub fn new(dir: impl AsRef<Path>) -> Self {
        Self {
            dir: dir.as_ref().to_path_buf(),
        }
    }

    /// Returns the workspace directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Path of the local root certificate.
    pub fn root_cert(&self) -> PathBuf {
        self.dir.join("myroot.pem")
    }

    /// Path of the local root private key.
    pub fn root_key(&self) -> PathBuf {
        self.dir.join("myroot.key")
    }

    /// Directory holding the foreign roots being constrained.
    pub fn roots_dir(&self) -> PathBuf {
        self.dir.join("roots")
    }

    /// Directory holding retired foreign roots.
    pub fn retired_dir(&self) -> PathBuf {
        self.roots_dir().join("retired")
    }

    /// Directory holding the generated cross-certificates.
    pub fn constrained_dir(&self) -> PathBuf {
        self.dir.join("constrained")
    }

    /// Path of the cross-certificate generated for the root named `name`.
    pub fn cross_cert(&self, name: &str) -> PathBuf {
        self.constrained_dir().join(format!("{name}.pem"))
    }

    /// Path of the PowerShell installer template.
    pub fn installer_template(&self) -> PathBuf {
        self.dir.join("install-certs.ps1")
    }

    /// Creates the directories the tool writes into.
    ///
    /// # Errors
    /// If a directory cannot be created.
    pub fn ensure_dirs(&self) -> Result<()> {
        for dir in [self.roots_dir(), self.constrained_dir()] {
            fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        Ok(())
    }

    /// Creates a timestamped backup directory and copies `files` into it.
    ///
    /// Returns the backup directory. Used before replacing key material, which is
    /// otherwise unrecoverable -- this workspace is not under version control.
    ///
    /// # Errors
    /// If the directory cannot be created or a file cannot be copied.
    pub fn backup(&self, label: &str, files: &[PathBuf]) -> Result<PathBuf> {
        let dir = self.dir.join(format!("backup-{label}"));
        fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        for src in files {
            if !src.exists() {
                continue;
            }
            let name = src.file_name().context("backup source has no file name")?;
            fs::copy(src, dir.join(name))
                .with_context(|| format!("copying {} into backup", src.display()))?;
        }
        Ok(dir)
    }
}
