//! Enumeration and lifecycle of the foreign CA roots being constrained.
//!
//! A CA "update" is one of two very different things, and telling them apart is this
//! module's main job:
//!
//! - **Same public key, new validity.** Nothing needs doing. The cross-certificate carries
//!   its own validity signed by the local root, so chains keep validating even after the
//!   original expires.
//! - **New public key.** A genuine rotation. The new root is added *alongside* the old
//!   one, because sites migrate gradually and both must be trusted meanwhile.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use openssl::x509::X509;

use crate::workspace::Workspace;
use crate::x509::{is_ca, is_self_signed, load_cert, pubkey_fingerprint};

/// Extensions accepted for files in `roots/`.
///
/// Matching on extension is what keeps `roots/retired/` out of every enumeration; an
/// earlier shell implementation globbed the directory and broke on it.
const ROOT_EXTENSIONS: [&str; 3] = ["cer", "pem", "crt"];

/// A foreign CA root under management.
#[derive(Debug)]
pub struct ForeignRoot {
    /// Stem of the file name, used to derive every generated artifact's name.
    pub name: String,
    /// Location of the certificate on disk.
    pub path: PathBuf,
    /// The parsed certificate.
    pub cert: X509,
}

/// What [`add`] did with an input certificate.
#[derive(Debug, PartialEq, Eq)]
pub enum Added {
    /// The key is already managed; only validity dates differ.
    Renewal {
        /// Name of the existing root carrying the same key.
        existing: String,
    },
    /// A new key, stored under the given name.
    NewKey {
        /// Name the certificate was filed under.
        name: String,
    },
}

/// Lists the managed roots, excluding retired ones.
///
/// # Errors
/// If the directory cannot be read or a certificate fails to parse.
pub fn list(ws: &Workspace) -> Result<Vec<ForeignRoot>> {
    let dir = ws.roots_dir();
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut out = Vec::new();
    for entry in fs::read_dir(&dir).with_context(|| format!("reading {}", dir.display()))? {
        let path = entry.context("reading directory entry")?.path();
        if !path.is_file() || !has_root_extension(&path) {
            continue;
        }
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .context("root file name is not valid UTF-8")?
            .to_owned();
        let cert = load_cert(&path)?;
        out.push(ForeignRoot { name, path, cert });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// Returns true when `path` has one of the accepted certificate extensions.
fn has_root_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| ROOT_EXTENSIONS.contains(&e.to_ascii_lowercase().as_str()))
}

/// Adds a foreign root, or reports that its key is already managed.
///
/// # Errors
/// If `src` is not a certificate, is not self-signed, is not a CA, or a differently-keyed
/// root already occupies the target name.
pub fn add(ws: &Workspace, src: &Path) -> Result<Added> {
    let cert = load_cert(src)?;

    anyhow::ensure!(
        is_self_signed(&cert)?,
        "{} is not self-signed -- an intermediate cannot be cross-signed this way",
        src.display()
    );
    anyhow::ensure!(
        is_ca(&cert)?,
        "{} is not a CA certificate (basicConstraints CA:TRUE missing)",
        src.display()
    );

    let fingerprint = pubkey_fingerprint(&cert)?;
    for existing in list(ws)? {
        if pubkey_fingerprint(&existing.cert)? == fingerprint {
            // Refresh the stored copy so listings show the new validity, but the
            // cross-certificate itself needs no reissue.
            let pem = cert.to_pem().context("encoding certificate")?;
            fs::write(&existing.path, pem)
                .with_context(|| format!("refreshing {}", existing.path.display()))?;
            return Ok(Added::Renewal {
                existing: existing.name,
            });
        }
    }

    let name = sanitise_name(
        src.file_stem()
            .and_then(|s| s.to_str())
            .context("input file name is not valid UTF-8")?,
    );
    let dest = ws.roots_dir().join(format!("{name}.cer"));
    anyhow::ensure!(
        !dest.exists(),
        "roots/{name}.cer already exists with a different key -- rename the input, or retire the old one first"
    );

    ws.ensure_dirs()?;
    let pem = cert.to_pem().context("encoding certificate")?;
    fs::write(&dest, pem).with_context(|| format!("writing {}", dest.display()))?;
    Ok(Added::NewKey { name })
}

/// Moves a root to `roots/retired/` and drops its cross-certificate.
///
/// # Errors
/// If no such root exists, or it is the only one. A workspace with no roots would produce
/// no cross-certificates at all, which reads as a broken setup rather than a decision.
pub fn retire(ws: &Workspace, name: &str) -> Result<()> {
    let roots = list(ws)?;
    anyhow::ensure!(
        roots.len() > 1,
        "refusing to retire the only root -- remove the certificates from your trust stores instead"
    );
    let target = roots
        .into_iter()
        .find(|r| r.name == name)
        .with_context(|| format!("no root named '{name}' (see `rucerts ca list`)"))?;

    let retired = ws.retired_dir();
    fs::create_dir_all(&retired).with_context(|| format!("creating {}", retired.display()))?;
    let dest = retired.join(
        target
            .path
            .file_name()
            .context("root has no file name")?,
    );
    fs::rename(&target.path, &dest)
        .with_context(|| format!("moving {} aside", target.path.display()))?;

    let cross = ws.cross_cert(&target.name);
    if cross.exists() {
        fs::remove_file(&cross).with_context(|| format!("removing {}", cross.display()))?;
    }
    Ok(())
}

/// Replaces characters that would be awkward in a generated file name.
fn sanitise_name(raw: &str) -> String {
    raw.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_certificate_extensions_are_listed() {
        assert!(has_root_extension(Path::new("roots/a.cer")));
        assert!(has_root_extension(Path::new("roots/a.PEM")));
        assert!(has_root_extension(Path::new("roots/a.crt")));
        assert!(!has_root_extension(Path::new("roots/retired")));
        assert!(!has_root_extension(Path::new("roots/notes.txt")));
    }

    #[test]
    fn names_are_reduced_to_safe_characters() {
        assert_eq!(sanitise_name("russian_trusted_root_ca"), "russian_trusted_root_ca");
        assert_eq!(sanitise_name("root 2027 (new)"), "root_2027__new_");
        assert_eq!(sanitise_name("../../etc/passwd"), ".._.._etc_passwd");
    }
}
