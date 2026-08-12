//! Produces the installable artifacts: certificate copies, policy and installer.
//!
//! Two things are written into the workspace:
//!
//! - `install-certs.ps1` with the certificates embedded, so it can be shared as one file,
//!   plus `install-certs.cmd`, a double-clickable wrapper that gets past the default
//!   execution policy without changing it.
//! - `constrained-ca-policy.reg`, applying `CACertificatesWithConstraints` to the
//!   *original* roots. Chrome and Edge need no cross-certificate at all.
//!
//! Loose `.crt` copies are deliberately not written. They duplicated `myroot.pem`,
//! `constrained/*.pem` and `roots/*` byte for byte, and every one of them is already
//! embedded in the installer -- `install-certs.ps1 -Export <dir>` writes them out when
//! Firefox needs files to import.
//!
//! The PowerShell template is compiled into this binary rather than read from disk, so the
//! generated installer cannot overwrite its own source and no template file has to travel
//! alongside the tool.
//!
//! The permitted list written into the policy is read back out of the **signed
//! certificates**, never from configuration. Deriving it from configuration allows a
//! config edit without a re-sign to produce a policy that does not match any certificate.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use base64::Engine as _;
use openssl::x509::X509;
use serde_json::json;

use crate::roots::ForeignRoot;
use crate::workspace::Workspace;
use crate::x509::{load_cert, permitted_dns};

/// CIDR range allowed by the Chrome policy.
///
/// Chrome treats an absent constraint type as unconstrained, so omitting this would let
/// the CA vouch for any bare-IP certificate. Loopback is the narrowest range that is
/// unambiguously present.
const POLICY_PERMITTED_CIDR: &str = "127.0.0.1/32";

/// Marker in the installer template replaced by the embedded certificate block.
const EMBED_MARKER: &str = "#<<<EMBEDDED>>>";

/// The PowerShell installer, compiled in so it needs no companion file at runtime.
const INSTALLER_TEMPLATE: &str = include_str!("../templates/install-certs.ps1");

/// Double-clickable wrapper that runs the installer past the default execution policy.
const INSTALLER_CMD: &str = include_str!("../templates/install-certs.cmd");

/// Line width for embedded base64, matching PEM convention.
const B64_WRAP: usize = 76;

/// Files written by earlier versions of this tool, no longer produced.
///
/// `myroot.crt` and the per-root `.crt` copies duplicated files already in the workspace
/// and are all recoverable with `install-certs.ps1 -Export`. They are deleted on every run
/// so a stale copy cannot be imported by mistake.
const LEGACY_FILES: [&str; 3] = [
    "russian-root-constrained.crt",
    "russian_trusted_root_ca.crt",
    "myroot.crt",
];

/// What a generation run produced.
#[derive(Debug)]
pub struct Staged {
    /// Directory written to.
    pub dir: PathBuf,
    /// Number of roots covered.
    pub roots: usize,
    /// Permitted domains, as read back from the signed certificates.
    pub domains: Vec<String>,
}

/// Writes every installable artifact into the workspace.
///
/// # Errors
/// If a cross-certificate is missing, the directory cannot be written, or the certificates
/// disagree about which domains they permit.
pub fn stage(ws: &Workspace, roots: &[ForeignRoot]) -> Result<Staged> {
    anyhow::ensure!(
        !roots.is_empty(),
        "нет корневых сертификатов, для которых создавать файлы установки"
    );
    let dir = ws.dir();
    clean_stale(dir)?;

    let root_cert = load_cert(&ws.root_cert())?;
    let mut entries = Vec::new();
    let mut domains: Option<Vec<String>> = None;

    for root in roots {
        let cross_path = ws.cross_cert(&root.name);
        anyhow::ensure!(
            cross_path.exists(),
            "нет кросс-сертификата для {} -- выполните `rucerts resign`",
            root.name
        );
        let cross = load_cert(&cross_path)?;

        let permitted = permitted_dns(&cross)?;
        anyhow::ensure!(
            !permitted.is_empty(),
            "{} не разрешает ни одного DNS-имени -- файлы установки не создаются",
            cross_path.display()
        );
        match &domains {
            None => domains = Some(permitted.clone()),
            Some(first) => anyhow::ensure!(
                *first == permitted,
                "кросс-сертификаты расходятся в разрешённых именах; действующей политикой \
                 стало бы их объединение. Выполните `rucerts resign`."
            ),
        }

        entries.push((root.name.clone(), root.cert.clone(), cross, permitted));
    }

    let domains = domains.unwrap_or_default();
    write_policy(dir, &entries)?;
    write_installer(dir, &root_cert, &entries)?;

    Ok(Staged {
        dir: dir.to_path_buf(),
        roots: roots.len(),
        domains,
    })
}

/// Removes per-root files plus the pre-refactor filenames.
fn clean_stale(dir: &Path) -> Result<()> {
    for legacy in LEGACY_FILES {
        let path = dir.join(legacy);
        if path.exists() {
            fs::remove_file(&path).with_context(|| format!("удаление {}", path.display()))?;
        }
    }
    for entry in fs::read_dir(dir).with_context(|| format!("чтение {}", dir.display()))? {
        let path = entry.context("чтение элемента каталога")?.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name.ends_with("-constrained.crt") || name.ends_with("-original.crt") {
            fs::remove_file(&path).with_context(|| format!("удаление {}", path.display()))?;
        }
    }
    Ok(())
}

/// Writes the Chrome and Edge policy file.
fn write_policy(dir: &Path, entries: &[(String, X509, X509, Vec<String>)]) -> Result<()> {
    let mut objects = Vec::new();
    for (_, original, _, permitted) in entries {
        let der = original.to_der().context("кодирование исходного корня")?;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&der);
        objects.push(
            json!({
                "certificate": b64,
                "constraints": {
                    "permitted_dns_names": permitted,
                    "permitted_cidrs": [POLICY_PERMITTED_CIDR],
                }
            })
            .to_string(),
        );
    }

    let mut lines = vec![
        "Windows Registry Editor Version 5.00".to_owned(),
        String::new(),
    ];
    for vendor in [r"Google\Chrome", r"Microsoft\Edge"] {
        lines.push(format!(
            r"[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\{vendor}\CACertificatesWithConstraints]"
        ));
        for (index, object) in objects.iter().enumerate() {
            let escaped = object.replace('\\', r"\\").replace('"', "\\\"");
            lines.push(format!("\"{}\"=\"{escaped}\"", index + 1));
        }
        lines.push(String::new());
    }

    let path = dir.join("constrained-ca-policy.reg");
    fs::write(&path, to_utf16le_with_bom(&lines.join("\r\n")))
        .with_context(|| format!("запись {}", path.display()))
}

/// Encodes text as UTF-16 little-endian with a byte order mark.
///
/// `regedit` rejects a `.reg` file that is not UTF-16 with a BOM.
fn to_utf16le_with_bom(text: &str) -> Vec<u8> {
    let mut out = vec![0xFF, 0xFE];
    for unit in text.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

/// Writes the installer with certificates embedded.
fn write_installer(
    dir: &Path,
    root: &X509,
    entries: &[(String, X509, X509, Vec<String>)],
) -> Result<()> {
    debug_assert!(
        INSTALLER_TEMPLATE.contains(EMBED_MARKER),
        "the compiled-in template lost its {EMBED_MARKER} marker"
    );

    let mut embedded = Vec::new();
    embedded.push(embed_entry("myroot", "root", root)?);
    for (name, original, cross, _) in entries {
        embedded.push(embed_entry(name, "constrained", cross)?);
        embedded.push(embed_entry(name, "original", original)?);
    }

    let filled = INSTALLER_TEMPLATE.replace(EMBED_MARKER, &embedded.join("\n"));
    let path = dir.join("install-certs.ps1");
    // UTF-8 with BOM and CRLF: Windows PowerShell 5.1 assumes the ANSI code page for a
    // BOM-less file, which mangles a non-ASCII root Common Name.
    let mut bytes = vec![0xEF, 0xBB, 0xBF];
    bytes.extend_from_slice(to_crlf(&filled).as_bytes());
    fs::write(&path, bytes).with_context(|| format!("запись {}", path.display()))?;

    // The wrapper carries no BOM: cmd.exe would try to execute those bytes as part of the
    // first line. It is plain ASCII, so none is needed.
    let cmd_path = dir.join("install-certs.cmd");
    fs::write(&cmd_path, to_crlf(INSTALLER_CMD).as_bytes())
        .with_context(|| format!("запись {}", cmd_path.display()))
}

/// Normalises line endings to CRLF, which both PowerShell and `cmd.exe` expect.
fn to_crlf(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\n', "\r\n")
}

/// Renders one PowerShell hashtable literal holding a certificate.
fn embed_entry(name: &str, kind: &str, cert: &X509) -> Result<String> {
    let der = cert.to_der().context("кодирование сертификата")?;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&der);
    let wrapped = b64
        .as_bytes()
        .chunks(B64_WRAP)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join("\n");
    Ok(format!(
        "@{{Name='{name}';Kind='{kind}';B64=@'\n{wrapped}\n'@}}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf16_encoding_starts_with_a_bom() {
        let bytes = to_utf16le_with_bom("AB");
        assert_eq!(bytes, vec![0xFF, 0xFE, b'A', 0x00, b'B', 0x00]);
    }

    #[test]
    fn registry_escaping_survives_a_json_round_trip() {
        let object = json!({"certificate": "MIIB\"x\\y"}).to_string();
        let escaped = object.replace('\\', r"\\").replace('"', "\\\"");
        // Reverse what regedit does when reading the value back.
        let unescaped = escaped.replace("\\\"", "\"").replace(r"\\", "\\");
        assert_eq!(unescaped, object);
        let parsed: serde_json::Value = serde_json::from_str(&unescaped).expect("valid json");
        assert_eq!(parsed["certificate"], "MIIB\"x\\y");
    }
}
