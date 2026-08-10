//! Certificate loading, cross-signing and inspection.
//!
//! The central operation is [`cross_sign`], which re-issues a foreign self-signed root
//! under a local root while adding an X.509 `nameConstraints` extension. It replaces
//! `openssl ca -ss_cert` from the shell implementation.
//!
//! Two properties of the output are load-bearing and are asserted by the caller rather
//! than assumed:
//!
//! - The **Subject DN must be byte-identical** to the original's. Chain building matches a
//!   sub-CA's `issuer` field against it; any re-encoding breaks every chain.
//! - The **Subject Key Identifier must be unchanged**, because sub-CAs carry an
//!   `authorityKeyIdentifier` pointing at it. Since the public key is copied verbatim and
//!   the SKI is its SHA-1, this holds by construction.

use anyhow::{Context, Result};
use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::rand::rand_bytes;
use openssl::rsa::Rsa;
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectKeyIdentifier,
};
use openssl::x509::{X509Builder, X509Extension, X509NameBuilder, X509};

use crate::config::{Constraints, MAX_CN_BYTES};

/// Key size for generated local roots.
///
/// 4096-bit RSA matches what the shell implementation produced; changing it invalidates
/// every previously issued cross-certificate, since the root key changes with it.
const ROOT_KEY_BITS: u32 = 4096;

/// Loads a certificate from PEM, falling back to DER.
///
/// # Errors
/// If the file cannot be read or is not a certificate in either encoding.
pub fn load_cert(path: &std::path::Path) -> Result<X509> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    X509::from_pem(&bytes)
        .or_else(|_| X509::from_der(&bytes))
        .with_context(|| format!("{} is not a PEM or DER certificate", path.display()))
}

/// Loads a private key from a PEM file.
///
/// # Errors
/// If the file cannot be read or does not contain a PEM private key.
pub fn load_key(path: &std::path::Path) -> Result<PKey<Private>> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    PKey::private_key_from_pem(&bytes).with_context(|| format!("parsing key {}", path.display()))
}

/// Generates a self-signed local root with the given Common Name.
///
/// # Errors
/// If `cn` is empty, exceeds [`MAX_CN_BYTES`], or key generation fails.
pub fn generate_root(cn: &str, days: u32) -> Result<(X509, PKey<Private>)> {
    anyhow::ensure!(!cn.is_empty(), "common name must not be empty");
    anyhow::ensure!(
        cn.len() <= MAX_CN_BYTES,
        "common name is {} bytes; the X.509 upper bound is {MAX_CN_BYTES}",
        cn.len()
    );

    let rsa = Rsa::generate(ROOT_KEY_BITS).context("generating root key")?;
    let key = PKey::from_rsa(rsa).context("wrapping root key")?;

    let mut name = X509NameBuilder::new()?;
    // Always UTF-8: the shell version needed `openssl req -utf8` here, and without it
    // non-ASCII names were stored double-encoded.
    name.append_entry_by_nid(Nid::COMMONNAME, cn)
        .context("setting common name")?;
    let name = name.build();

    let mut b = X509Builder::new()?;
    b.set_version(2)?; // X.509 v3
    b.set_subject_name(&name)?;
    b.set_issuer_name(&name)?;
    b.set_pubkey(&key)?;

    let serial = random_serial()?;
    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(days)?;
    b.set_serial_number(&serial)?;
    b.set_not_before(&not_before)?;
    b.set_not_after(&not_after)?;

    let mut bc = BasicConstraints::new();
    b.append_extension(bc.critical().ca().build()?)?;

    let ski = {
        let ctx = b.x509v3_context(None, None);
        SubjectKeyIdentifier::new().build(&ctx)?
    };
    b.append_extension(ski)?;

    b.sign(&key, MessageDigest::sha256())
        .context("self-signing root")?;
    Ok((b.build(), key))
}

/// Re-issues `original` under `root`, adding name constraints.
///
/// The Subject DN and public key are copied from `original`, so the result is a drop-in
/// replacement in any chain that previously terminated at `original`.
///
/// # Errors
/// If `original` has no usable public key, or signing fails.
pub fn cross_sign(
    root: &X509,
    root_key: &PKey<Private>,
    original: &X509,
    constraints: &Constraints,
    days: u32,
    path_len: u32,
) -> Result<X509> {
    let mut b = X509Builder::new()?;
    b.set_version(2)?; // X.509 v3

    // This is what `preserve = yes` did in the old cross.cnf: the DN is taken from the
    // original's parsed name, not rebuilt from strings, so its encoding survives intact.
    b.set_subject_name(original.subject_name())?;
    b.set_issuer_name(root.subject_name())?;

    let pubkey = original
        .public_key()
        .context("reading the original's public key")?;
    b.set_pubkey(&pubkey)?;

    // Serials were sequential via index.txt; random removes the CA database entirely.
    let serial = random_serial()?;
    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(days)?;
    b.set_serial_number(&serial)?;
    b.set_not_before(&not_before)?;
    b.set_not_after(&not_after)?;

    let mut bc = BasicConstraints::new();
    b.append_extension(bc.critical().ca().pathlen(path_len).build()?)?;
    b.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()?,
    )?;

    let (ski, akid) = {
        let ctx = b.x509v3_context(Some(root), None);
        (
            SubjectKeyIdentifier::new().build(&ctx)?,
            AuthorityKeyIdentifier::new().keyid(true).build(&ctx)?,
        )
    };
    b.append_extension(ski)?;
    b.append_extension(akid)?;
    b.append_extension(name_constraints_ext(constraints)?)?;

    b.sign(root_key, MessageDigest::sha256())
        .context("signing cross-certificate")?;
    Ok(b.build())
}

/// Builds the critical `nameConstraints` extension.
///
/// # Errors
/// If the permitted list is empty, or OpenSSL rejects the encoded value.
#[expect(
    deprecated,
    reason = "The typed x509::extension builders have no NameConstraints equivalent. The \
              alternative, new_from_der, means hand-encoding GeneralSubtree DER, which is \
              precisely where a silent mistake would widen the CA's authority. Letting \
              OpenSSL parse its own configuration syntax is what keeps the output \
              byte-identical to the previously issued certificates -- asserted by the \
              golden test in tests/golden.rs."
)]
pub fn name_constraints_ext(constraints: &Constraints) -> Result<X509Extension> {
    let value = name_constraints_value(constraints)?;
    X509Extension::new_nid(None, None, Nid::NAME_CONSTRAINTS, &value)
        .with_context(|| format!("encoding nameConstraints from {value:?}"))
}

/// Renders the OpenSSL configuration value for `nameConstraints`.
///
/// # Errors
/// If no permitted DNS names are configured. A cross-certificate permitting nothing
/// rejects every host, which presents as a broken chain rather than as a policy.
pub fn name_constraints_value(constraints: &Constraints) -> Result<String> {
    anyhow::ensure!(
        !constraints.permitted_dns.is_empty(),
        "no permitted DNS names -- the certificate would trust nothing"
    );

    let mut parts = vec!["critical".to_owned()];
    for dns in &constraints.permitted_dns {
        parts.push(format!("permitted;DNS:{dns}"));
    }
    // A constraint type that is absent is unconstrained, not forbidden. Without these the
    // CA would still be free to vouch for bare-IP, email and URI names.
    if constraints.exclude_ip {
        parts.push("excluded;IP:0.0.0.0/0.0.0.0".to_owned());
        parts.push("excluded;IP:::/::".to_owned());
    }
    if constraints.exclude_email {
        parts.push("excluded;email:.".to_owned());
    }
    if constraints.exclude_uri {
        parts.push("excluded;URI:.".to_owned());
    }
    Ok(parts.join(","))
}

/// Returns the Subject Key Identifier as uppercase colon-separated hex.
pub fn ski_hex(cert: &X509) -> Option<String> {
    cert.subject_key_id().map(|id| hex(id.as_slice(), true))
}

/// Extracts the permitted DNS names recorded in a certificate's `nameConstraints`.
///
/// Read back from the signed certificate rather than from configuration, so anything
/// derived from it (notably the Chrome policy) cannot drift from what was actually issued.
///
/// # Errors
/// If the certificate cannot be rendered as text.
pub fn permitted_dns(cert: &X509) -> Result<Vec<String>> {
    let text = String::from_utf8(cert.to_text().context("rendering certificate")?)
        .context("certificate text was not UTF-8")?;
    Ok(parse_permitted_dns(&text))
}

/// Parses the `Permitted:` DNS entries out of an OpenSSL text dump.
fn parse_permitted_dns(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_constraints = false;
    let mut in_permitted = false;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("X509v3 Name Constraints") {
            in_constraints = true;
            continue;
        }
        if !in_constraints {
            continue;
        }
        match trimmed {
            "Permitted:" => in_permitted = true,
            "Excluded:" => in_permitted = false,
            _ => {
                if let Some(name) = trimmed.strip_prefix("DNS:") {
                    if in_permitted {
                        out.push(name.to_owned());
                    }
                } else if trimmed.starts_with("X509v3 ") {
                    // A following extension ends the block.
                    break;
                }
            }
        }
    }
    out
}

/// Returns true when the certificate is self-signed.
///
/// Both halves matter: matching names alone can be forged, and a valid signature over a
/// different DN is not a root. `openssl ca -ss_cert` required this, and so does
/// [`cross_sign`] -- an intermediate cannot be cross-signed this way.
///
/// # Errors
/// If either distinguished name or the public key cannot be encoded.
pub fn is_self_signed(cert: &X509) -> Result<bool> {
    let subject = cert.subject_name().to_der().context("subject DN")?;
    let issuer = cert.issuer_name().to_der().context("issuer DN")?;
    if subject != issuer {
        return Ok(false);
    }
    let key = cert.public_key().context("public key")?;
    Ok(cert.verify(&key).unwrap_or(false))
}

/// Returns true when the certificate carries `basicConstraints` with `CA:TRUE`.
///
/// # Errors
/// If the certificate cannot be rendered as text.
pub fn is_ca(cert: &X509) -> Result<bool> {
    let text = String::from_utf8(cert.to_text().context("rendering certificate")?)
        .context("certificate text was not UTF-8")?;
    Ok(text.contains("CA:TRUE"))
}

/// Returns a SHA-256 fingerprint over the `SubjectPublicKeyInfo`.
///
/// Identifies a CA key across re-issuances: a renewal keeps this value, a rotation changes
/// it. That distinction decides whether any action is needed at all.
///
/// # Errors
/// If the public key cannot be read, encoded or hashed.
pub fn pubkey_fingerprint(cert: &X509) -> Result<String> {
    let der = cert
        .public_key()
        .context("public key")?
        .public_key_to_der()
        .context("encoding public key")?;
    let digest = openssl::hash::hash(MessageDigest::sha256(), &der).context("hashing key")?;
    Ok(hex(&digest, false))
}

/// Returns a SHA-256 fingerprint over the whole certificate, colon-separated.
///
/// # Errors
/// If the certificate cannot be hashed.
pub fn fingerprint(cert: &X509) -> Result<String> {
    let digest = cert.digest(MessageDigest::sha256()).context("hashing cert")?;
    Ok(hex(&digest, true))
}

/// Renders bytes as hex, optionally uppercase and colon-separated.
fn hex(bytes: &[u8], colons: bool) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 3), |mut acc, b| {
            if colons && !acc.is_empty() {
                acc.push(':');
            }
            // Writing into a String cannot fail.
            let _ = if colons {
                write!(acc, "{b:02X}")
            } else {
                write!(acc, "{b:02x}")
            };
            acc
        })
}

/// Returns the certificate's Common Name, if it has one.
pub fn subject_cn(cert: &X509) -> Option<String> {
    cert.subject_name()
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        // Read the raw bytes rather than via as_utf8, which truncates at an interior NUL.
        .and_then(|e| String::from_utf8(e.data().as_slice().to_vec()).ok())
}

/// Generates a positive 64-bit serial number.
fn random_serial() -> Result<Asn1Integer> {
    let mut bytes = [0_u8; 8];
    rand_bytes(&mut bytes).context("drawing serial bytes")?;
    bytes[0] &= 0x7F; // keep the DER INTEGER positive
    let bn = BigNum::from_slice(&bytes).context("building serial")?;
    bn.to_asn1_integer().context("encoding serial")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn constraints(names: &[&str]) -> Constraints {
        Config::new(names.iter().map(|s| (*s).to_owned()).collect()).constraints
    }

    #[test]
    fn value_lists_permitted_then_excluded() {
        let c = constraints(&["a.ru", "b.ru"]);
        let v = name_constraints_value(&c).expect("non-empty list");
        assert_eq!(
            v,
            "critical,permitted;DNS:a.ru,permitted;DNS:b.ru,\
             excluded;IP:0.0.0.0/0.0.0.0,excluded;IP:::/::,\
             excluded;email:.,excluded;URI:."
        );
    }

    #[test]
    fn empty_permitted_list_is_rejected() {
        let c = constraints(&[]);
        // Panics if this unexpectedly succeeds, which is the assertion.
        name_constraints_value(&c).unwrap_err();
    }

    #[test]
    fn hex_rendering_matches_openssl_conventions() {
        assert_eq!(hex(&[0xE1, 0x0D], true), "E1:0D");
        assert_eq!(hex(&[0xE1, 0x0D], false), "e10d");
        assert_eq!(hex(&[], true), "");
    }

    #[test]
    fn parses_permitted_but_not_excluded_names() {
        let text = "\
            X509v3 Name Constraints: critical\n\
            \x20   Permitted:\n\
            \x20     DNS:sberbank.ru\n\
            \x20     DNS:vtb.ru\n\
            \x20   Excluded:\n\
            \x20     DNS:evil.ru\n\
            \x20     IP:0.0.0.0/0.0.0.0\n";
        assert_eq!(parse_permitted_dns(text), vec!["sberbank.ru", "vtb.ru"]);
    }
}
