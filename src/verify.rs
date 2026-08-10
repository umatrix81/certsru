//! Audits the generated cross-certificates.
//!
//! Four checks, of which only the third proves anything:
//!
//! 1. Inspection: constraints present and critical, SKI preserved, issuer correct, and
//!    every cross-certificate permitting the same list.
//! 2. Positive control: real leaves from permitted domains still validate.
//! 3. **Negative control**: the same real leaf is rejected once its names are removed from
//!    the permitted list, with `permitted subtree violation` specifically.
//! 4. Competing trust paths: the unconstrained originals must not be trusted anywhere.
//!
//! Without step 3 a certificate permitting *everything* looks identical to a working one:
//! every leaf validates, every extension is present, and nothing is actually constrained.

use anyhow::{Context, Result};
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::{X509StoreContext, X509};

use crate::config::Config;
use crate::probe;
use crate::roots::ForeignRoot;
use crate::workspace::Workspace;
use crate::x509::{cross_sign, load_cert, load_key, permitted_dns, ski_hex};

/// Outcome of one audit run.
#[derive(Debug, Default)]
pub struct Report {
    /// Checks that passed.
    pub passed: usize,
    /// Checks that failed.
    pub failed: usize,
}

impl Report {
    fn pass(&mut self, message: &str) {
        self.passed += 1;
        println!("  PASS {message}");
    }

    fn fail(&mut self, message: &str) {
        self.failed += 1;
        println!("  FAIL {message}");
    }

    #[expect(
        clippy::unused_self,
        reason = "kept a method for symmetry with pass/fail at call sites"
    )]
    fn skip(&self, message: &str) {
        println!("  skip {message}");
    }
}

/// Runs the full audit.
///
/// # Errors
/// If the workspace cannot be read. Individual check failures are recorded in the report
/// rather than returned, so one failure does not hide the others.
pub fn run(ws: &Workspace, cfg: &Config, roots: &[ForeignRoot]) -> Result<Report> {
    let mut report = Report::default();
    let root_cert = load_cert(&ws.root_cert())?;

    println!("\n1. Cross-certificates and what they permit");
    let (bundle, permitted) = inspect(ws, roots, &root_cert, &mut report)?;

    println!("\n2. Positive control -- permitted domains that use these CAs");
    let probe_material = positive_control(&root_cert, &bundle, &permitted, &mut report)?;

    println!("\n3. Negative control -- same leaf, names removed from the constraint");
    if let Some((leaf, intermediate)) = probe_material {
        negative_control(
            ws,
            cfg,
            roots,
            &root_cert,
            &leaf,
            &intermediate,
            &mut report,
        )?;
    } else {
        report.skip("no reachable domain used these CAs, cannot run the negative control");
        println!(
            "        Without this step the audit is incomplete: an over-permissive \
             certificate still passes everything above."
        );
    }

    println!("\n4. Competing trust paths for the original roots");
    for root in roots {
        let name = crate::x509::subject_cn(&root.cert).unwrap_or_else(|| root.name.clone());
        println!(
            "  '{name}' SHA256 {}",
            crate::x509::fingerprint(&root.cert)?
        );
    }
    println!("  Windows stores: run install-certs.ps1 -- it scans CurrentUser and LocalMachine");
    println!("  Firefox: about:preferences#privacy > View Certificates > Authorities");

    Ok(report)
}

/// Checks each cross-certificate's extensions, returning the chain bundle and the list.
fn inspect(
    ws: &Workspace,
    roots: &[ForeignRoot],
    root_cert: &X509,
    report: &mut Report,
) -> Result<(Vec<X509>, Vec<String>)> {
    let mut bundle = Vec::new();
    let mut reference: Option<Vec<String>> = None;

    for root in roots {
        let path = ws.cross_cert(&root.name);
        if !path.exists() {
            report.fail(&format!("{} has no cross-certificate", root.name));
            continue;
        }
        let cross = load_cert(&path)?;

        let text = String::from_utf8(cross.to_text().context("rendering certificate")?)
            .context("certificate text was not UTF-8")?;
        if text.contains("X509v3 Name Constraints: critical") {
            report.pass(&format!("{} constraints present and critical", root.name));
        } else {
            report.fail(&format!(
                "{} constraints missing or not critical -- a verifier that ignores them \
                 would accept anything",
                root.name
            ));
        }

        if ski_hex(&cross) == ski_hex(&root.cert) {
            report.pass(&format!("{} SKI matches the original root", root.name));
        } else {
            report.fail(&format!(
                "{} SKI differs -- sub-CA authorityKeyIdentifier will not match",
                root.name
            ));
        }

        let issuer = cross.issuer_name().to_der().context("issuer DN")?;
        let subject = root_cert.subject_name().to_der().context("subject DN")?;
        if issuer == subject {
            report.pass(&format!("{} issued by the local root", root.name));
        } else {
            report.fail(&format!("{} is not issued by myroot.pem", root.name));
        }

        let permitted = permitted_dns(&cross)?;
        match &reference {
            None => {
                println!("  permitted: {}", permitted.join(", "));
                report.pass(&format!("{} permits {} names", root.name, permitted.len()));
                reference = Some(permitted);
            }
            Some(first) if *first == permitted => {
                report.pass(&format!(
                    "{} permits the same list as the others",
                    root.name
                ));
            }
            Some(_) => report.fail(&format!(
                "{} permits a different list -- the effective policy is their union",
                root.name
            )),
        }
        bundle.push(cross);
    }

    Ok((bundle, reference.unwrap_or_default()))
}

/// Validates real leaves, returning the first that chained through our certificates.
fn positive_control(
    root_cert: &X509,
    bundle: &[X509],
    permitted: &[String],
    report: &mut Report,
) -> Result<Option<(X509, X509)>> {
    let mut material = None;

    for domain in permitted {
        let Ok(chain) = probe::fetch(domain) else {
            report.skip(&format!("{domain} (unreachable)"));
            continue;
        };
        let Some(intermediate) = chain.intermediates.first().cloned() else {
            report.skip(&format!("{domain} (server sent no intermediate)"));
            continue;
        };

        let mut untrusted = bundle.to_vec();
        untrusted.push(intermediate.clone());

        match verify_chain(root_cert, &untrusted, &chain.leaf)? {
            Verdict::Valid => {
                report.pass(&format!("{domain} validates through the constrained chain"));
                if material.is_none() {
                    material = Some((chain.leaf.clone(), intermediate));
                }
            }
            Verdict::Rejected(reason) => {
                let issuer = crate::x509::subject_cn(&intermediate).unwrap_or_default();
                report.skip(&format!(
                    "{domain} (chains to a CA we do not constrain: {issuer}; {reason})"
                ));
            }
        }
    }
    Ok(material)
}

/// Re-signs with the probe leaf's names removed and asserts the leaf is now rejected.
fn negative_control(
    ws: &Workspace,
    cfg: &Config,
    roots: &[ForeignRoot],
    root_cert: &X509,
    leaf: &X509,
    intermediate: &X509,
    report: &mut Report,
) -> Result<()> {
    let key = load_key(&ws.root_key())?;

    // Every SAN of the probe leaf must be uncovered, or a sibling name lets it through.
    let leaf_names = probe::dns_names(leaf);
    let mut narrowed = cfg.constraints.clone();
    narrowed.permitted_dns.retain(|permitted| {
        !leaf_names.iter().any(|san| {
            let base = san.strip_prefix("*.").unwrap_or(san);
            base == permitted || base.ends_with(&format!(".{permitted}"))
        })
    });

    if narrowed.permitted_dns.is_empty() {
        // A cross-certificate permitting nothing is rejected for a different reason, which
        // would not prove the constraint works. Substitute a name the leaf cannot match.
        narrowed
            .permitted_dns
            .push("negative-control.invalid".to_owned());
    }

    let mut untrusted = Vec::new();
    for root in roots {
        untrusted.push(cross_sign(
            root_cert,
            &key,
            &root.cert,
            &narrowed,
            cfg.signing.cross_days,
            cfg.signing.path_len,
        )?);
    }
    untrusted.push(intermediate.clone());

    match verify_chain(root_cert, &untrusted, leaf)? {
        Verdict::Rejected(reason) if reason.contains("permitted subtree violation") => {
            report.pass(&format!("leaf rejected: {reason}"));
            println!("        => constraints are enforced, not merely present");
        }
        Verdict::Rejected(reason) => report.fail(&format!(
            "leaf was rejected, but for the wrong reason: {reason}. The constraint may not \
             be what stopped it."
        )),
        Verdict::Valid => report
            .fail("leaf still accepted with its names removed -- constraints are NOT enforced"),
    }
    Ok(())
}

/// Result of a chain validation.
#[derive(Debug)]
enum Verdict {
    /// The chain validated.
    Valid,
    /// The chain was rejected, with OpenSSL's reason.
    Rejected(String),
}

/// Validates `leaf` against `anchor`, using `untrusted` as the candidate chain.
fn verify_chain(anchor: &X509, untrusted: &[X509], leaf: &X509) -> Result<Verdict> {
    let mut builder = X509StoreBuilder::new().context("building certificate store")?;
    builder
        .add_cert(anchor.clone())
        .context("adding trust anchor")?;
    let store = builder.build();

    let mut stack = Stack::new().context("building chain stack")?;
    for cert in untrusted {
        stack.push(cert.clone()).context("pushing chain entry")?;
    }

    let mut ctx = X509StoreContext::new().context("creating verification context")?;
    let outcome = ctx
        .init(&store, leaf, &stack, |c| {
            let ok = c.verify_cert()?;
            Ok((ok, c.error().error_string().to_owned()))
        })
        .context("verifying chain")?;

    Ok(if outcome.0 {
        Verdict::Valid
    } else {
        Verdict::Rejected(outcome.1)
    })
}
