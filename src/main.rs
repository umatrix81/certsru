//! Command line entry point for `rucerts`.
//!
//! Every mutating command funnels through [`resign_and_stage`], so a certificate on disk
//! and the artifacts derived from it cannot drift apart.

mod cli;

use std::io::{self, Write as _};
use std::path::Path;

use anyhow::{Context, Result};
use clap::Parser as _;
use mimalloc::MiMalloc;

use rucerts::config::{Config, MAX_CN_BYTES};
use rucerts::roots::{self, Added};
use rucerts::stage;
use rucerts::verify;
use rucerts::workspace::Workspace;
use rucerts::x509::{
    cross_sign, fingerprint, generate_root, load_cert, load_key, pubkey_fingerprint, ski_hex,
    subject_cn,
};

use crate::cli::{CaAction, Cli, Command, DomainAction, RootAction};

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let dir = match cli.dir {
        Some(ref d) => d.clone(),
        None => std::env::current_dir().context("resolving current directory")?,
    };
    let ws = Workspace::new(&dir);

    match cli.command {
        Command::Init { ref cn } => init(&ws, cn),
        Command::Domain { ref action } => domain(&ws, action, cli.no_artifacts),
        Command::Ca { ref action } => ca(&ws, action, cli.no_artifacts),
        Command::Root { ref action } => root(&ws, action, cli.no_artifacts),
        Command::Resign => {
            let cfg = Config::load(ws.dir())?;
            resign_and_stage(&ws, &cfg, cli.no_artifacts)
        }
        Command::Artifacts => {
            let roots = roots::list(&ws)?;
            let staged = stage::stage(&ws, &roots)?;
            report_staged(&staged);
            Ok(())
        }
        Command::Verify => {
            let cfg = Config::load(ws.dir())?;
            let roots = roots::list(&ws)?;
            anyhow::ensure!(
                !roots.is_empty(),
                "no roots in roots/ -- add one with `rucerts ca add`"
            );
            let report = verify::run(&ws, &cfg, &roots)?;
            println!("\nResult");
            if report.failed == 0 {
                println!("  all {} checks passed", report.passed);
                Ok(())
            } else {
                anyhow::bail!(
                    "{} of {} checks failed",
                    report.failed,
                    report.passed + report.failed
                )
            }
        }
    }
}

/// Creates a local root and configuration in an empty workspace.
fn init(ws: &Workspace, cn: &str) -> Result<()> {
    anyhow::ensure!(
        !ws.root_cert().exists(),
        "{} already exists -- use `rucerts root set-cn` to replace it",
        ws.root_cert().display()
    );
    ws.ensure_dirs()?;

    let cfg = Config::new(Vec::new());
    cfg.save(ws.dir())?;

    let (cert, key) = generate_root(cn, cfg.signing.root_days)?;
    let advisory = write_root(ws, &cert, &key)?;

    println!("created {}", ws.root_cert().display());
    println!("  subject: {}", subject_cn(&cert).unwrap_or_default());
    println!("\nNext: `rucerts ca add <root.cer>` then `rucerts domain add <domain>`.");
    if let Some(note) = advisory {
        println!("\n{note}");
    }
    Ok(())
}

/// Writes the local root certificate and key, returning any permissions advisory.
fn write_root(
    ws: &Workspace,
    cert: &openssl::x509::X509,
    key: &openssl::pkey::PKey<openssl::pkey::Private>,
) -> Result<Option<String>> {
    std::fs::write(ws.root_cert(), cert.to_pem().context("encoding root")?)
        .with_context(|| format!("writing {}", ws.root_cert().display()))?;
    std::fs::write(
        ws.root_key(),
        key.private_key_to_pem_pkcs8().context("encoding key")?,
    )
    .with_context(|| format!("writing {}", ws.root_key().display()))?;
    restrict_key_permissions(&ws.root_key())
}

/// Restricts the private key to the owner, returning any advisory for the caller.
#[cfg(unix)]
fn restrict_key_permissions(path: &Path) -> Result<Option<String>> {
    use std::os::unix::fs::PermissionsExt as _;
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms)
        .with_context(|| format!("restricting {}", path.display()))?;
    Ok(None)
}

/// Reports that the private key inherits its directory's access control list.
///
/// Windows has no mode bits to set. Under `C:\Users\<you>\` the inherited ACL is already
/// owner-only, but a workspace on a shared drive would not be, and this key is what lets
/// its holder issue certificates for every permitted domain.
#[cfg(not(unix))]
fn restrict_key_permissions(path: &Path) -> Result<Option<String>> {
    // The account must be interpolated by PowerShell, not passed as the literal
    // %USERNAME%, which only cmd.exe expands. The subexpression form is required too:
    // "$env:USERNAME:F" parses the trailing :F as part of the variable path.
    //
    // Full control rather than read: the owner still has to be able to replace this file,
    // and `rucerts root set-cn` rewrites it. Removing inheritance is what makes it private.
    Ok(Some(format!(
        "note: {} inherits its folder's permissions. If this workspace is not somewhere \
         only you can read, restrict it in PowerShell with:\n      \
         icacls \"{}\" /inheritance:r /grant:r \"$($env:USERNAME):F\"",
        path.display(),
        path.display()
    )))
}

/// Handles `rucerts domain ...`.
fn domain(ws: &Workspace, action: &DomainAction, no_artifacts: bool) -> Result<()> {
    let mut cfg = Config::load(ws.dir())?;

    match action {
        DomainAction::List => {
            for d in &cfg.constraints.permitted_dns {
                println!("{d}");
            }
            return Ok(());
        }
        DomainAction::Add { domains } => {
            let mut changed = false;
            let mut hosts = Vec::new();

            // First pass adds everything. The SAN check has to wait until the whole batch
            // is in: checking as we go would warn about a name supplied later in the same
            // command line.
            for raw in domains {
                let host = host_of(raw);
                if cfg.covers(&host) {
                    println!("skip   {host} (already inside a permitted subtree)");
                } else {
                    cfg.constraints.permitted_dns.push(host.clone());
                    println!("add    {host}");
                    changed = true;
                }
                if !hosts.contains(&host) {
                    hosts.push(host);
                }
            }

            for host in &hosts {
                warn_uncovered_sans(&cfg, host);
            }

            if !changed {
                println!("no domains added");
                return stage_only(ws, no_artifacts);
            }
        }
        DomainAction::Remove { domains } => {
            let mut changed = false;
            for raw in domains {
                let host = host_of(raw);
                let Some(pos) = cfg
                    .constraints
                    .permitted_dns
                    .iter()
                    .position(|d| *d == host)
                else {
                    println!(
                        "skip   {host} (not an exact entry; remove the subtree parent by name)"
                    );
                    continue;
                };
                anyhow::ensure!(
                    cfg.constraints.permitted_dns.len() > 1,
                    "refusing to remove the last permitted domain -- the certificate would \
                     trust nothing, which reads as a broken chain rather than a policy"
                );
                cfg.constraints.permitted_dns.remove(pos);
                println!("remove {host}");
                changed = true;
            }
            if !changed {
                println!("nothing removed");
                return Ok(());
            }
        }
    }

    cfg.save(ws.dir())?;
    resign_and_stage(ws, &cfg, no_artifacts)?;
    println!("\nRemoval and addition take effect only after re-import; browsers keep the old");
    println!("certificates until then.");
    Ok(())
}

/// Warns about sibling SAN entries that the permitted list does not cover.
///
/// A leaf fails unless *every* SAN entry falls inside a permitted subtree, so adding
/// `sberbank.ru` alone is not enough when its certificate also carries `sbrf.ru`.
fn warn_uncovered_sans(cfg: &Config, host: &str) {
    let Ok(chain) = rucerts::probe::fetch(host) else {
        return;
    };
    for san in rucerts::probe::dns_names(&chain.leaf) {
        let base = san.strip_prefix("*.").unwrap_or(&san);
        if !cfg.covers(base) {
            println!("  WARNING: leaf also carries SAN '{san}' -- not covered, add it too");
        }
    }
}

/// Handles `rucerts ca ...`.
fn ca(ws: &Workspace, action: &CaAction, no_artifacts: bool) -> Result<()> {
    let cfg = Config::load(ws.dir())?;

    match action {
        CaAction::List => {
            let list = roots::list(ws)?;
            if list.is_empty() {
                println!("(none)");
            }
            for root in list {
                println!("{}", root.name);
                println!(
                    "    subject : {}",
                    subject_cn(&root.cert).unwrap_or_default()
                );
                println!("    expires : {}", root.cert.not_after());
                println!(
                    "    key     : {}...",
                    &pubkey_fingerprint(&root.cert)?[..32]
                );
                let cross = ws.cross_cert(&root.name);
                if cross.exists() {
                    let c = load_cert(&cross)?;
                    println!(
                        "    cross   : {} (expires {})",
                        cross.display(),
                        c.not_after()
                    );
                } else {
                    println!("    cross   : MISSING -- run `rucerts resign`");
                }
            }
            Ok(())
        }
        CaAction::Add { files } => {
            let mut changed = false;
            for file in files {
                match roots::add(ws, file)? {
                    Added::Renewal { existing } => {
                        println!("{}: same public key as {existing}", file.display());
                        println!(
                            "  -> The existing cross-certificate already covers this key. \
                             Nothing must be re-imported; chains keep validating even past \
                             the original's expiry."
                        );
                    }
                    Added::NewKey { name } => {
                        println!("{}: added as roots/{name}.cer", file.display());
                        // Only meaningful once a second root exists; on a fresh workspace
                        // this is simply the first one.
                        if roots::list(ws)?.len() > 1 {
                            println!(
                                "  A new key, kept alongside the existing root. Both stay \
                                 constrained; retire the old one once sites have migrated."
                            );
                        }
                        changed = true;
                    }
                }
            }
            if changed {
                resign_and_stage(ws, &cfg, no_artifacts)
            } else {
                stage_only(ws, no_artifacts)
            }
        }
        CaAction::Retire { name } => {
            roots::retire(ws, name)?;
            println!("retired {name} -> roots/retired/");
            resign_and_stage(ws, &cfg, no_artifacts)?;
            println!(
                "\nThe retired cross-certificate is still valid wherever it is installed. \
                 Run install-certs.ps1 to remove it."
            );
            Ok(())
        }
    }
}

/// Handles `rucerts root ...`.
fn root(ws: &Workspace, action: &RootAction, no_artifacts: bool) -> Result<()> {
    let RootAction::SetCn { cn, yes } = action;
    let cfg = Config::load(ws.dir())?;

    anyhow::ensure!(!cn.contains('/'), "common name must not contain '/'");
    anyhow::ensure!(
        !cn.contains('='),
        "common name must not contain '=' -- pass the name only, not a full DN"
    );
    anyhow::ensure!(
        cn.len() <= MAX_CN_BYTES,
        "common name is {} bytes; the X.509 upper bound is {MAX_CN_BYTES}",
        cn.len()
    );

    if ws.root_cert().exists() {
        let current = load_cert(&ws.root_cert())?;
        println!(
            "current root : {}",
            subject_cn(&current).unwrap_or_default()
        );
    }
    println!("new root     : {cn}");
    println!("\nThis mints a new key pair and re-signs every cross-certificate.");
    println!("Any trust store holding the old root must be updated.");

    if !yes && !confirm()? {
        anyhow::bail!("aborted");
    }

    let label = timestamp();
    let backup = ws.backup(&label, &[ws.root_key(), ws.root_cert()])?;
    println!("backed up -> {}", backup.display());

    let (cert, key) = generate_root(cn, cfg.signing.root_days)?;
    let advisory = write_root(ws, &cert, &key)?;

    resign_and_stage(ws, &cfg, no_artifacts)?;
    println!(
        "\nRe-import required. The OLD root is now orphaned; delete it wherever it was trusted."
    );
    if let Some(note) = advisory {
        println!("\n{note}");
    }
    Ok(())
}

/// Re-signs every cross-certificate, then regenerates the artifacts.
fn resign_and_stage(ws: &Workspace, cfg: &Config, no_artifacts: bool) -> Result<()> {
    let roots = roots::list(ws)?;
    anyhow::ensure!(
        !roots.is_empty(),
        "no certificates in roots/ -- add one with `rucerts ca add`"
    );

    // A fresh workspace has roots but no domains yet. Signing would fail on an empty
    // permitted list, so say what is missing instead of surfacing that as an error.
    if cfg.constraints.permitted_dns.is_empty() {
        println!("no permitted domains yet -- add one with `rucerts domain add <domain>`");
        return Ok(());
    }
    ws.ensure_dirs()?;

    let root_cert = load_cert(&ws.root_cert())?;
    let root_key = load_key(&ws.root_key())?;

    for root in &roots {
        let cross = cross_sign(
            &root_cert,
            &root_key,
            &root.cert,
            &cfg.constraints,
            cfg.signing.cross_days,
            cfg.signing.path_len,
        )?;

        // Fatal, never a warning: a changed SKI means sub-CA authorityKeyIdentifier no
        // longer resolves and chains silently fail to build.
        let (before, after) = (ski_hex(&root.cert), ski_hex(&cross));
        anyhow::ensure!(
            before == after,
            "SKI changed for {} ({:?} -> {:?}) -- chain building would break",
            root.name,
            before,
            after
        );

        let path = ws.cross_cert(&root.name);
        std::fs::write(&path, cross.to_pem().context("encoding cross-certificate")?)
            .with_context(|| format!("writing {}", path.display()))?;
        println!(
            "signed {}\n(SKI {})",
            path.display(),
            after.unwrap_or_default()
        );
    }

    stage_only(ws, no_artifacts)
}

/// Regenerates the installable artifacts in the workspace.
fn stage_only(ws: &Workspace, no_artifacts: bool) -> Result<()> {
    if no_artifacts {
        println!("artifacts not regenerated (--no-artifacts)");
        return Ok(());
    }
    let roots = roots::list(ws)?;
    let staged = stage::stage(ws, &roots)?;
    report_staged(&staged);
    Ok(())
}

/// Prints what a generation run produced.
fn report_staged(staged: &stage::Staged) {
    println!(
        "wrote artifacts for {} root(s), domains: {}",
        staged.roots,
        staged.domains.join(", ")
    );
    println!("  in {}", staged.dir.display());
    println!("\nRe-import in whichever store you use:");
    println!("  certmgr.msc : run install-certs.ps1 again (it replaces old copies)");
    println!("  policy      : re-run constrained-ca-policy.reg as admin, restart Chrome/Edge");
    println!("  Firefox     : delete the old certs under Authorities, import with NO trust bits");
}

/// Reduces a pasted URL to its host.
fn host_of(raw: &str) -> String {
    let without_scheme = raw.split_once("://").map_or(raw, |(_, rest)| rest);
    without_scheme
        .split('/')
        .next()
        .unwrap_or(without_scheme)
        .to_owned()
}

/// Asks for confirmation on standard input, defaulting to no.
fn confirm() -> Result<bool> {
    print!("Proceed? [y/N] ");
    io::stdout().flush().context("flushing prompt")?;
    let mut line = String::new();
    io::stdin().read_line(&mut line).context("reading reply")?;
    Ok(matches!(
        line.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

/// Returns a filesystem-safe timestamp for backup directory names.
fn timestamp() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    format!("{secs}")
}

/// Prints a certificate fingerprint. Retained for diagnostics from other commands.
#[expect(dead_code, reason = "used by ad-hoc debugging and kept deliberately")]
fn print_fingerprint(cert: &openssl::x509::X509) -> Result<()> {
    println!("{}", fingerprint(cert)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::host_of;

    #[test]
    fn urls_are_reduced_to_their_host() {
        assert_eq!(host_of("sberbank.ru"), "sberbank.ru");
        assert_eq!(host_of("https://sberbank.ru/some/path"), "sberbank.ru");
        assert_eq!(host_of("http://psb.ru"), "psb.ru");
    }
}
