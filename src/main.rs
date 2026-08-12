//! Command line entry point for `rucerts`.
//!
//! Every mutating command funnels through [`resign_and_stage`], so a certificate on disk
//! and the artifacts derived from it cannot drift apart.

mod cli;

use std::io::{self, Write as _};
use std::path::Path;

use anyhow::{Context, Result};
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

use crate::cli::{CaAction, Command, DomainAction, RootAction};

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

fn main() {
    if let Err(err) = run() {
        eprintln!("ошибка: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = cli::parse();
    let dir = match cli.dir {
        Some(ref d) => d.clone(),
        None => std::env::current_dir().context("определение текущего каталога")?,
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
                "в roots/ нет корневых сертификатов -- добавьте командой `rucerts ca add`\n"
            );
            let report = verify::run(&ws, &cfg, &roots)?;
            println!("\nИтог");
            if report.failed == 0 {
                println!("  все проверки пройдены: {}", report.passed);
                Ok(())
            } else {
                anyhow::bail!(
                    "не пройдено проверок: {} из {}",
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
        "{} уже существует -- замените его командой `rucerts root set-cn`",
        ws.root_cert().display()
    );
    ws.ensure_dirs()?;

    let cfg = Config::new(Vec::new());
    cfg.save(ws.dir())?;

    let (cert, key) = generate_root(cn, cfg.signing.root_days)?;
    let advisory = write_root(ws, &cert, &key)?;

    println!("создан {}", ws.root_cert().display());
    println!("CN: {}", subject_cn(&cert).unwrap_or_default());
    println!("\nДалее:\n `rucerts ca add <root.cer>`,\n затем\n `rucerts domain add <домен>`.");
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
    std::fs::write(
        ws.root_cert(),
        cert.to_pem().context("генерация корневого сертификата")?,
    )
    .with_context(|| format!("запись {}", ws.root_cert().display()))?;
    std::fs::write(
        ws.root_key(),
        key.private_key_to_pem_pkcs8().context("генерация ключа")?,
    )
    .with_context(|| format!("запись {}", ws.root_key().display()))?;
    restrict_key_permissions(&ws.root_key())
}

/// Restricts the private key to the owner, returning any advisory for the caller.
#[cfg(unix)]
fn restrict_key_permissions(path: &Path) -> Result<Option<String>> {
    use std::os::unix::fs::PermissionsExt as _;
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms)
        .with_context(|| format!("ограничение доступа к {}", path.display()))?;
    Ok(None)
}

/// Reports that the private key inherits its directory's access control list.
///
/// Windows has no mode bits to set. Under `C:\Users\<you>\` the inherited ACL is already
/// owner-only, but a workspace on a shared drive would not be, and this key is what lets
/// its holder issue certificates for every permitted domain.
#[cfg(not(unix))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "this variant cannot fail, but its signature has to match the unix one, \
              which can: std::fs::set_permissions returns a Result"
)]
fn restrict_key_permissions(path: &Path) -> Result<Option<String>> {
    // The account must be interpolated by PowerShell, not passed as the literal
    // %USERNAME%, which only cmd.exe expands. The subexpression form is required too:
    // "$env:USERNAME:F" parses the trailing :F as part of the variable path.
    //
    // Full control rather than read: the owner still has to be able to replace this file,
    // and `rucerts root set-cn` rewrites it. Removing inheritance is what makes it private.
    Ok(Some(format!(
        "примечание: {} наследует права своей папки. Если к папке имеете доступ, \
         не только вы, ограничьте доступ в PowerShell:\n   \
         icacls \"{}\" /inheritance:r /grant:r \"$($env:USERNAME):F\"\n",
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
                    println!("пропуск  {host} (уже в списке разрешенных)");
                } else {
                    cfg.constraints.permitted_dns.push(host.clone());
                    println!("добавлен {host}");
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
                println!("домены не добавлены");
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
                        "пропуск  {host} (нет такой точной записи; удалите родителя поддерева по имени)"
                    );
                    continue;
                };
                anyhow::ensure!(
                    cfg.constraints.permitted_dns.len() > 1,
                    "отказ удалить последний разрешённый домен -- сертификат не доверял бы \
                     ничему, а это выглядит как сломанная цепочка, а не как политика"
                );
                cfg.constraints.permitted_dns.remove(pos);
                println!("удалён   {host}");
                changed = true;
            }
            if !changed {
                println!("ничего не удалено");
                return Ok(());
            }
        }
    }

    cfg.save(ws.dir())?;
    resign_and_stage(ws, &cfg, no_artifacts)?;
    println!("\nДобавление и удаление вступают в силу только после повторного импорта;");
    println!("до этого браузеры используют старые сертификаты.\n");
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
            println!("  ВНИМАНИЕ: в конечном сертификате есть SAN '{san}' -- он не покрыт, добавьте и его");
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
                println!("(нет)");
            }
            for root in list {
                println!("{}", root.name);
                println!(
                    "    CN       : {}",
                    subject_cn(&root.cert).unwrap_or_default()
                );
                println!("    истекает : {}", root.cert.not_after());
                println!(
                    "    ключ     : {}...",
                    &pubkey_fingerprint(&root.cert)?[..32]
                );
                let cross = ws.cross_cert(&root.name);
                if cross.exists() {
                    let c = load_cert(&cross)?;
                    println!(
                        "    кросс    : {} (истекает {})",
                        cross.display(),
                        c.not_after()
                    );
                } else {
                    println!("    кросс    : ОТСУТСТВУЕТ -- выполните `rucerts resign`");
                }
            }
            Ok(())
        }
        CaAction::Add { files } => {
            let mut changed = false;
            for file in files {
                match roots::add(ws, file)? {
                    Added::Renewal { existing } => {
                        println!(
                            "{}: тот же открытый ключ, что и у {existing}",
                            file.display()
                        );
                        println!(
                            "  -> Существующий кросс-сертификат уже покрывает этот ключ. \
                             Переимпортировать ничего не нужно; цепочки продолжат проверяться \
                             и после истечения оригинала."
                        );
                    }
                    Added::NewKey { name } => {
                        println!("{}: добавлен как roots/{name}.cer", file.display());
                        // Only meaningful once a second root exists; on a fresh workspace
                        // this is simply the first one.
                        if roots::list(ws)?.len() > 1 {
                            println!(
                                "  Новый ключ, оставлен рядом с существующим корнем. Оба \
                                 остаются ограниченными; выведите старый из обращения, \
                                 когда сайты перейдут на новый."
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
            println!("выведен из обращения {name} -> roots/retired/");
            resign_and_stage(ws, &cfg, no_artifacts)?;
            println!(
                "\nВыведенный кросс-сертификат остаётся действительным везде, где он \
                 установлен. Запустите install-certs.ps1, чтобы удалить его."
            );
            Ok(())
        }
    }
}

/// Handles `rucerts root ...`.
fn root(ws: &Workspace, action: &RootAction, no_artifacts: bool) -> Result<()> {
    let RootAction::SetCn { cn, yes } = action;
    let cfg = Config::load(ws.dir())?;

    anyhow::ensure!(!cn.contains('/'), "common name не должен содержать '/'");
    anyhow::ensure!(
        !cn.contains('='),
        "common name не должен содержать '=' -- передайте только имя, а не полный DN"
    );
    anyhow::ensure!(
        cn.len() <= MAX_CN_BYTES,
        "длина common name -- {} байт; предел X.509 -- {MAX_CN_BYTES}",
        cn.len()
    );

    if ws.root_cert().exists() {
        let current = load_cert(&ws.root_cert())?;
        println!(
            "текущий корневой сертификат : {}",
            subject_cn(&current).unwrap_or_default()
        );
    }
    println!("новый корневой сертификат   : {cn}");
    println!("\nБудет создана новая пара ключей и переподписаны все кросс-сертификаты.");
    println!("Все хранилища доверия со старым корневым сертификатом придётся обновить.");

    if !yes && !confirm()? {
        anyhow::bail!("отменено");
    }

    let label = timestamp();
    let backup = ws.backup(&label, &[ws.root_key(), ws.root_cert()])?;
    println!("резервная копия -> {}", backup.display());

    let (cert, key) = generate_root(cn, cfg.signing.root_days)?;
    let advisory = write_root(ws, &cert, &key)?;

    resign_and_stage(ws, &cfg, no_artifacts)?;
    println!(
        "\nНужен повторный импорт. СТАРЫЙ корневой сертификат теперь ни к чему не привязан; удалите его \
         везде, где он был доверенным."
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
        "в roots/ нет сертификатов -- добавьте командой `rucerts ca add`\n"
    );

    // A fresh workspace has roots but no domains yet. Signing would fail on an empty
    // permitted list, so say what is missing instead of surfacing that as an error.
    if cfg.constraints.permitted_dns.is_empty() {
        println!("\nразрешённых доменов пока нет -- добавьте командой `rucerts domain add <домен>`\n");
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
            "SKI изменился у {} ({:?} -> {:?}) -- построение цепочки сломается",
            root.name,
            before,
            after
        );

        let path = ws.cross_cert(&root.name);
        std::fs::write(
            &path,
            cross.to_pem().context("кодирование кросс-сертификата")?,
        )
        .with_context(|| format!("запись {}", path.display()))?;
        println!(
            "\nподписан {}\n(SKI {})",
            path.display(),
            after.unwrap_or_default()
        );
    }

    stage_only(ws, no_artifacts)
}

/// Regenerates the installable artifacts in the workspace.
fn stage_only(ws: &Workspace, no_artifacts: bool) -> Result<()> {
    if no_artifacts {
        println!("файлы для установки не пересоздавались (--no-artifacts)");
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
        "\nсозданы файлы для установки, корневых сертификатов: {}, домены: {}",
        staged.roots,
        staged.domains.join(", ")
    );
    println!("в {}", staged.dir.display());
    println!("\nИмпорт сертификатов:");
    println!("  certmgr.msc : запустите install-certs.ps1 ещё раз (он заменит старые копии)");
    println!(
        "  политика    : выполните constrained-ca-policy.reg от админа, перезапустите Chrome/Edge"
    );
    println!("  Firefox     : удалите старые сертификаты в «Центры сертификации», импортируйте БЕЗ флагов доверия");
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
///
/// Both the Latin and the Cyrillic affirmative are accepted: the prompt is Russian, but
/// `y` is what a keyboard left on the English layout produces.
fn confirm() -> Result<bool> {
    print!("Продолжить? [y/N] ");
    io::stdout().flush().context("вывод приглашения")?;
    let mut line = String::new();
    io::stdin().read_line(&mut line).context("чтение ответа")?;
    Ok(matches!(
        line.trim().to_lowercase().as_str(),
        "y" | "yes" | "д" | "да"
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
