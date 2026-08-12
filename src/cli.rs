//! Command line surface.

use std::path::PathBuf;

use clap::{CommandFactory as _, FromArgMatches as _, Parser, Subcommand};

/// Help layout with clap's own English headings replaced.
///
/// The section titles clap prints around the derived text -- `Usage:`, `Options:`,
/// `Commands:`, the help and version blurbs -- are not part of any doc comment, so they
/// are overridden on the built [`clap::Command`] instead. Errors clap raises for a bad
/// invocation stay English; those strings are not exposed for replacement.
const HELP_TEMPLATE: &str = "\
{before-help}{about-with-newline}
Использование: {usage}

{all-args}{after-help}";

/// Returns the parsed command line, with clap's own text in Russian.
///
/// # Errors
/// Never returns: clap exits the process itself on a parse error or a help request.
pub fn parse() -> Cli {
    let matches = localize(Cli::command()).get_matches();
    // The derive guarantees the shape matches, so this cannot fail on real input.
    Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit())
}

/// Applies the Russian headings to a command and, recursively, its subcommands.
fn localize(cmd: clap::Command) -> clap::Command {
    // clap adds its own --help and --version while building, too late to relabel, so the
    // automatic ones are switched off and replaced with identically-behaving arguments.
    let has_version = cmd.get_version().is_some();
    let mut cmd = cmd
        .help_template(HELP_TEMPLATE)
        .subcommand_help_heading("Команды")
        .subcommand_value_name("КОМАНДА")
        .mut_args(|arg| arg.help_heading("Параметры"))
        // The generated `help` subcommand carries English text that cannot be replaced
        // before the command is built; `--help` covers the same ground.
        .disable_help_subcommand(true)
        .disable_help_flag(true)
        .disable_version_flag(true)
        .arg(
            clap::Arg::new("help")
                .short('h')
                .long("help")
                .action(clap::ArgAction::Help)
                .help("Показать справку")
                .help_heading("Параметры"),
        );

    if has_version {
        cmd = cmd.arg(
            clap::Arg::new("version")
                .short('V')
                .long("version")
                .action(clap::ArgAction::Version)
                .help("Показать версию")
                .help_heading("Параметры"),
        );
    }

    let names: Vec<String> = cmd
        .get_subcommands()
        .map(|s| s.get_name().to_owned())
        .collect();
    names
        .into_iter()
        .fold(cmd, |c, name| c.mut_subcommand(name, localize))
}

/// Кросс-сертификаты с ограничением имён для сторонних УЦ.
///
/// Доверие стороннему УЦ обычно позволяет ему ручаться за любое имя
/// хоста. Здесь это сужается: корневой сертификат УЦ переподписывается
/// локально созданным корневым сертификатом с расширением 
/// X.509 nameConstraints, и доверие выдаётся только локальному
/// корневому сертификату.
/// 
/// Для Firefox сертфикаты нужно устанавливать вручную через 
/// "Настройки" -> "Приватность и защита" -> "Безопасность подключения и ПО" ->
/// "Дополнительные настройки" -> "Сертификаты" -> "Управление сертификатами" ->
/// "Центры сертификации" -> кнопка "Импортировать..."
/// В первую очередь импортируем корневой сертификат: myroot.pem, установив
/// галочку на пункте "Доверять при идентификации веб-сайтов"
/// затем импортируем сертификат из папки constrained не устанавливая галочки.
/// 
/// Первый запуск, в таком порядке:
///
///   rucerts init                         создать локальный корневой сертификат
///   rucerts ca add <root.cer>            УЦ, который надо ограничить
///   rucerts domain add example.com       за что ему разрешено ручаться
///   rucerts verify                       проверить, прежде чем доверять
///
/// Затем установка: запустить install-certs.cmd либо install-certs.ps1
/// из PowerShell с -ExecutionPolicy Bypass.
///
/// Дальше используются команды domain и ca; каждая сама переподписывает
/// сертификаты и заново создаёт файлы для установки.
#[derive(Debug, Parser)]
#[command(name = "rucerts", version, about, verbatim_doc_comment)]
#[expect(
    clippy::doc_markdown,
    reason = "verbatim_doc_comment renders this as terminal help, so backticks and other \
              markdown would be shown to the user literally rather than formatted"
)]
pub struct Cli {
    /// Каталог рабочей области с roots/, constrained/ и rucerts.toml.
    #[arg(long, global = true)]
    pub dir: Option<PathBuf>,

    /// Не пересоздавать файлы для установки.
    #[arg(long, global = true)]
    pub no_artifacts: bool,

    /// Что сделать.
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
    /// 1. Создать локальный корневой сертификат и конфигурацию.
    Init {
        /// Common Name локального корня.
        #[arg(long, default_value = "!Root to bypass Russian certificates")]
        cn: String,
    },
    /// 2. Управление корневыми сертификатами УЦ.
    Ca {
        /// Операция с УЦ.
        #[command(subcommand)]
        action: CaAction,
    },
    /// 3. Управлять списком разрешённых доменов.
    Domain {
        /// Операция с доменами.
        #[command(subcommand)]
        action: DomainAction,
    },
    /// 4. Проверить созданные кросс-сертификаты.
    Verify,
    /// Переподписать все кросс-сертификаты, не меняя список доменов.
    Resign,
    /// Пересоздать файлы для установки без переподписи.
    Artifacts,
    /// Переименовать или заменить локальный корневой сертификат.
    Root {
        /// Операция с локальным корнем.
        #[command(subcommand)]
        action: RootAction,
    },
}

/// Operations on the permitted domain list.
#[derive(Debug, Subcommand)]
pub enum DomainAction {
    /// Добавить домены, затем переподписать и собрать файлы.
    Add {
        /// Домены, которые разрешить. Из вставленного URL берётся только хост.
        #[arg(required = true)]
        domains: Vec<String>,
    },
    /// Убрать домены, затем переподписать и собрать файлы.
    Remove {
        /// Домены, которые больше не разрешать. Удаляются только точные записи.
        #[arg(required = true)]
        domains: Vec<String>,
    },
    /// Показать разрешённые домены.
    List,
}

/// Operations on the foreign CA roots.
#[derive(Debug, Subcommand)]
pub enum CaAction {
    /// Добавить корень или сообщить, что его ключ уже под управлением.
    Add {
        /// Файлы сертификатов, PEM или DER.
        #[arg(required = true)]
        files: Vec<PathBuf>,
    },
    /// Показать управляемые корни с отпечатками их ключей.
    List,
    /// Перестать ограничивать корень, переместив его в roots/retired/.
    Retire {
        /// Имя, как его показывает `rucerts ca list`.
        name: String,
    },
}

/// Operations on the local root.
#[derive(Debug, Subcommand)]
pub enum RootAction {
    /// Создать новый локальный корень с указанным Common Name.
    ///
    /// Создаётся новая пара ключей; всё, что уже доверяет старому корню, придётся
    /// обновить.
    SetCn {
        /// Новый Common Name.
        cn: String,
        /// Не спрашивать подтверждение.
        #[arg(short = 'y', long)]
        yes: bool,
    },
}
