//! Tool configuration held in `rucerts.toml`.
//!
//! Replaces the `[nc]` section of the old `cross.cnf`. The permitted-domain list is the
//! single input that shapes every generated cross-certificate, so it is kept in a typed
//! form rather than edited line-wise. Legacy `cross.cnf` files are migrated on load.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Validity of a generated cross-certificate.
///
/// Chosen to outlive the Ministry root's own expiry (2032-02-27) without exceeding it by
/// much: a cross-certificate that outlives the key it vouches for only creates confusion.
pub const DEFAULT_CROSS_DAYS: u32 = 2000;

/// Validity of a generated local root, in days.
pub const DEFAULT_ROOT_DAYS: u32 = 3650;

/// `pathLenConstraint` placed on the cross-certificate.
///
/// One intermediate (the CA's own sub-CA) plus a leaf. Tighter than the originals, which
/// ship `pathlen:4`, and enough for every chain observed from these CAs.
pub const DEFAULT_PATH_LEN: u32 = 1;

/// Upper bound on a Common Name, in bytes, from RFC 5280 `ub-common-name`.
///
/// Counted in bytes, not characters: Cyrillic costs two bytes per character in UTF-8.
pub const MAX_CN_BYTES: usize = 64;

/// Complete tool configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Name constraints applied to every cross-certificate.
    pub constraints: Constraints,
    /// Signing parameters.
    #[serde(default)]
    pub signing: Signing,
}

/// Name constraints applied to every cross-certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constraints {
    /// Permitted DNS subtrees. A name here also covers all of its subdomains.
    pub permitted_dns: Vec<String>,
    /// Exclude every IPv4 and IPv6 address.
    #[serde(default = "yes")]
    pub exclude_ip: bool,
    /// Exclude every rfc822 (email) name.
    #[serde(default = "yes")]
    pub exclude_email: bool,
    /// Exclude every URI name.
    #[serde(default = "yes")]
    pub exclude_uri: bool,
}

/// Signing parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signing {
    /// Validity of a generated cross-certificate, in days.
    #[serde(default = "default_cross_days")]
    pub cross_days: u32,
    /// Validity of a generated local root, in days.
    #[serde(default = "default_root_days")]
    pub root_days: u32,
    /// `pathLenConstraint` placed on the cross-certificate.
    #[serde(default = "default_path_len")]
    pub path_len: u32,
}

const fn yes() -> bool {
    true
}
const fn default_cross_days() -> u32 {
    DEFAULT_CROSS_DAYS
}
const fn default_root_days() -> u32 {
    DEFAULT_ROOT_DAYS
}
const fn default_path_len() -> u32 {
    DEFAULT_PATH_LEN
}

impl Default for Signing {
    fn default() -> Self {
        Self {
            cross_days: DEFAULT_CROSS_DAYS,
            root_days: DEFAULT_ROOT_DAYS,
            path_len: DEFAULT_PATH_LEN,
        }
    }
}

impl Config {
    /// Creates a configuration with the given permitted domains and all defaults.
    pub fn new(permitted_dns: Vec<String>) -> Self {
        Self {
            constraints: Constraints {
                permitted_dns,
                exclude_ip: true,
                exclude_email: true,
                exclude_uri: true,
            },
            signing: Signing::default(),
        }
    }

    /// Loads `rucerts.toml`, migrating older configuration formats when found.
    ///
    /// Two legacy names are accepted and rewritten on load: `certsru.toml` from before the
    /// tool was renamed, and the `[nc]` section of the shell implementation's `cross.cnf`.
    ///
    /// # Errors
    /// If no configuration exists, or the TOML is malformed.
    pub fn load(dir: &Path) -> Result<Self> {
        let toml_path = dir.join("rucerts.toml");
        if toml_path.exists() {
            let text = fs::read_to_string(&toml_path)
                .with_context(|| format!("reading {}", toml_path.display()))?;
            return toml::from_str(&text)
                .with_context(|| format!("parsing {}", toml_path.display()));
        }

        let renamed = dir.join("certsru.toml");
        if renamed.exists() {
            let text = fs::read_to_string(&renamed)
                .with_context(|| format!("reading {}", renamed.display()))?;
            let cfg: Self = toml::from_str(&text)
                .with_context(|| format!("parsing {}", renamed.display()))?;
            cfg.save(dir)?;
            fs::remove_file(&renamed)
                .with_context(|| format!("removing {}", renamed.display()))?;
            eprintln!("migrated certsru.toml -> rucerts.toml");
            return Ok(cfg);
        }

        let cnf_path = dir.join("cross.cnf");
        if cnf_path.exists() {
            let text = fs::read_to_string(&cnf_path)
                .with_context(|| format!("reading {}", cnf_path.display()))?;
            let cfg = Self::new(parse_cross_cnf(&text));
            cfg.save(dir)?;
            eprintln!("migrated cross.cnf -> rucerts.toml");
            return Ok(cfg);
        }

        anyhow::bail!(
            "no rucerts.toml in {} -- run `rucerts init` first",
            dir.display()
        )
    }

    /// Writes `rucerts.toml`.
    ///
    /// # Errors
    /// If the file cannot be written.
    pub fn save(&self, dir: &Path) -> Result<()> {
        let path = dir.join("rucerts.toml");
        let text = toml::to_string_pretty(self).context("serialising config")?;
        fs::write(&path, text).with_context(|| format!("writing {}", path.display()))
    }

    /// Returns true when `name` falls inside an already-permitted subtree.
    ///
    /// A permitted `psbank.ru` covers `www.psbank.ru`, matching RFC 5280 subtree semantics.
    pub fn covers(&self, name: &str) -> bool {
        self.constraints
            .permitted_dns
            .iter()
            .any(|p| name == p || name.ends_with(&format!(".{p}")))
    }
}

/// Extracts permitted DNS names from a legacy `cross.cnf`.
fn parse_cross_cnf(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            let rest = line.strip_prefix("permitted;DNS")?;
            // Keys are `permitted;DNS.<n>`; the suffix only makes them unique.
            let (_, value) = rest.split_once('=')?;
            Some(value.trim().to_owned())
        })
        .filter(|v| !v.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrates_permitted_names_ignoring_index_gaps() {
        let cnf = "\
[nc]
permitted;DNS.1  = sberbank.ru
permitted;DNS.2  = sbrf.ru
permitted;DNS.6  = alfabank.ru
excluded;IP.0    = 0.0.0.0/0.0.0.0
excluded;email.0 = .
";
        assert_eq!(
            parse_cross_cnf(cnf),
            vec!["sberbank.ru", "sbrf.ru", "alfabank.ru"]
        );
    }

    #[test]
    fn subtree_coverage_matches_rfc5280_semantics() {
        let cfg = Config::new(vec!["psbank.ru".to_owned()]);
        assert!(cfg.covers("psbank.ru"));
        assert!(cfg.covers("www.psbank.ru"));
        assert!(cfg.covers("a.b.psbank.ru"));
        // Suffix match must not be a substring match.
        assert!(!cfg.covers("notpsbank.ru"));
        assert!(!cfg.covers("psbank.ru.evil.com"));
    }
}
