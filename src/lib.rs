//! Manage name-constrained cross-certificates for third-party CAs.
//!
//! Trusting a third-party CA normally lets it vouch for any hostname. This crate narrows
//! that: a foreign self-signed root is re-issued under a locally generated root with an
//! X.509 `nameConstraints` extension attached, and only the local root is trusted. Chains
//! from the foreign CA then validate for the permitted domains and fail everywhere else.
//!
//! The workspace on disk holds `roots/` (foreign roots), `constrained/` (one
//! cross-certificate each), the local root, and `rucerts.toml`.

pub mod config;
pub mod probe;
pub mod roots;
pub mod stage;
pub mod verify;
pub mod workspace;
pub mod x509;
