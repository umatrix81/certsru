//! Fetches the certificate chain a TLS server presents.
//!
//! Used by the audit to test real chains rather than synthetic ones. Server verification is
//! deliberately disabled: the chain is being *collected* for inspection, not trusted. The
//! constrained root is not in any store this process consults, so verifying here would
//! reject exactly the chains worth examining.

use std::io::{Read as _, Write as _};
use std::net::{TcpStream, ToSocketAddrs as _};
use std::time::Duration;

use anyhow::{Context, Result};
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use openssl::x509::X509;

/// How long to wait for a probe to connect and complete its handshake.
///
/// Short enough that a handful of unreachable hosts do not stall an audit, long enough for
/// a TLS handshake over a slow link.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(12);

/// Default TLS port.
const HTTPS_PORT: u16 = 443;

/// A chain as presented by a server.
#[derive(Debug)]
pub struct Chain {
    /// The server's own certificate.
    pub leaf: X509,
    /// Intermediates sent alongside it, in the order received.
    pub intermediates: Vec<X509>,
}

/// Connects to `host` and returns the chain it presents.
///
/// # Errors
/// If the host does not resolve, the connection times out, the handshake fails, or the
/// server sends no certificate.
pub fn fetch(host: &str) -> Result<Chain> {
    let addr = format!("{host}:{HTTPS_PORT}")
        .to_socket_addrs()
        .with_context(|| format!("resolving {host}"))?
        .next()
        .with_context(|| format!("{host} resolved to no addresses"))?;

    let stream = TcpStream::connect_timeout(&addr, PROBE_TIMEOUT)
        .with_context(|| format!("connecting to {host}"))?;
    stream.set_read_timeout(Some(PROBE_TIMEOUT))?;
    stream.set_write_timeout(Some(PROBE_TIMEOUT))?;

    let mut builder = SslConnector::builder(SslMethod::tls()).context("building TLS connector")?;
    // Collecting, not trusting -- see the module documentation.
    builder.set_verify(SslVerifyMode::NONE);
    let connector = builder.build();

    let mut tls = connector
        .configure()
        .context("configuring TLS")?
        // The server needs SNI to pick the right certificate; without it many hosts
        // return a default certificate for an unrelated name.
        .verify_hostname(false)
        .connect(host, stream)
        .with_context(|| format!("TLS handshake with {host}"))?;

    let leaf = tls
        .ssl()
        .peer_certificate()
        .with_context(|| format!("{host} sent no certificate"))?;
    let intermediates = tls
        .ssl()
        .peer_cert_chain()
        .map(|chain| {
            chain
                .iter()
                // The peer chain repeats the leaf in position zero.
                .skip(1)
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    // Politely end the session; failures here do not affect the collected chain.
    let _ = tls.write_all(b"");
    let _ = tls.read(&mut [0_u8; 0]);
    let _ = tls.shutdown();

    Ok(Chain {
        leaf,
        intermediates,
    })
}

/// Returns the DNS names in a certificate's subjectAltName extension.
pub fn dns_names(cert: &X509) -> Vec<String> {
    cert.subject_alt_names()
        .map(|names| {
            names
                .iter()
                .filter_map(|n| n.dnsname().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}
