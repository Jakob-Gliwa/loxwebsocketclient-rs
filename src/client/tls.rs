//! Certificate verification policy for HTTPS / WSS connections.
//!
//! Loxone Miniservers are usually reached by IP address while their CloudDNS
//! certificate is issued for `{ip}.{snr}.dyndns.loxonecloud.com`, so plain
//! WebPKI verification fails for most local deployments. [`TlsMode`] therefore
//! offers SPKI pinning as a middle ground between full verification and
//! disabling it.
//!
//! # Security caveats
//!
//! * [`TlsMode::PinOnFirstUse`] is *trust on first use*. The pin is learned
//!   either from the first TLS handshake or from `jdev/sys/getcertificate`,
//!   both of which are unauthenticated at that point. An attacker who is in
//!   position during the very first connect can therefore have their own key
//!   pinned. Only [`TlsMode::Pinned`] with an out-of-band fingerprint is free
//!   of that window.
//! * Chain validation against the *Loxone Root Certificate* — which the
//!   protocol document recommends — is deliberately **not** implemented. The
//!   pin modes verify the leaf public key only; the issuing chain is logged but
//!   not trusted.
//! * The pin modes also skip hostname verification, because the certificate
//!   name virtually never matches the address the client dials.

use crate::error::{Error, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex, OnceLock};
use tokio_rustls::TlsConnector;
use tracing::{debug, info, warn};
use x509_cert::Certificate;
use x509_cert::der::{Decode, Encode};

/// How server certificates are verified.
///
/// See the [module documentation](self) for the security properties of each
/// variant.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum TlsMode {
    /// Full WebPKI verification against the Mozilla root store. Default.
    #[default]
    WebPki,
    /// Trust the first certificate seen and pin its SPKI for the process
    /// lifetime.
    PinOnFirstUse,
    /// Accept only a certificate whose SPKI hashes to `spki_sha256`.
    Pinned {
        /// SHA-256 over the DER-encoded `SubjectPublicKeyInfo` of the leaf.
        spki_sha256: [u8; 32],
    },
    /// Accept any certificate. Explicit opt-out of all verification.
    Insecure,
}

impl TlsMode {
    fn pins(&self) -> bool {
        matches!(self, Self::PinOnFirstUse | Self::Pinned { .. })
    }
}

/// A reusable [`TlsConnector`] plus the pin state shared by all connections.
///
/// Cloning is cheap and shares both the rustls configuration and the learned
/// pin, so a single context should be built per client and reused across
/// reconnects.
#[derive(Clone)]
pub struct TlsContext {
    mode: TlsMode,
    pin: Arc<Mutex<Option<[u8; 32]>>>,
    connector: TlsConnector,
}

impl std::fmt::Debug for TlsContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsContext")
            .field("mode", &self.mode)
            .field("pinned", &self.pinned_spki().is_some())
            .finish()
    }
}

impl TlsContext {
    /// Build the rustls configuration for `mode` once.
    pub fn new(mode: TlsMode) -> Result<Self> {
        let pin: Arc<Mutex<Option<[u8; 32]>>> = match &mode {
            TlsMode::Pinned { spki_sha256 } => Arc::new(Mutex::new(Some(*spki_sha256))),
            _ => Arc::new(Mutex::new(None)),
        };

        let builder = rustls::ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| Error::Tls(e.to_string()))?;

        let config = match &mode {
            TlsMode::WebPki => {
                let mut roots = rustls::RootCertStore::empty();
                roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                builder.with_root_certificates(roots).with_no_client_auth()
            }
            TlsMode::PinOnFirstUse | TlsMode::Pinned { .. } => builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(SpkiPinVerifier {
                    pin: Arc::clone(&pin),
                    learn: matches!(mode, TlsMode::PinOnFirstUse),
                }))
                .with_no_client_auth(),
            TlsMode::Insecure => {
                warn!("TLS certificate verification is disabled for this client");
                builder
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
                    .with_no_client_auth()
            }
        };

        Ok(Self {
            mode,
            pin,
            connector: TlsConnector::from(Arc::new(config)),
        })
    }

    /// The configured policy.
    pub fn mode(&self) -> &TlsMode {
        &self.mode
    }

    /// The shared connector; clones share one connection-independent config.
    pub fn connector(&self) -> TlsConnector {
        self.connector.clone()
    }

    /// The currently enforced SPKI fingerprint, if any.
    pub fn pinned_spki(&self) -> Option<[u8; 32]> {
        *lock(&self.pin)
    }

    /// Whether a pin still has to be learned from `jdev/sys/getcertificate`.
    pub fn needs_pin_bootstrap(&self) -> bool {
        self.mode.pins() && self.pinned_spki().is_none()
    }

    /// Adopt `spki` as the pin, or fail if a different one is already enforced.
    ///
    /// Called with the fingerprint derived from `jdev/sys/getcertificate`.
    pub fn adopt_spki(&self, spki: [u8; 32]) -> Result<()> {
        if !self.mode.pins() {
            return Ok(());
        }
        let mut slot = lock(&self.pin);
        match *slot {
            Some(existing) if existing == spki => {
                debug!(spki = %hex::encode(spki), "certificate pin confirmed");
                Ok(())
            }
            Some(existing) => Err(Error::TlsPinMismatch {
                expected: hex::encode(existing),
                actual: hex::encode(spki),
            }),
            None => {
                warn!(
                    spki = %hex::encode(spki),
                    "pinning Miniserver certificate on first use; the pin was learned over an \
                     unauthenticated channel and is not chain-verified"
                );
                *slot = Some(spki);
                Ok(())
            }
        }
    }
}

/// SHA-256 over the DER-encoded `SubjectPublicKeyInfo` of a DER certificate.
pub fn spki_sha256(cert_der: &[u8]) -> Result<[u8; 32]> {
    let cert = Certificate::from_der(cert_der)
        .map_err(|e| Error::Tls(format!("certificate parse: {e}")))?;
    spki_sha256_of(&cert)
}

fn spki_sha256_of(cert: &Certificate) -> Result<[u8; 32]> {
    let der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| Error::Tls(format!("SPKI encode: {e}")))?;
    Ok(Sha256::digest(&der).into())
}

/// Derive the leaf SPKI fingerprint from a PEM certificate chain.
///
/// Per the protocol document the root is the *first* certificate of the chain
/// and the Miniserver's own certificate the last, so the fingerprint is taken
/// from the last entry. Subject, issuer and validity of every certificate are
/// logged; the chain itself is not verified.
pub fn spki_sha256_from_pem_chain(pem: &str) -> Result<[u8; 32]> {
    let chain = Certificate::load_pem_chain(pem.as_bytes())
        .map_err(|e| Error::Tls(format!("certificate chain parse: {e}")))?;
    let leaf = chain
        .last()
        .ok_or_else(|| Error::Tls("certificate chain is empty".into()))?;
    for (idx, cert) in chain.iter().enumerate() {
        let tbs = &cert.tbs_certificate;
        info!(
            index = idx,
            subject = %tbs.subject,
            issuer = %tbs.issuer,
            not_before = %tbs.validity.not_before.to_date_time(),
            not_after = %tbs.validity.not_after.to_date_time(),
            "Miniserver certificate"
        );
    }
    spki_sha256_of(leaf)
}

fn provider() -> Arc<CryptoProvider> {
    static PROVIDER: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
    Arc::clone(PROVIDER.get_or_init(|| Arc::new(rustls::crypto::ring::default_provider())))
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Verifies the leaf public key against a pinned fingerprint.
///
/// Handshake signatures are verified normally, so a matching pin proves the
/// peer holds the corresponding private key. Chain and hostname are not
/// checked.
#[derive(Debug)]
struct SpkiPinVerifier {
    pin: Arc<Mutex<Option<[u8; 32]>>>,
    learn: bool,
}

impl ServerCertVerifier for SpkiPinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let presented =
            spki_sha256(end_entity.as_ref()).map_err(|e| rustls::Error::General(e.to_string()))?;
        let mut slot = lock(&self.pin);
        match *slot {
            Some(expected) if expected == presented => Ok(ServerCertVerified::assertion()),
            Some(_) => Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            )),
            None if self.learn => {
                warn!(
                    spki = %hex::encode(presented),
                    "pinning Miniserver certificate on first use; the pin was learned over an \
                     unauthenticated channel and is not chain-verified"
                );
                *slot = Some(presented);
                Ok(ServerCertVerified::assertion())
            }
            None => Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            )),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Accepts every certificate — backs [`TlsMode::Insecure`].
#[derive(Debug)]
struct NoCertVerifier;

impl ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Self-signed P-256 certificate, `CN=loxone-test`. Its DER-encoded SPKI
    /// hashes to [`LEAF_SPKI_SHA256`] (cross-checked with `openssl dgst`).
    const LEAF_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIBgDCCASegAwIBAgIUCAWO3OcJ1bc6jZQLKcLIzJxlg54wCgYIKoZIzj0EAwIw
FjEUMBIGA1UEAwwLbG94b25lLXRlc3QwHhcNMjYwODA1MjAxNDMxWhcNMzYwODAy
MjAxNDMxWjAWMRQwEgYDVQQDDAtsb3hvbmUtdGVzdDBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABLz6r6SZiwNvSmSLU6dIO1FWCramxvTybGCfRX+RMxLCbnMSfGNf
J+zTIe/AjAH4bNFHaMUgFEbASg6aGCtTHbijUzBRMB0GA1UdDgQWBBQ4kpn258OK
/gqi9DHaOndr8CbY1DAfBgNVHSMEGDAWgBQ4kpn258OK/gqi9DHaOndr8CbY1DAP
BgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIAfgbNJOl24bCBDDVG21
Zxnz8JCYkAxQCb/OuRUhuWRWAiA3LusHaEstgKoobMbjdssGbZVBHiaH+pzUsHmk
8znXJw==
-----END CERTIFICATE-----
";

    /// Self-signed P-256 certificate, `CN=loxone-test-root`.
    const ROOT_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIBizCCATGgAwIBAgIUfafIu/sdEwinPGrD3CaZZA41jF4wCgYIKoZIzj0EAwIw
GzEZMBcGA1UEAwwQbG94b25lLXRlc3Qtcm9vdDAeFw0yNjA4MDUyMDE0MzZaFw0z
NjA4MDIyMDE0MzZaMBsxGTAXBgNVBAMMEGxveG9uZS10ZXN0LXJvb3QwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAATw2y8OxfihpGRwSlYxNpwGQ7rYvcz2uRrZCKHf
fZ1yatGJjW2gPgufGaVzaRDLhUa3feDZ7qf+w24+Imw48FBwo1MwUTAdBgNVHQ4E
FgQU/9rfwmymaYkvYVGCzyhrYOrLZ+YwHwYDVR0jBBgwFoAU/9rfwmymaYkvYVGC
zyhrYOrLZ+YwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEAtUw3
L/GUP+zngMsTnGdVNOOHxyHsiI8AsqnGp8xXB/sCIAfxqCF7wOOjEYhazKiKlVWP
Etr5+6jfwEn7WT6y8WOG
-----END CERTIFICATE-----
";

    const LEAF_SPKI_SHA256: &str =
        "4a3650e743d13d5b39bd673a5bdedf5a7f264ba013a9a7eb39151eac2cfdf9b0";

    #[test]
    fn webpki_is_default() {
        assert_eq!(TlsMode::default(), TlsMode::WebPki);
    }

    #[test]
    fn pinned_mode_starts_with_its_pin() {
        let ctx = TlsContext::new(TlsMode::Pinned {
            spki_sha256: [7; 32],
        })
        .unwrap();
        assert_eq!(ctx.pinned_spki(), Some([7; 32]));
        assert!(!ctx.needs_pin_bootstrap());
    }

    #[test]
    fn tofu_mode_needs_bootstrap_then_locks_in() {
        let ctx = TlsContext::new(TlsMode::PinOnFirstUse).unwrap();
        assert!(ctx.needs_pin_bootstrap());
        ctx.adopt_spki([1; 32]).unwrap();
        assert_eq!(ctx.pinned_spki(), Some([1; 32]));
        assert!(!ctx.needs_pin_bootstrap());
        ctx.adopt_spki([1; 32]).unwrap();
        assert!(matches!(
            ctx.adopt_spki([2; 32]),
            Err(Error::TlsPinMismatch { .. })
        ));
    }

    #[test]
    fn non_pinning_modes_ignore_adopted_spki() {
        let ctx = TlsContext::new(TlsMode::WebPki).unwrap();
        assert!(!ctx.needs_pin_bootstrap());
        ctx.adopt_spki([3; 32]).unwrap();
        assert_eq!(ctx.pinned_spki(), None);
    }

    #[test]
    fn spki_matches_openssl() {
        let der = Certificate::load_pem_chain(LEAF_PEM.as_bytes()).unwrap()[0]
            .to_der()
            .unwrap();
        assert_eq!(hex::encode(spki_sha256(&der).unwrap()), LEAF_SPKI_SHA256);
    }

    #[test]
    fn chain_fingerprint_uses_the_last_certificate() {
        let root_first = format!("{ROOT_PEM}{LEAF_PEM}");
        assert_eq!(
            hex::encode(spki_sha256_from_pem_chain(&root_first).unwrap()),
            LEAF_SPKI_SHA256
        );
        assert_eq!(
            hex::encode(spki_sha256_from_pem_chain(LEAF_PEM).unwrap()),
            LEAF_SPKI_SHA256
        );
        assert_ne!(
            hex::encode(spki_sha256_from_pem_chain(ROOT_PEM).unwrap()),
            LEAF_SPKI_SHA256
        );
    }

    #[test]
    fn malformed_input_is_rejected() {
        assert!(spki_sha256_from_pem_chain("not a certificate").is_err());
        assert!(spki_sha256(b"\x00\x01\x02").is_err());
    }
}
