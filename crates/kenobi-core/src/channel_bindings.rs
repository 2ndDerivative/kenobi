pub trait Channel {
    fn channel_bindings(&self) -> Result<Option<Vec<u8>>, impl std::error::Error>;
}

#[cfg(any(feature = "native-tls", feature = "rustls"))]
const PREFIX: &[u8] = b"tls-server-end-point:";

#[cfg(feature = "native-tls")]
impl<S: std::io::Read + std::io::Write> Channel for native_tls::TlsStream<S> {
    fn channel_bindings(&self) -> Result<Option<Vec<u8>>, impl std::error::Error> {
        match self.tls_server_end_point() {
            Ok(Some(v)) => {
                let mut vec = Vec::with_capacity(PREFIX.len() + v.len());
                vec.extend_from_slice(PREFIX);
                vec.extend_from_slice(&v);
                Ok(Some(vec))
            }
            other => other,
        }
    }
}
#[cfg(feature = "rustls")]
impl Channel for rustls::ClientConnection {
    fn channel_bindings(&self) -> Result<Option<Vec<u8>>, impl std::error::Error> {
        use std::convert::Infallible;

        Ok::<_, Infallible>(
            self.peer_certificates()
                .and_then(|peers| peers.first())
                .and_then(|p| p.channel_bindings().unwrap()),
        )
    }
}
#[cfg(feature = "rustls")]
impl Channel for rustls::pki_types::CertificateDer<'_> {
    fn channel_bindings(&self) -> Result<Option<Vec<u8>>, impl std::error::Error> {
        let hash = tls_server_end_point_digest(self);
        Ok::<_, std::convert::Infallible>(Some([PREFIX, hash.as_ref()].concat()))
    }
}

#[cfg(feature = "rustls")]
fn tls_server_end_point_digest(cert_der: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256, Sha384, Sha512};
    use x509_parser::{oid_registry::*, prelude::*, signature_algorithm::RsaSsaPssParams};

    let Ok((_, x509)) = X509Certificate::from_der(cert_der) else {
        return Sha256::digest(cert_der).to_vec();
    };

    let sig_oid = &x509.signature_algorithm.algorithm;

    if sig_oid == &OID_PKCS1_RSASSAPSS {
        if let Some(params_any) = x509.signature_algorithm.parameters()
            && let Ok(pss) = RsaSsaPssParams::try_from(params_any)
        {
            let alg = pss.hash_algorithm_oid();
            if alg == &OID_NIST_HASH_SHA512 {
                return Sha512::digest(cert_der).to_vec();
            }
            if alg == &OID_NIST_HASH_SHA384 {
                return Sha384::digest(cert_der).to_vec();
            }
        }
        return Sha256::digest(cert_der).to_vec();
    }

    if sig_oid == &OID_PKCS1_SHA256WITHRSA {
        return Sha256::digest(cert_der).to_vec();
    }
    if sig_oid == &OID_PKCS1_SHA384WITHRSA {
        return Sha384::digest(cert_der).to_vec();
    }
    if sig_oid == &OID_PKCS1_SHA512WITHRSA {
        return Sha512::digest(cert_der).to_vec();
    }
    if sig_oid == &OID_PKCS1_MD5WITHRSAENC || sig_oid == &OID_PKCS1_SHA1WITHRSA {
        return Sha256::digest(cert_der).to_vec();
    }

    // ECDSA with SHA-2
    if sig_oid == &OID_SIG_ECDSA_WITH_SHA384 {
        return Sha384::digest(cert_der).to_vec();
    }
    if sig_oid == &OID_SIG_ECDSA_WITH_SHA512 {
        return Sha512::digest(cert_der).to_vec();
    }

    Sha256::digest(cert_der).to_vec()
}
