use reqwest;
use std::collections::HashMap;
use std::time::Duration;

use std::process::Command;

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as RustlsError, RootCertStore, SignatureScheme};
use sha2::{Digest, Sha256};

pub fn login(username: &str, password: &str) -> Result<bool, Box<dyn std::error::Error>> {
    check_uabc_connection()?;

    let local_id = get_local_id()?;

    let login_success = send_login(username, password, &local_id)?;

    if login_success {
        return Ok(true);
    }

    Ok(false)
}

fn get_local_id() -> Result<String, Box<dyn std::error::Error>> {
    let client = build_client(true);

    let response = client.get("https://pcw.uabc.mx/").send()?;

    if response.status().is_redirection() {
        if let Some(location) = response.headers().get("Location") {
            let url = location.to_str().unwrap_or_default();
            if let Some(pos) = url.find("url=") {
                let local_id = &url[(pos + 4)..];
                return Ok(local_id.to_string());
            }
        }
    }

    Err("Portal cautivo no disponible".into())
}

fn send_login(
    email: &str,
    password: &str,
    local_id: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let client = build_client(false);

    let mut form = HashMap::new();
    form.insert("url", local_id);
    form.insert("username", email);
    form.insert("password", password);

    let response = client.post("https://pcw.uabc.mx/").form(&form).send()?;

    if response.status().is_success() {
        let body = response.text()?;
        return Ok(body.contains("<title>Login Successful</title>"));
    } 

    Ok(false)
}

fn check_uabc_connection() -> Result<bool, Box<dyn std::error::Error>> {
    match get_current_ssid() {
        Ok(name) => {
            if name.contains("UABC") {
                Ok(true)
            } else {
                Err("No estás conectado a la red UABC".into())
            }
        }
        Err(_) => Err("No te encuentras en una red Wifi".into()),
    }
}


//? Pinnig certificado del portal
#[derive(Debug)]
struct PinnedCertVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    expected_cert_sha256: [u8; 32],
}

impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)?;

        // Se calcula el SHA-256 del certificado presentado por el servidor y se compara con el pin configurado
        let mut hasher = Sha256::new();
        hasher.update(end_entity.as_ref());
        let digest = hasher.finalize();

        if digest.as_slice() == self.expected_cert_sha256 {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(RustlsError::General(
                "El certificado del servidor no coincide con el pin configurado".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

fn build_client(no_redirect: bool) -> reqwest::blocking::Client {
    const CERT_SHA256_HEX: &str =
        "19DC98BB1F0806934A375019394A01A9DAD4A18758EB1E4BB82607CDEB1DD25B";

    let expected_cert_sha256_vec =
        hex::decode(CERT_SHA256_HEX).expect("CERT_SHA256_HEX inválido, no es hex");
    let expected_cert_sha256: [u8; 32] = expected_cert_sha256_vec
        .try_into()
        .expect("CERT_SHA256_HEX no tiene longitud de 32 bytes");

    // Construimos el RootCertStore a partir de los anchors de webpki-roots.
    let mut root_store = RootCertStore::empty();
    root_store.roots = webpki_roots::TLS_SERVER_ROOTS.to_vec();
    let root_store = Arc::new(root_store);

    let inner_verifier: Arc<dyn ServerCertVerifier> = WebPkiServerVerifier::builder(root_store)
        .build()
        .expect("No se pudo construir el verificador WebPki");

    let pinned_verifier = Arc::new(PinnedCertVerifier {
        inner: inner_verifier,
        expected_cert_sha256,
    });

    let root_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(pinned_verifier)
        .with_no_client_auth();

    let mut builder = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .use_preconfigured_tls(root_config);

    if no_redirect {
        builder = builder.redirect(reqwest::redirect::Policy::none());
    }

    builder.build().expect("Failed to build HTTP client with pinning")
}

fn get_current_ssid() -> Result<String, Box<dyn std::error::Error>> {
    let output = Command::new("iwgetid").arg("-r").output()?;

    if !output.status.success() {
        return Err("El comando falló".into());
    }

    let wifi_name = String::from_utf8(output.stdout)?.trim().to_string();

    Ok(wifi_name)
}
