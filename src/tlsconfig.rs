use crate::ess_errors::{EssError, Result};

use std::env;
use std::fs::File;
use std::io::BufReader;
/// The reason we use the full qualified path is that tide_rustls uses rustls 0.19
/// instead of curren 0.20.
use tide_rustls::rustls::{
    AllowAnyAuthenticatedClient, Certificate, PrivateKey, RootCertStore, ServerConfig,
};

pub enum WsType {
    Admin,
    Pam,
}

enum CertType {
    RootCA,
    CertChain,
    Key,
}

impl CertType {
    fn default_path(&self, wtype: &WsType) -> String {
        let mut path = String::from("./certs/");
        match wtype {
            WsType::Admin => path.push_str("admin/admin"),
            WsType::Pam => path.push_str("pam/pam"),
        };
        match self {
            CertType::RootCA => path.push_str("-root-ca.crt"),
            CertType::CertChain => path.push_str("-server-crt.pem"),
            CertType::Key => path.push_str("-server-key.pem"),
        };
        path
    }

    fn envar(&self, wtype: &WsType) -> String {
        let mut var = String::from(match wtype {
            WsType::Admin => "ESS_ADMIN_WS_",
            WsType::Pam => "ESS_PAM_WS_",
        });
        var.push_str(match self {
            CertType::RootCA => "ROOT_CA",
            CertType::CertChain => "CERT",
            CertType::Key => "KEY",
        });
        var
    }
}

fn load_certs(filename: &str) -> Result<Vec<Certificate>> {
    let certfile = File::open(filename)?;
    let mut reader = BufReader::new(certfile);
    Ok(rustls_pemfile::certs(&mut reader)
        .unwrap()
        .iter()
        .map(|v| Certificate(v.clone()))
        .collect())
}

fn load_private_key(filename: &str) -> Result<PrivateKey> {
    let keyfile = File::open(filename)?;
    let mut reader = BufReader::new(keyfile);

    loop {
        match rustls_pemfile::read_one(&mut reader)? {
            Some(rustls_pemfile::Item::RSAKey(key)) => return Ok(PrivateKey(key)),
            Some(rustls_pemfile::Item::PKCS8Key(key)) => return Ok(PrivateKey(key)),
            Some(rustls_pemfile::Item::ECKey(key)) => return Ok(PrivateKey(key)),
            None => break,
            _ => {}
        }
    }

    Err(EssError::TlsCert(String::from(filename)))
}

fn get_root_store(file: &str) -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();

    for root in load_certs(file)? {
        roots.add(&root)?;
    }

    Ok(roots)
}

pub fn make_server_config(wtype: WsType) -> Result<ServerConfig> {
    let (root_ca, cert_chain, cert_key) = if let (Ok(root_ca_file), Ok(cert_file), Ok(key_file)) = (
        env::var(CertType::RootCA.envar(&wtype)),
        env::var(CertType::CertChain.envar(&wtype)),
        env::var(CertType::Key.envar(&wtype)),
    ) {
        println!("[tls] using cert paths from envars");
        (root_ca_file, cert_file, key_file)
    } else {
        println!("[tls] using default cert paths");
        (
            CertType::RootCA.default_path(&wtype),
            CertType::CertChain.default_path(&wtype),
            CertType::Key.default_path(&wtype),
        )
    };

    let root_store = get_root_store(&root_ca)?;
    let cert = load_certs(&cert_chain)?;
    let key = load_private_key(&cert_key)?;
    let client_auth = AllowAnyAuthenticatedClient::new(root_store);

    let mut srvcfg = ServerConfig::new(client_auth);
    srvcfg.set_single_cert(cert, key)?;

    Ok(srvcfg)
}
