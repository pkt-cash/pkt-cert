use serde::{Deserialize, Serialize};

use std::io::Write;
use tokio::io::{AsyncBufReadExt, BufReader};
use std::path::Path;
use eyre::{bail, Context, OptionExt, Result};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Config {
    /// List of ACME directory URLs to try for certificate issuance.
    pub acme_dirs: Vec<String>,
    /// List of servers where you can get the list of PKT domains
    pub pkt_domain_service: Vec<String>,
    /// Contact email for ACME account registration.
    pub email: String,
    /// PKT domains for which to obtain certificates.
    pub domains: Vec<String>,
    /// Address and port to bind the service for handling ACME challenges.
    pub bind: String,

    // Optional config fields, not included in default config
    pub poll_interval: Option<u64>, // in seconds
    pub poll_attempts: Option<u64>,
    pub renew_days_before_expiration: Option<u64>, // default 30

    #[serde(skip)]
    pub cert_path: String, // path to store certs and keys
}
impl Config {
    pub async fn load(cert_path: &str) -> Result<Config> {
        let config_path = config_path(cert_path);
        let path = Path::new(&config_path);
        if !path.exists() {
            bail!("Configuration file {} does not exist. Use --genconf to create one.", path.display());
        }
        let content = std::fs::read_to_string(path)
            .context("Failed to read configuration file")?;
        let mut config: Config = serde_yaml::from_str(&content)
            .context("Failed to parse configuration file")?;
        // Convert path to absolute and store as config.cert_path
        config.cert_path = std::fs::canonicalize(cert_path)
            .context("Failed to canonicalize cert path")?
            .to_str()
            .ok_or_eyre("Invalid cert path")?
            .to_string();
        // println!("Loaded configuration: {:?}", path);
        Ok(config)
    }
    pub fn renew_days_before_expiration(&self) -> u64 {
        self.renew_days_before_expiration.unwrap_or(30)
    }
}

fn default_config(email: &str, cert_path: &str) -> Config {
    Config {
        acme_dirs: vec![
            "https://acme-v02.api.letsencrypt.org/directory".to_string(),
        ],
        pkt_domain_service: vec![
            "https://app.pkt.cash/api/v1/infra/domain/all/simple".to_string(),
        ],
        email: email.to_string(),
        domains: [].into(),
        bind: "127.0.0.1:9987".to_string(),
        poll_interval: None,
        poll_attempts: None,
        cert_path: cert_path.to_string(),
        renew_days_before_expiration: None,
    }
}

pub fn config_path(cert_path: &str) -> String {
    format!(
        "{}/config.yaml",
        cert_path.trim_end_matches('/')
    )
}

pub async fn generate(path: &Path) -> Result<()> {
    // Prompt for email address via stdin
    print!("Enter contact email for ACME account registration: ");
    std::io::stdout().flush()?;
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut email = String::new();
    reader.read_line(&mut email).await.context("Reading email from stdin")?;
    let email = email.trim();
    if email.is_empty() {
        bail!("Email address cannot be empty.");
    }
    let cert_path = path.parent().ok_or_eyre("Config path has no directory")?;
    let conf = default_config(email, cert_path.to_str().ok_or_eyre("Invalid cert path")?);
    let yaml = serde_yaml::to_string(&conf).context("Serializing config to YAML")?;
    tokio::fs::create_dir_all(cert_path).await.context("Creating directories")?;
    tokio::fs::write(path, yaml).await.context("Writing config")?;
    println!("Configuration written to {}", path.display());
    println!("Use pkt-cert --add <domain>.pkt to get your first certificate");
    Ok(())
}

pub fn cert_path(conf: &Config, domain: &str) -> String {
    format!(
        "{}/{}.fullchain",
        conf.cert_path.trim_end_matches('/'),
        domain
    )
}

pub fn key_path(conf: &Config, domain: &str) -> String {
    format!(
        "{}/{}.key",
        conf.cert_path.trim_end_matches('/'),
        domain
    )
}

pub fn nginx_path(conf: &Config, domain: &str) -> String {
    format!(
        "{}/{}.nginx.inc",
        conf.cert_path.trim_end_matches('/'),
        domain
    )
}