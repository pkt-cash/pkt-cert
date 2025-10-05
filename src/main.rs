use std::time::SystemTime;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use acme2::openssl::asn1::Asn1Time;
use clap::{Parser};
use eyre::{eyre, Context, Result};
use config::Config;
use rand::seq::IndexedRandom;
use tokio::sync::Mutex;
use rand::RngCore;

use crate::server::{Server, ServerMut};

mod config;
mod acme;
mod server;
mod precheck;

/// Simple ACME certificate bot
#[derive(Parser, Debug)]
#[command(name = "pkt-cert")]
#[command(about = "ACME certificate updater for PKT domains", long_about = None)]
struct Cli {
    /// Path to configuration file
    #[arg(short = 'p', long = "path", default_value = "/etc/pkt-cert")]
    cert_path: String,

    /// Generate a default configuration and write it to <config>, then exit
    #[arg(long = "genconf", action)]
    genconf: bool,

    /// Check and renew any certificates that are expiring soon
    #[arg(short = 'c', long = "check", action, default_value_t = false)]
    check: bool,

    /// Force the renewal of a specific domain, even if not expiring soon
    #[arg(short = 'f', long = "force-renew")]
    force_renew: Option<String>,

    /// Add a domain to the configuration and trigger renewal
    #[arg(short = 'a', long = "add")]
    add: Option<String>,

    /// Run this server command after getting certificates, e.g. 'service nginx reload'
    #[arg(short = 'r', long = "reload-command")]
    reload_command: Option<String>,
}

async fn domains_needing_update(conf: &Config) -> Result<Vec<String>> {
    let mut need_update = Vec::new();
    for domain in &conf.domains {
        match acme::cert_expiration_date(conf, domain).await {
            Ok(exp) => {
                let now = SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
                let exp_s = Asn1Time::from_unix(exp as _)?.to_string();
                let renew_time = exp - conf.renew_days_before_expiration() * 24 * 60 * 60;
                let renew_time_s = Asn1Time::from_unix(renew_time as _)?.to_string();
                if now < renew_time {
                    println!("Domain {} certificate is valid until {}, no need to update until {}",
                        domain, exp_s, renew_time_s);
                } else {
                    println!("Domain {} certificate expires soon ({}), need to update", domain, exp_s);
                    need_update.push(domain.clone());
                }
            }
            Err(e) => {
                println!("Domain {} certificate not found or invalid: {e}, need to obtain", domain);
                need_update.push(domain.clone());
            }
        }
    }
    Ok(need_update)
}

async fn update_certs(
    need_update: &[String],
    bind: SocketAddr,
    config: Config,
) -> Result<()> {
    let mut rng = rand::rng();
    // Make a random cookie with only printable characters
    let cookie = format!("{:x}", rng.next_u64());
    let mut challenges = HashMap::new();
    challenges.insert("pkt-cookie".to_owned(), cookie.clone());

    let server = Arc::new(Server {
        m: Mutex::new(ServerMut { challenges }),
        config,
        bind,
    });

    println!("Starting server on {}", server.config.bind);
    tokio::task::spawn(server::warp_task(server.clone()));

    // Use randomly chosen dir so that failures will self-rectify in subsequent runs
    let dir = server.config.acme_dirs[..].choose(&mut rng)
        .ok_or(eyre!("No ACME directories configured"))?.clone();

    let tlds = precheck::get_valid_tlds(&server.config).await?;
    for domain in need_update {
        println!("Checking domain {domain}");
        let good_tlds = precheck::precheck_domain(domain, &tlds, &cookie).await?;
        acme::do_acme(&server, &dir, domain, &good_tlds).await?;
    }

    Ok(())
}

async fn update_nginx_conf(config: &Config, domain: &str) -> Result<bool> {
    // For each domain in config.domains, we update a file called {config.cert_path}/{domain}.nginx.inc
    // This file contains:
    // ssl_certificate {acme::cert_path()}
    // ssl_certificate_key {acme::key_path()}
    // server_name {acme::cert_all_domains()}
    let path = config::nginx_path(config, domain);
    let server_name = acme::cert_all_domains(config, domain).await?;
    let content = [
        format!("ssl_certificate {};", config::cert_path(config, domain)),
        format!("ssl_certificate_key {};", config::key_path(config, domain)),
        format!("server_name {};", server_name.join(", ")),
    ].join("\n") + "\n";
    let existing = tokio::fs::read(&path).await?;
    if existing == content.as_bytes() {
        // No change
        return Ok(false);
    }
    println!("Nginx config {} has changed", path);
    tokio::fs::write(&path, content).await.context("Writing nginx config")?;
    Ok(true)
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut cli = Cli::parse();
    if cli.genconf {
        let path = config::config_path(&cli.cert_path);
        if std::path::Path::new(&path).exists() {
            return Err(eyre!("Config file {} already exists, will not overwrite", path));
        }
        return config::generate(std::path::Path::new(&path)).await;
    }
    let mut config = Config::load(&cli.cert_path).await?;
    let bind: SocketAddr = config.bind.parse().context("Parsing bind address")?;

    if let Some(new_domain) = cli.add {
        if !new_domain.ends_with(".pkt") {
            return Err(eyre!("Domain must end with .pkt"));
        }
        if config.domains.contains(&new_domain) {
            println!("Domain {} is already in the configuration", new_domain);
            return Ok(());
        } else {
            println!("Adding domain {} to configuration", new_domain);
            config.domains.push(new_domain);
            let path = config::config_path(&cli.cert_path);
            let content = serde_yaml::to_string(&config).context("Serializing configuration")?;
            tokio::fs::write(&path, content).await.context("Writing configuration file")?;
            println!("Wrote updated configuration to {}", path);
            println!("Triggering --check to obtain certificate for new domain");
            cli.check = true;
        }
    }

    if !cli.check && cli.force_renew.is_none() {
        println!("No action specified, use --help to see options");
        return Ok(());
    }

    let need_update = if let Some(fr) = cli.force_renew {
        if !config.domains.contains(&fr) {
            return Err(eyre!("Domain {} is not in the configuration, cannot force renew", fr));
        }
        vec![fr]
    } else {
        domains_needing_update(&config).await?
    };

    // Check if there are any domains which need updating
    if !need_update.is_empty() {
        update_certs(&need_update, bind, config.clone()).await?;
    }

    let mut update = !need_update.is_empty();
    for domain in &config.domains {
        update |= update_nginx_conf(&config, domain).await?;
    }

    if !update {
        // do not reload
    } else if let Some(rc) = cli.reload_command {
        println!("Running reload command: {}", rc);
        let status = tokio::process::Command::new("sh")
            .arg("-c")
            .arg(&rc)
            .status()
            .await
            .context("Running reload command")?;
        if !status.success() {
            return Err(eyre!("Reload command failed with status {}", status));
        }
        println!("Reload command completed successfully");
    }

    Ok(())
}
