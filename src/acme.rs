use acme2::gen_rsa_private_key;
use acme2::openssl::asn1::Asn1Time;
use acme2::openssl::asn1::Asn1TimeRef;
use acme2::Account;
use acme2::AccountBuilder;
use acme2::AuthorizationStatus;
use acme2::ChallengeStatus;
use acme2::DirectoryBuilder;
use acme2::OrderBuilder;
use acme2::OrderStatus;
use acme2::Csr;
use eyre::bail;
use eyre::OptionExt;
use reqwest::Client;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use std::io::Write;
use eyre::Result;
use acme2::openssl::pkey::{PKey,Private};

use crate::config::cert_path;
use crate::config::key_path;
use crate::config::Config;
use crate::server::Server;

#[derive(serde::Serialize, serde::Deserialize)]
struct AccountJson {
    key: Vec<u8>,
}

async fn make_account(
    server: &str,
    email: &str,
    pkey: Option<PKey<Private>>,
    client: &Client,
) -> Result<Arc<Account>> {
    let dir = DirectoryBuilder::new(server.to_string())
        .http_client(client.clone())
        .build()
        .await
        .map_err(|e| eyre::eyre!("Failed to create directory: {}", e))?;
    let mut builder = AccountBuilder::new(dir);
    builder.contact(vec![format!("mailto:{}", email)]);
    builder.terms_of_service_agreed(true);
    if let Some(pkey) = pkey {
        builder.only_return_existing(true);
        builder.private_key(pkey);
    }
    let acct = builder.build().await
        .map_err(|e| eyre::eyre!("Failed to build account: {}", e))?;
    Ok(acct)
}

async fn account_path(conf: &Config, server: &str, email: &str) -> Result<PathBuf> {
    let server_email_hash = md5::compute(format!("{}:{}", server, email));
    let acct_path = format!(
        "{}/account-{:x}.json",
        conf.cert_path.trim_end_matches('/'),
        server_email_hash
    );
    Ok(acct_path.into())
}

async fn load_account(conf: &Config, server: &str, email: &str, client: &Client) -> Result<Option<Arc<Account>>> {
    let acct_path = account_path(conf, server, email).await?;
    if !acct_path.exists() {
        return Ok(None);
    }
    let acct_json = tokio::fs::read_to_string(&acct_path)
        .await
        .map_err(|e| eyre::eyre!("Failed to read account file: {}", e))?;
    let acct: AccountJson = serde_json::from_str(&acct_json)
        .map_err(|e| eyre::eyre!("Failed to deserialize account: {}", e))?;
    let pkey = PKey::private_key_from_pkcs8(&acct.key[..])
        .map_err(|e| eyre::eyre!("Failed to parse private key: {}", e))?;
    let acct = make_account(server, email, Some(pkey), client).await?;
    Ok(Some(acct))
}

async fn store_account(
    conf: &Config,
    acct: &Arc<Account>,
    server: &str,
    email: &str,
) -> Result<()> {
    let acct_path = account_path(conf, server, email).await?;
    let pk = acct.private_key()
        .private_key_to_pkcs8()
        .map_err(|e| eyre::eyre!("Failed to encode private key: {}", e))?;
    let acct_json = AccountJson{ key: pk };
    let acct_json_s = serde_json::to_string_pretty(&acct_json)
        .map_err(|e| eyre::eyre!("Failed to serialize account: {}", e))?;
    tokio::fs::create_dir_all(&conf.cert_path)
        .await
        .map_err(|e| eyre::eyre!("Failed to create cert path: {}", e))?;
    tokio::fs::write(&acct_path, acct_json_s)
        .await
        .map_err(|e| eyre::eyre!("Failed to write account file: {}", e))?;
    println!("Account stored at {}", acct_path.display());
    Ok(())
}

async fn get_account(conf: &Config, server: &str, client: &Client) -> Result<Arc<Account>> {
    if let Some(acct) = load_account(conf, server, &conf.email, client).await? {
        println!("Loaded existing account for {} at {}", conf.email, server);
        Ok(acct)
    } else {
        println!("Creating new account for {} at {}", conf.email, server);
        let acct = make_account(server, &conf.email, None, client).await?;
        store_account(conf, &acct, server, &conf.email).await?;
        Ok(acct)
    }
}

pub async fn do_acme(server: &Arc<Server>, dir: &str, domain: &str, tlds: &[String]) -> Result<()> {
    let client = reqwest::ClientBuilder::new()
        .timeout(Duration::from_secs(10))
        .user_agent("pkt-cert/1.0 - https://github.com/pkt-cash/pkt-cert - cjd@cjdns.fr")
        .build()
        .map_err(|e| eyre::eyre!("Failed to build HTTP client: {}", e))?;
    let account = get_account(&server.config, dir, &client).await?;

    // Create a new order for a specific domain name.
    let mut builder = OrderBuilder::new(account);
    for tld in tlds {
        let tld = tld.strip_prefix("pkt.").unwrap_or(&tld[..]);
        let d = format!("{}.{}", domain, tld);
        // println!("Adding domain {}", d);
        builder.add_dns_identifier(d.to_string());
    }
    let order = builder.build().await?;

    let poll_interval = Duration::from_secs(server.config.poll_interval.unwrap_or(10));
    let poll_attempts = server.config.poll_attempts.unwrap_or(30) as usize;

    // Get the list of needed authorizations for this order.
    let authorizations = order.authorizations().await?;
    let mut challenges = Vec::with_capacity(authorizations.len());
    for auth in &authorizations {
        let challenge = auth.get_challenge("http-01")
            .ok_or_eyre("Failed to get http-01 challenge")?;
        if let (Some(k), Some(v)) = (challenge.token.clone(), challenge.key_authorization()?) {
            println!("Authorization: {} = {}", auth.identifier.value, k);
            server.m.lock().await.challenges.insert(k, v);
        } else {
            bail!("Challenge missing token or key authorization");
        }
        let challenge = challenge.validate().await?;
        challenges.push((auth.identifier.value.clone(), challenge));
    }
    for (domain, challenge) in challenges {
        print!("Wait challenge {domain}");
        std::io::stdout().flush()?;
        let challenge = challenge.wait_done(poll_interval, poll_attempts).await?;
        if challenge.status != ChallengeStatus::Valid {
            bail!("Challenge did not become valid");
        }
        println!("  OK");
    }
    for auth in authorizations {
        print!("Wait authorization {}", auth.identifier.value);
        std::io::stdout().flush()?;
        let authorization = auth.wait_done(poll_interval, poll_attempts).await?;
        if authorization.status != AuthorizationStatus::Valid {
            bail!("Authorization did not become valid");
        }
        println!("  OK");
    }

    // Poll the order every 5 seconds until it is in either the
    // `ready` or `invalid` state. Ready means that it is now ready
    // for finalization (certificate creation).
    println!("Waiting for order to be ready for certificate signing...");
    let order = order.wait_ready(poll_interval, poll_attempts).await?;
    if order.status != OrderStatus::Ready {
        bail!("Order did not become ready");
    }

    // Generate an RSA private key for the certificate.
    let pkey = gen_rsa_private_key(4096)?;

    let key_b = pkey.private_key_to_pem_pkcs8()
        .map_err(|e| eyre::eyre!("Failed to encode private key to PEM: {}", e))?;

    // Create a certificate signing request for the order, and request
    // the certificate.
    println!("Waiting for certificate to be signed...");
    let order = order.finalize(Csr::Automatic(pkey)).await?;

    // Poll the order every 5 seconds until it is in either the
    // `valid` or `invalid` state. Valid means that the certificate
    // has been provisioned, and is now ready for download.
    println!("Waiting for certificate signature...");
    let order = order.wait_done(poll_interval, poll_attempts).await?;
    if order.status != OrderStatus::Valid {
        bail!("Order did not become valid");
    }

    // Download the certificate, and panic if it doesn't exist.
    let cert = order.certificate().await?.unwrap();

    // Write the certificate to disk
    let mut fullchain = Vec::new();
    for c in cert.iter() {
        let cert_b = c.to_pem()
            .map_err(|e| eyre::eyre!("Failed to encode certificate to PEM: {}", e))?;
        fullchain.extend_from_slice(&cert_b);
    }

    let fullchain_path = cert_path(&server.config, domain);
    println!("Saving full certificate chain to {}", fullchain_path);
    tokio::fs::create_dir_all(&server.config.cert_path)
        .await
        .map_err(|e| eyre::eyre!("Failed to create cert path: {}", e))?;
    tokio::fs::write(&fullchain_path, &fullchain)
        .await
        .map_err(|e| eyre::eyre!("Failed to write full certificate chain file: {}", e))?;

    let key_path = key_path(&server.config, domain);
    println!("Saving private key to {}", key_path);
    tokio::fs::write(&key_path, &key_b)
        .await
        .map_err(|e| eyre::eyre!("Failed to write private key file: {}", e))?;

    Ok(())
}

fn asn1_to_unix(t: &Asn1TimeRef) -> Result<u64> {
    let atr = Asn1Time::from_unix(0).unwrap();
    let td = atr.as_ref().diff(t).unwrap();
    (td.days as u64)
        .checked_mul(60*60*24)
        .and_then(|d| d.checked_add(td.secs as _))
        .ok_or(eyre::eyre!("Overflow converting ASN1 time to unix time"))
}

pub async fn cert_expiration_date(config: &Config, domain: &str) -> Result<u64> {
    let fullchain_path = cert_path(config, domain);
    let cert_data = tokio::fs::read(&fullchain_path)
        .await
        .map_err(|e| eyre::eyre!("Failed to read certificate file {}: {}", fullchain_path, e))?;
    let cert = acme2::openssl::x509::X509::from_pem(&cert_data)
        .map_err(|e| eyre::eyre!("Failed to parse certificate in file {}: {}", fullchain_path, e))?;
    let not_after = asn1_to_unix(cert.not_after())?;
    // println!("Certificate for domain {} expires at unix time {} ({})",
    //     domain, not_after, cert.not_after().to_string());
    Ok(not_after)
}

pub async fn cert_all_domains(config: &Config, domain: &str) -> Result<Vec<String>> {
    let fullchain_path = cert_path(config, domain);
    let cert_data = tokio::fs::read(&fullchain_path)
        .await
        .map_err(|e| eyre::eyre!("Failed to read certificate file {}: {}", fullchain_path, e))?;
    let cert = acme2::openssl::x509::X509::from_pem(&cert_data)
        .map_err(|e| eyre::eyre!("Failed to parse certificate in file {}: {}", fullchain_path, e))?;
    let mut domains = Vec::new();
    if let Some(san) = cert.subject_alt_names() {
        for i in 0..san.len() {
            if let Some(d) = san.get(i) {
                if let Some(d) = d.dnsname() {
                    domains.push(d.to_string());
                }
            }
        }
    }
    // Also include the common name if present
    let cn =
        cert.subject_name().entries_by_nid(acme2::openssl::nid::Nid::COMMONNAME).next();
    if let Some(name) = cn {
        if let Ok(cn) = name.data().as_utf8() {
            let cn = cn.to_string();
            if !domains.contains(&cn) {
                domains.push(cn);
            }
        }
    }
    Ok(domains)
}