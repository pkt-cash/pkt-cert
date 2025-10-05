use std::sync::Arc;

use eyre::{bail, Result};
use hickory_resolver::TokioResolver;
use tokio::{sync::Semaphore, task::JoinSet};

use crate::config::Config;

async fn get_possible_tlds(conf: &Config) -> Result<Vec<String>> {
    for service in &conf.pkt_domain_service {
        let resp = reqwest::get(service).await?;
        if !resp.status().is_success() {
            eprintln!("Failed to fetch domains from {}: HTTP {}", service, resp.status());
            continue;
        }
        let domains: Vec<String> = resp.json().await?;
        if domains.is_empty() {
            eprintln!("No domains found from {}", service);
            continue;
        }
        return Ok(domains);
    }
    bail!("Failed to fetch active domains from all services");
}

pub async fn get_valid_tlds(conf: &Config) -> Result<Vec<String>> {
    let possible = get_possible_tlds(conf).await?;
    println!("Checking {} PKT TLDs", possible.len());

    let resolver = TokioResolver::builder_tokio()?
        .build();

    let mut valid = Vec::new();

    let mut js = JoinSet::new();
    for d in possible {
        let r1 = resolver.clone();
        js.spawn(async move { (d.clone(), r1.ns_lookup(d).await,) });
    }
    while let Some(res) = js.join_next().await {
        match res? {
            (d, Ok(ns_response)) => {
                let mut ok = false;
                for ns in ns_response.iter() {
                    let ns_name = ns.to_utf8();
                    if ns_name.contains("pns.") {
                        ok = true;
                        break;
                    }
                }
                if ok {
                    if false {
                        println!("Domain {} is valid", d);
                    }
                    valid.push(d.clone());
                } else {
                    if false {
                        println!("Domain {} is invalid (no pns. nameserver)", d);
                    }
                }
            }
            _ =>  {}
        }
    }

    println!("Found {} valid PKT TLDs", valid.len());
    Ok(valid)
}

async fn precheck_one_tld(fqdn: &str, cookie: &str) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap();
    let url = format!("http://{}/.well-known/acme-challenge/pkt-cookie", fqdn);
    match client.get(&url).send().await {
        Ok(resp) => {
            if resp.status().is_success() {
                match resp.text().await {
                    Ok(text) => {
                        if text.trim() == cookie {
                            return Ok(());
                        } else {
                            bail!("Invalid cookie");
                        }
                    }
                    Err(e) => {
                        bail!("Error reading response: {}", e);
                    }
                }
            } else {
                bail!("Failed: HTTP {}", resp.status());
            }
        }
        Err(e) => {
            bail!("Error: {}", e);
        }
    }
}

/// Get the list of TLDs for which `domain` is valid.
/// Suppose domain = cjd.pkt and the tld list contains pkt.com and pkt.net
/// We check for /.well-known/acme-challenge/pkt-cookie on cjd.pkt.com and cjd.pkt.net
/// Then we return the ones which had the correct cookie.
/// Those ones will later be used for obtaining the certificate.
pub async fn precheck_domain(domain: &str, all_tlds: &[String], cookie: &str) -> Result<Vec<String>> {
    // use http only, not https
    let mut valid = Vec::new();
    let domain = domain.strip_suffix(".pkt").unwrap_or(domain);
    let mut js = JoinSet::new();
    let sema = Arc::new(Semaphore::new(5));
    for tld in all_tlds {
        let fqdn = format!("{}.{}", domain, tld);
        let tld = tld.clone();
        let cookie = cookie.to_string();
        let sema = Arc::clone(&sema);
        js.spawn(async move {
            let _handle = sema.acquire().await.unwrap();
            (
                precheck_one_tld(&fqdn, &cookie).await,
                fqdn,
                tld,
            )
        });
    }
    while let Some(res) = js.join_next().await {
        match res? {
            (Ok(()), fqdn, tld) => {
                if false {
                    println!("HTTP: {} -> OK", fqdn);
                }
                valid.push(tld.clone());
            }
            (Err(e), fqdn, _) => {
                if false {
                    println!("HTTP: {} -> FAILED ({})", fqdn, e);
                }
            }
        }
    }
    Ok(valid)
}
