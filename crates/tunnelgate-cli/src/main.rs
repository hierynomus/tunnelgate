//! `tunnelgate`: operator tooling that doesn't need the operator running.
//!
//! - `crdgen` prints the CRD YAML generated from the Rust types, or a Markdown reference.
//! - `sweep` lists (and deletes) Cloudflare objects marked for a cluster ID. It needs only an API
//!   token, account ID and cluster ID, so it works after the cluster is gone.

use std::io::Write;
use std::process::ExitCode;

use anyhow::Context;
use clap::{Parser, Subcommand};
use secrecy::SecretString;
use tunnelgate_cf::{Client, ClientConfig, CloudflareApi};

#[derive(Debug, Parser)]
#[command(name = "tunnelgate", version = tunnelgate_cf::VERSION, about = "tunnelgate tooling")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print the CustomResourceDefinitions as multi-document YAML.
    Crdgen {
        /// Write one file per CRD into this directory instead of printing.
        #[arg(long, conflicts_with = "markdown")]
        out_dir: Option<std::path::PathBuf>,
        /// Print a Markdown field reference instead of YAML.
        #[arg(long)]
        markdown: bool,
    },
    /// Find (and delete) Cloudflare objects created by tunnelgate for a cluster.
    Sweep {
        /// The cluster ID (UID of the cluster's kube-system namespace).
        #[arg(long)]
        cluster_id: String,
        #[arg(long, env = "CLOUDFLARE_ACCOUNT_ID")]
        account_id: String,
        /// Only list what would be deleted.
        #[arg(long)]
        dry_run: bool,
        /// Exit with status 3 when anything is found (for leftover checks).
        #[arg(long)]
        fail_on_leftovers: bool,
        #[arg(long, env = "TUNNELGATE_CLOUDFLARE_API", default_value = tunnelgate_cf::DEFAULT_BASE_URL)]
        cloudflare_api: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<ExitCode> {
    match Cli::parse().command {
        Command::Crdgen { markdown: true, .. } => {
            print!("{}", tunnelgate_cli::crd_docs::render(&tunnelgate_api::crds()));
            Ok(ExitCode::SUCCESS)
        }
        Command::Crdgen { out_dir, .. } => crdgen(out_dir),
        Command::Sweep { cluster_id, account_id, dry_run, fail_on_leftovers, cloudflare_api } => {
            let token = std::env::var("CLOUDFLARE_API_TOKEN").context("CLOUDFLARE_API_TOKEN is not set")?;
            let config = ClientConfig { base_url: cloudflare_api, ..Default::default() };
            let api = Client::with_config(SecretString::from(token), config)?;
            let found = run_sweep(&api, &cluster_id, &account_id, dry_run).await?;
            Ok(if fail_on_leftovers && found > 0 { ExitCode::from(3) } else { ExitCode::SUCCESS })
        }
    }
}

fn crdgen(out_dir: Option<std::path::PathBuf>) -> anyhow::Result<ExitCode> {
    let crds = tunnelgate_api::crds();
    match out_dir {
        Some(dir) => {
            std::fs::create_dir_all(&dir)?;
            for crd in crds {
                let name = crd.metadata.name.clone().unwrap_or_default();
                std::fs::write(dir.join(format!("{name}.yaml")), serde_saphyr::to_string(&crd)?)?;
            }
        }
        None => {
            let mut out = std::io::stdout().lock();
            for crd in crds {
                writeln!(out, "---")?;
                write!(out, "{}", serde_saphyr::to_string(&crd)?)?;
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Returns the number of objects found.
async fn run_sweep(
    api: &dyn CloudflareApi,
    cluster_id: &str,
    account_id: &str,
    dry_run: bool,
) -> anyhow::Result<usize> {
    let tunnelgate_cli::Found { leftovers: found, unreadable_zones } =
        tunnelgate_cli::find_leftovers(api, cluster_id, account_id).await?;
    for zone in &unreadable_zones {
        eprintln!("skipped\tzone\t{zone}\tthe token may not read its DNS records");
    }
    let action = if dry_run { "found" } else { "deleting" };
    for item in &found {
        println!("{action}\t{}\t{}\t{}", item.kind(), item.id(), item.describe());
        if dry_run {
            continue;
        }
        if let Err(e) = tunnelgate_cli::delete_leftover(api, account_id, item).await {
            eprintln!("failed\t{}\t{}\t{e}", item.kind(), item.id());
        }
    }
    eprintln!("{} object(s) marked for cluster {cluster_id}", found.len());
    Ok(found.len())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use tunnelgate_cf_fake::{ACCOUNT_ID, FakeCloudflare, Fault, TOKEN};

    #[tokio::test]
    async fn sweeps_only_marked_objects() {
        let fake = FakeCloudflare::start().await;
        let config = ClientConfig {
            base_url: fake.base_url(),
            initial_backoff: Duration::from_millis(1),
            rate_limit: None,
            ..Default::default()
        };
        let api = Client::with_config(SecretString::from(TOKEN), config).unwrap();
        let cluster = "3f2a9c1e-7b44-4d0e-9a51-0c8d2e6f1b7a";

        let mine = api.create_tunnel(ACCOUNT_ID, "tunnelgate-main-3f2a9c1e").await.unwrap();
        api.create_tunnel(ACCOUNT_ID, "someone-elses").await.unwrap();
        fake.set_connections(&mine.id, 1);
        fake.add_dns_record(
            "example.org",
            serde_json::json!({ "name": "a.example.org", "type": "CNAME", "content": "x", "comment": format!("tunnelgate:{cluster}/ns/Tunnel/main") }),
        );
        fake.add_dns_record(
            "example.org",
            serde_json::json!({ "name": "b.example.org", "type": "A", "content": "10.0.0.1" }),
        );

        fake.clear_log();
        assert_eq!(run_sweep(&api, cluster, ACCOUNT_ID, true).await.unwrap(), 2);
        assert!(fake.writes().is_empty(), "dry run doesn't write");
        assert_eq!(run_sweep(&api, cluster, ACCOUNT_ID, false).await.unwrap(), 2);
        assert_eq!(run_sweep(&api, cluster, ACCOUNT_ID, true).await.unwrap(), 0);
        assert_eq!(fake.live_tunnels().len(), 1);
        assert_eq!(fake.dns_records("example.org").len(), 1);
        // A zone the token may not read DNS in is skipped, not fatal.
        let zones = api.list_zones(ACCOUNT_ID).await.unwrap();
        let other = zones.iter().find(|z| z.name != "example.org").unwrap();
        fake.inject(Fault::new(Some("GET"), &format!("/zones/{}/dns_records", other.id), 403).times(5));
        let found = tunnelgate_cli::find_leftovers(&api, cluster, ACCOUNT_ID).await.unwrap();
        assert_eq!(found.unreadable_zones, vec![other.name.clone()]);
    }
}
