//! Library part of the `tunnelgate` CLI, shared with the end-to-end tests.

pub mod crd_docs;

use anyhow::Context;
use tunnelgate_cf::CloudflareApi;
use tunnelgate_cf::types::DnsRecordFilter;
use tunnelgate_render::marker::OwnerMarker;
use tunnelgate_render::sweep::{self, Leftover};

#[derive(Debug, Default)]
pub struct Found {
    /// In safe deletion order.
    pub leftovers: Vec<Leftover>,
    /// Zones whose DNS records the token may not read. The operator can't have created records
    /// there with this token, but a token with fewer rights than the operator's may miss some.
    pub unreadable_zones: Vec<String>,
}

/// Every Cloudflare object marked for `cluster_id`.
pub async fn find_leftovers(api: &dyn CloudflareApi, cluster_id: &str, account_id: &str) -> anyhow::Result<Found> {
    let prefix = OwnerMarker::cluster_prefix(cluster_id);
    let mut dns = Vec::new();
    let mut unreadable_zones = Vec::new();
    for zone in api.list_zones(account_id).await.context("listing zones")? {
        let filter = DnsRecordFilter { comment_startswith: Some(prefix.clone()), ..Default::default() };
        match api.list_dns_records(&zone.id, &filter).await {
            Ok(records) => dns.extend(records.into_iter().map(|r| (zone.id.clone(), r))),
            Err(e) if e.status() == Some(403) => unreadable_zones.push(zone.name),
            Err(e) => return Err(e).with_context(|| format!("listing DNS records in {}", zone.name)),
        }
    }
    let apps = api.list_access_apps(account_id).await.context("listing Access applications")?;
    let policies = api.list_access_policies(account_id).await.context("listing Access policies")?;
    let tokens = api.list_service_tokens(account_id).await.context("listing service tokens")?;
    let tunnels = api.list_tunnels(account_id, None).await.context("listing tunnels")?;
    let leftovers = sweep::select(cluster_id, &dns, &apps, &policies, &tokens, &tunnels);
    Ok(Found { leftovers, unreadable_zones })
}

pub async fn delete_leftover(api: &dyn CloudflareApi, account_id: &str, item: &Leftover) -> tunnelgate_cf::Result<()> {
    match item {
        Leftover::DnsRecord { zone_id, id, .. } => api.delete_dns_record(zone_id, id).await,
        Leftover::AccessApplication { id, .. } => api.delete_access_app(account_id, id).await,
        Leftover::AccessPolicy { id, .. } => api.delete_access_policy(account_id, id).await,
        Leftover::ServiceToken { id, .. } => api.delete_service_token(account_id, id).await,
        Leftover::Tunnel { id, .. } => {
            api.cleanup_tunnel_connections(account_id, id).await?;
            api.delete_tunnel(account_id, id).await
        }
    }
}
