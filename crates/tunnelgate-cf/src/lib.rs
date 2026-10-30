//! A small typed client for the Cloudflare endpoints tunnelgate uses.
//!
//! Controllers depend on the [`CloudflareApi`] trait; [`Client`] implements it over HTTPS and
//! `tunnelgate-cf-fake` provides an in-process fake for tests.

use async_trait::async_trait;
use secrecy::SecretString;

mod error;
pub mod types;

#[cfg(feature = "client")]
mod client;
#[cfg(feature = "client")]
mod limit;

#[cfg(feature = "client")]
pub use client::{Client, ClientConfig};
pub use error::{Error, Result};
#[cfg(feature = "client")]
pub use limit::RateLimit;
use types::*;

/// The tunnelgate version: the release tag's version (`TUNNELGATE_VERSION` at build time, set by
/// `mise run dist`), else the workspace's placeholder version for development builds.
pub const VERSION: &str = match option_env!("TUNNELGATE_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

/// Default API base URL.
pub const DEFAULT_BASE_URL: &str = "https://api.cloudflare.com/client/v4";

/// The Cloudflare operations tunnelgate performs. Every method maps to one endpoint (plus
/// pagination for lists); "get" methods return `None` on 404.
#[async_trait]
pub trait CloudflareApi: Send + Sync {
    // Accounts and zones
    async fn list_accounts(&self, name: Option<&str>) -> Result<Vec<Account>>;
    async fn list_zones(&self, account_id: &str) -> Result<Vec<Zone>>;

    // Tunnels
    async fn create_tunnel(&self, account_id: &str, name: &str) -> Result<Tunnel>;
    async fn get_tunnel(&self, account_id: &str, tunnel_id: &str) -> Result<Option<Tunnel>>;
    /// Non-deleted tunnels, optionally only those with an exact name.
    async fn list_tunnels(&self, account_id: &str, name: Option<&str>) -> Result<Vec<Tunnel>>;
    async fn delete_tunnel(&self, account_id: &str, tunnel_id: &str) -> Result<()>;
    async fn get_tunnel_token(&self, account_id: &str, tunnel_id: &str) -> Result<SecretString>;
    /// Removes stale connections of a tunnel whose connectors are gone.
    async fn cleanup_tunnel_connections(&self, account_id: &str, tunnel_id: &str) -> Result<()>;
    async fn get_tunnel_configuration(&self, account_id: &str, tunnel_id: &str) -> Result<Option<TunnelConfiguration>>;
    async fn put_tunnel_configuration(
        &self,
        account_id: &str,
        tunnel_id: &str,
        config: &TunnelConfig,
    ) -> Result<TunnelConfiguration>;

    // DNS
    async fn list_dns_records(&self, zone_id: &str, filter: &DnsRecordFilter) -> Result<Vec<DnsRecord>>;
    async fn create_dns_record(&self, zone_id: &str, record: &DnsRecordInput) -> Result<DnsRecord>;
    async fn update_dns_record(&self, zone_id: &str, record_id: &str, record: &DnsRecordInput) -> Result<DnsRecord>;
    async fn delete_dns_record(&self, zone_id: &str, record_id: &str) -> Result<()>;

    // Access: reusable policies
    async fn list_access_policies(&self, account_id: &str) -> Result<Vec<AccessPolicy>>;
    async fn get_access_policy(&self, account_id: &str, policy_id: &str) -> Result<Option<AccessPolicy>>;
    async fn create_access_policy(&self, account_id: &str, policy: &AccessPolicy) -> Result<AccessPolicy>;
    async fn update_access_policy(
        &self,
        account_id: &str,
        policy_id: &str,
        policy: &AccessPolicy,
    ) -> Result<AccessPolicy>;
    async fn delete_access_policy(&self, account_id: &str, policy_id: &str) -> Result<()>;

    // Access: applications
    async fn list_access_apps(&self, account_id: &str) -> Result<Vec<AccessApplication>>;
    async fn get_access_app(&self, account_id: &str, app_id: &str) -> Result<Option<AccessApplication>>;
    async fn create_access_app(&self, account_id: &str, app: &AccessApplication) -> Result<AccessApplication>;
    async fn update_access_app(
        &self,
        account_id: &str,
        app_id: &str,
        app: &AccessApplication,
    ) -> Result<AccessApplication>;
    async fn delete_access_app(&self, account_id: &str, app_id: &str) -> Result<()>;

    // Access: service tokens
    async fn list_service_tokens(&self, account_id: &str) -> Result<Vec<ServiceToken>>;
    async fn create_service_token(&self, account_id: &str, name: &str, duration: &str) -> Result<CreatedServiceToken>;
    async fn delete_service_token(&self, account_id: &str, token_id: &str) -> Result<()>;
}
