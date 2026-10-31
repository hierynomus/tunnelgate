//! Shared controller state: Kubernetes client, operator settings, Cloudflare clients and caches.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use k8s_openapi::api::core::v1::Secret;
use kube::api::Api;
use kube::runtime::reflector::Store;
use secrecy::SecretString;
use sha2::{Digest, Sha256};
use tunnelgate_api::conditions::reasons;
use tunnelgate_api::v1alpha1::{CloudflareAccount, CloudflareRef, DEFAULT_TOKEN_KEY, TunnelRoute};
use tunnelgate_cf::types::Zone;
use tunnelgate_cf::{ClientConfig, CloudflareApi};

use crate::error::Result;

/// The official cloudflared image, pinned by digest (multi-arch index).
pub const DEFAULT_CONNECTOR_IMAGE: &str =
    "cloudflare/cloudflared:2026.10.5@sha256:1b1d34d0a9c0bfca9de72db8460d328db3f19edd2b96169114e3e893a97bbe53";

/// Operator settings (from flags/env, see `main.rs`).
#[derive(Debug, Clone)]
pub struct Settings {
    /// Period of the full drift-repairing resync.
    pub resync: Duration,
    pub default_connector_image: String,
    pub default_connector_replicas: i32,
    /// Maximum ingress rules per tunnel, including the fallback.
    pub max_rules: usize,
    /// Requeue delay while a tunnel isn't Ready (e.g. waiting for connectors).
    pub not_ready_requeue: Duration,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            resync: Duration::from_secs(600),
            default_connector_image: DEFAULT_CONNECTOR_IMAGE.to_owned(),
            default_connector_replicas: 2,
            max_rules: tunnelgate_render::ingress::DEFAULT_MAX_RULES,
            not_ready_requeue: Duration::from_secs(20),
        }
    }
}

/// Builds Cloudflare clients for API tokens.
pub trait CloudflareFactory: Send + Sync {
    fn client(&self, token: SecretString) -> Result<Arc<dyn CloudflareApi>>;
}

/// Real HTTPS clients.
pub struct HttpFactory {
    pub config: ClientConfig,
}

impl CloudflareFactory for HttpFactory {
    fn client(&self, token: SecretString) -> Result<Arc<dyn CloudflareApi>> {
        Ok(Arc::new(tunnelgate_cf::Client::with_config(token, self.config.clone())?))
    }
}

pub struct Context {
    pub client: kube::Client,
    pub settings: Settings,
    /// UID of the `kube-system` namespace.
    pub cluster_id: String,
    /// Whether Gateway API's ReferenceGrant is installed (it may appear while we run).
    reference_grants: AtomicBool,
    pub routes: Store<TunnelRoute>,
    cloudflare: Arc<dyn CloudflareFactory>,
    clients: Mutex<HashMap<[u8; 32], Arc<dyn CloudflareApi>>>,
    zones: Mutex<HashMap<String, (Instant, Vec<Zone>)>>,
    account_names: Mutex<HashMap<(String, [u8; 32]), String>>,
    /// Last configuration this process applied per tunnel ID, as (hash, version). The cached
    /// Tunnel can lag behind our own status patch; without this, a reconcile on the stale object
    /// would mistake our previous PUT for an edit elsewhere and PUT again.
    applied_configs: Mutex<HashMap<String, (String, i64)>>,
    /// Last account that worked per object UID. Deleting a namespace deletes the credentials
    /// Secret alongside the objects whose cleanup needs it; cleanup falls back to this.
    last_accounts: Mutex<HashMap<String, Account>>,
}

/// A usable Cloudflare account.
#[derive(Clone)]
pub struct Account {
    pub id: String,
    pub api: Arc<dyn CloudflareApi>,
}

/// Why credentials couldn't be resolved, as condition reason and message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialError {
    pub reason: &'static str,
    pub message: String,
}

impl CredentialError {
    fn new(reason: &'static str, message: impl Into<String>) -> Self {
        Self { reason, message: message.into() }
    }
}

const ZONE_TTL: Duration = Duration::from_secs(300);

impl Context {
    /// The configuration last applied to a tunnel, by this process or (after a restart) as
    /// recorded in status.
    pub fn applied_config(&self, tunnel_id: &str, status: (Option<&str>, Option<i64>)) -> Option<(String, i64)> {
        let mem = self.applied_configs.lock().expect("poisoned").get(tunnel_id).cloned();
        mem.or_else(|| Some((status.0?.to_owned(), status.1?)))
    }

    /// Resolves credentials for the object with `uid` and remembers them for its cleanup.
    pub async fn account_for(&self, uid: &str, cf: &CloudflareRef, ns: &str) -> Result<Account, CredentialError> {
        let account = self.account(cf, ns).await?;
        self.last_accounts.lock().expect("poisoned").insert(uid.to_owned(), account.clone());
        Ok(account)
    }

    /// Credentials for cleaning up the object with `uid`: current ones, or the last that worked
    /// when they've been deleted since.
    pub async fn cleanup_account(&self, uid: &str, cf: &CloudflareRef, ns: &str) -> Result<Account, CredentialError> {
        match self.account(cf, ns).await {
            Ok(account) => Ok(account),
            Err(e) => self.last_accounts.lock().expect("poisoned").get(uid).cloned().ok_or(e),
        }
    }

    /// Drops what was remembered for an object that is gone.
    pub fn forget_object(&self, uid: &str) {
        self.last_accounts.lock().expect("poisoned").remove(uid);
    }

    pub fn forget_applied_config(&self, tunnel_id: &str) {
        self.applied_configs.lock().expect("poisoned").remove(tunnel_id);
    }

    pub fn record_applied_config(&self, tunnel_id: &str, hash: &str, version: i64) {
        self.applied_configs.lock().expect("poisoned").insert(tunnel_id.to_owned(), (hash.to_owned(), version));
    }

    pub fn new(
        client: kube::Client,
        settings: Settings,
        cluster_id: String,
        reference_grants: bool,
        routes: Store<TunnelRoute>,
        cloudflare: Arc<dyn CloudflareFactory>,
    ) -> Self {
        Self {
            client,
            settings,
            cluster_id,
            reference_grants: AtomicBool::new(reference_grants),
            routes,
            cloudflare,
            clients: Mutex::default(),
            zones: Mutex::default(),
            account_names: Mutex::default(),
            applied_configs: Mutex::default(),
            last_accounts: Mutex::default(),
        }
    }

    /// Resolves a resource's `cloudflare` block in namespace `ns` to an account and client.
    /// Whether ReferenceGrants are honoured.
    pub fn reference_grants(&self) -> bool {
        self.reference_grants.load(Ordering::Relaxed)
    }

    pub fn set_reference_grants(&self, installed: bool) {
        self.reference_grants.store(installed, Ordering::Relaxed);
    }

    pub async fn account(&self, cf: &CloudflareRef, ns: &str) -> Result<Account, CredentialError> {
        let (secret_ns, secret_name, key, account_id, account_name) = match &cf.account_ref {
            Some(name) => {
                let accounts: Api<CloudflareAccount> = Api::all(self.client.clone());
                let account = accounts
                    .get_opt(name)
                    .await
                    .map_err(|e| {
                        CredentialError::new(
                            reasons::ACCOUNT_NOT_FOUND,
                            format!("reading CloudflareAccount {name}: {e}"),
                        )
                    })?
                    .ok_or_else(|| {
                        CredentialError::new(reasons::ACCOUNT_NOT_FOUND, format!("CloudflareAccount {name} not found"))
                    })?;
                if !account.spec.allows_namespace(ns) {
                    return Err(CredentialError::new(
                        reasons::ACCOUNT_NOT_ALLOWED,
                        format!("CloudflareAccount {name} does not list namespace {ns} in allowedNamespaces"),
                    ));
                }
                let r = &account.spec.credentials_secret_ref;
                (
                    r.namespace.clone(),
                    r.name.clone(),
                    r.key.clone(),
                    account.spec.account_id.clone(),
                    account.spec.account_name.clone(),
                )
            }
            None => {
                let r = cf.credentials_secret_ref.as_ref().ok_or_else(|| {
                    CredentialError::new(
                        reasons::INVALID_SPEC,
                        "cloudflare.credentialsSecretRef is required without accountRef",
                    )
                })?;
                (ns.to_owned(), r.name.clone(), r.key.clone(), cf.account_id.clone(), cf.account_name.clone())
            }
        };
        let key = key.unwrap_or_else(|| DEFAULT_TOKEN_KEY.to_owned());
        let token = self.read_secret_key(&secret_ns, &secret_name, &key).await?;
        let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let api = self.client_for(digest, token)?;
        let id = match (account_id, account_name) {
            (Some(id), _) => id,
            (None, Some(name)) => self.account_id_by_name(&api, &name, digest).await?,
            (None, None) => {
                return Err(CredentialError::new(reasons::INVALID_SPEC, "set accountId or accountName"));
            }
        };
        Ok(Account { id, api })
    }

    async fn read_secret_key(&self, ns: &str, name: &str, key: &str) -> Result<String, CredentialError> {
        let secrets: Api<Secret> = Api::namespaced(self.client.clone(), ns);
        let secret = secrets
            .get_opt(name)
            .await
            .map_err(|e| {
                CredentialError::new(reasons::CREDENTIALS_NOT_FOUND, format!("reading Secret {ns}/{name}: {e}"))
            })?
            .ok_or_else(|| {
                CredentialError::new(reasons::CREDENTIALS_NOT_FOUND, format!("Secret {ns}/{name} not found"))
            })?;
        let value = secret
            .data
            .as_ref()
            .and_then(|d| d.get(key))
            .map(|v| String::from_utf8_lossy(&v.0).trim().to_owned())
            .or_else(|| secret.string_data.as_ref().and_then(|d| d.get(key)).map(|v| v.trim().to_owned()))
            .filter(|v| !v.is_empty())
            .ok_or_else(|| {
                CredentialError::new(reasons::CREDENTIALS_NOT_FOUND, format!("Secret {ns}/{name} has no key {key}"))
            })?;
        Ok(value)
    }

    fn client_for(&self, digest: [u8; 32], token: String) -> Result<Arc<dyn CloudflareApi>, CredentialError> {
        let mut clients = self.clients.lock().expect("clients lock");
        if let Some(c) = clients.get(&digest) {
            return Ok(c.clone());
        }
        let client = self
            .cloudflare
            .client(SecretString::from(token))
            .map_err(|e| CredentialError::new(reasons::CLOUDFLARE_ERROR, e.to_string()))?;
        clients.insert(digest, client.clone());
        Ok(client)
    }

    async fn account_id_by_name(
        &self,
        api: &Arc<dyn CloudflareApi>,
        name: &str,
        digest: [u8; 32],
    ) -> Result<String, CredentialError> {
        let cache_key = (name.to_owned(), digest);
        if let Some(id) = self.account_names.lock().expect("account cache lock").get(&cache_key) {
            return Ok(id.clone());
        }
        let accounts = api.list_accounts(Some(name)).await.map_err(|e| {
            let reason = if e.is_unauthorized() { reasons::CLOUDFLARE_UNAUTHORIZED } else { reasons::CLOUDFLARE_ERROR };
            CredentialError::new(reason, format!("looking up account {name:?} (needs Account Settings: Read): {e}"))
        })?;
        let account = accounts.into_iter().find(|a| a.name == name).ok_or_else(|| {
            CredentialError::new(
                reasons::ACCOUNT_NOT_FOUND,
                format!("no Cloudflare account named {name:?} is visible to the token"),
            )
        })?;
        self.account_names.lock().expect("account cache lock").insert(cache_key, account.id.clone());
        Ok(account.id)
    }

    /// Zones visible in an account (cached for a few minutes).
    pub async fn zones(&self, account: &Account) -> Result<Vec<Zone>> {
        if let Some((at, zones)) = self.zones.lock().expect("zone cache lock").get(&account.id)
            && at.elapsed() < ZONE_TTL
        {
            return Ok(zones.clone());
        }
        let zones = account.api.list_zones(&account.id).await?;
        self.zones.lock().expect("zone cache lock").insert(account.id.clone(), (Instant::now(), zones.clone()));
        Ok(zones)
    }

    /// Requeue delay for a healthy resource: the resync period ±10%, so resyncs spread out.
    pub fn resync_jittered(&self) -> Duration {
        use rand::RngExt;
        let base = self.settings.resync.as_secs_f64();
        Duration::from_secs_f64(base * rand::rng().random_range(0.9..1.1))
    }
}
