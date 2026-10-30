use std::time::Duration;

use async_trait::async_trait;
use rand::Rng;
use reqwest::{Method, StatusCode, header};
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::limit::{Limiter, RateLimit};
use crate::types::*;
use crate::{CloudflareApi, DEFAULT_BASE_URL, Error, Result};

const PER_PAGE: u32 = 100;
const DNS_PER_PAGE: u32 = 1000;

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub base_url: String,
    /// Retries after the first attempt on 429/5xx/transport errors (POSTs only retry 429).
    pub max_retries: u32,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
    pub timeout: Duration,
    /// Client-side request budget; `None` sends as fast as the caller asks.
    pub rate_limit: Option<RateLimit>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            base_url: DEFAULT_BASE_URL.to_owned(),
            max_retries: 4,
            initial_backoff: Duration::from_millis(500),
            max_backoff: Duration::from_secs(30),
            timeout: Duration::from_secs(30),
            rate_limit: Some(RateLimit::default()),
        }
    }
}

/// HTTPS implementation of [`CloudflareApi`] with an API token.
#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    token: SecretString,
    config: ClientConfig,
    limiter: Option<Limiter>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client").field("base_url", &self.config.base_url).finish_non_exhaustive()
    }
}

impl Client {
    pub fn new(token: SecretString) -> Result<Self> {
        Self::with_config(token, ClientConfig::default())
    }

    pub fn with_config(token: SecretString, config: ClientConfig) -> Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("tunnelgate/", env!("CARGO_PKG_VERSION")))
            .timeout(config.timeout)
            .build()
            .map_err(|e| Error::Transport { method: "INIT", path: String::new(), message: e.to_string() })?;
        let limiter = config.rate_limit.map(Limiter::new);
        Ok(Self { http, token, config, limiter })
    }

    async fn send<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<&Value>,
    ) -> Result<Envelope<T>> {
        let method_name = method_name(&method);
        let url = format!("{}{}", self.config.base_url.trim_end_matches('/'), path);
        let mut attempt = 0;
        loop {
            if let Some(limiter) = &self.limiter {
                limiter.acquire().await;
            }
            let mut req = self
                .http
                .request(method.clone(), &url)
                .header(header::AUTHORIZATION, format!("Bearer {}", self.token.expose_secret()))
                .query(query);
            if let Some(body) = body {
                req = req.json(body);
            }
            let outcome = req.send().await;
            let retry_after = match &outcome {
                Ok(resp) if is_retryable_status(resp.status(), &method) => Some(retry_after(resp)),
                Err(_) if method != Method::POST => Some(None),
                _ => None,
            };
            if let Some(hint) = retry_after
                && attempt < self.config.max_retries
            {
                let wait = hint.unwrap_or_else(|| self.backoff(attempt));
                if let (Some(limiter), Ok(resp)) = (&self.limiter, &outcome)
                    && resp.status() == StatusCode::TOO_MANY_REQUESTS
                {
                    limiter.pause(wait);
                }
                tracing::debug!(method = method_name, path, attempt, ?wait, "retrying cloudflare request");
                tokio::time::sleep(wait).await;
                attempt += 1;
                continue;
            }
            let resp = outcome.map_err(|e| Error::Transport {
                method: method_name,
                path: path.to_owned(),
                message: e.without_url().to_string(),
            })?;
            return decode(method_name, path, resp).await;
        }
    }

    fn backoff(&self, attempt: u32) -> Duration {
        let base = self.config.initial_backoff.saturating_mul(2u32.saturating_pow(attempt));
        let capped = base.min(self.config.max_backoff);
        // Full jitter.
        let millis = rand::rng().random_range(0..=capped.as_millis().max(1) as u64);
        Duration::from_millis(millis)
    }

    async fn get<T: DeserializeOwned>(&self, path: &str, query: &[(&str, String)]) -> Result<T> {
        let env = self.send::<T>(Method::GET, path, query, None).await?;
        require_result("GET", path, env)
    }

    async fn get_opt<T: DeserializeOwned>(&self, path: &str) -> Result<Option<T>> {
        match self.get(path, &[]).await {
            Ok(v) => Ok(Some(v)),
            Err(e) if e.is_not_found() => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn write<T: DeserializeOwned, B: Serialize + Sync>(&self, method: Method, path: &str, body: &B) -> Result<T> {
        let name = method_name(&method);
        let body = serde_json::to_value(body).map_err(|e| Error::Decode {
            method: name,
            path: path.to_owned(),
            message: e.to_string(),
        })?;
        let env = self.send::<T>(method, path, &[], Some(&body)).await?;
        require_result(name, path, env)
    }

    async fn delete(&self, path: &str) -> Result<()> {
        match self.send::<Value>(Method::DELETE, path, &[], None).await {
            Ok(_) => Ok(()),
            Err(e) if e.is_not_found() => Ok(()),
            Err(e) => Err(e),
        }
    }

    async fn paginate<T: DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, String)],
        per_page: u32,
    ) -> Result<Vec<T>> {
        let mut out = Vec::new();
        let mut page = 1u32;
        loop {
            let mut q = query.to_vec();
            q.push(("page", page.to_string()));
            q.push(("per_page", per_page.to_string()));
            let env = self.send::<Vec<T>>(Method::GET, path, &q, None).await?;
            let info = env.result_info.clone();
            let items = env.result.unwrap_or_default();
            let n = items.len() as u32;
            out.extend(items);
            let more = match info {
                Some(ResultInfo { total_pages: Some(total), .. }) => page < total,
                Some(ResultInfo { total_count, .. }) if total_count > 0 => (out.len() as u32) < total_count,
                _ => n == per_page,
            };
            if !more || n == 0 {
                return Ok(out);
            }
            page += 1;
        }
    }
}

fn method_name(method: &Method) -> &'static str {
    match *method {
        Method::GET => "GET",
        Method::POST => "POST",
        Method::PUT => "PUT",
        Method::PATCH => "PATCH",
        Method::DELETE => "DELETE",
        _ => "OTHER",
    }
}

fn is_retryable_status(status: StatusCode, method: &Method) -> bool {
    status == StatusCode::TOO_MANY_REQUESTS || (status.is_server_error() && method != Method::POST)
}

fn retry_after(resp: &reqwest::Response) -> Option<Duration> {
    let secs: u64 = resp.headers().get(header::RETRY_AFTER)?.to_str().ok()?.trim().parse().ok()?;
    Some(Duration::from_secs(secs.min(120)))
}

async fn decode<T: DeserializeOwned>(method: &'static str, path: &str, resp: reqwest::Response) -> Result<Envelope<T>> {
    let status = resp.status();
    let bytes = resp.bytes().await.map_err(|e| Error::Transport {
        method,
        path: path.to_owned(),
        message: e.without_url().to_string(),
    })?;
    if !status.is_success() {
        let errors = serde_json::from_slice::<Envelope<Value>>(&bytes).map(|e| e.errors).unwrap_or_default();
        return Err(Error::Api { method, path: path.to_owned(), status: status.as_u16(), errors });
    }
    let env: Envelope<T> = serde_json::from_slice(&bytes).map_err(|e| Error::Decode {
        method,
        path: path.to_owned(),
        message: redact_quoted(&e.to_string()),
    })?;
    if !env.success {
        return Err(Error::Api { method, path: path.to_owned(), status: status.as_u16(), errors: env.errors });
    }
    Ok(env)
}

/// serde_json quotes the offending value (`invalid type: string "…"`), which may be a token or a
/// client secret; keep the message, drop the value. Field names use backticks and survive.
fn redact_quoted(msg: &str) -> String {
    let mut out = String::with_capacity(msg.len());
    let mut inside = false;
    for c in msg.chars() {
        if c == '"' {
            if !inside {
                out.push_str("\"<redacted>\"");
            }
            inside = !inside;
        } else if !inside {
            out.push(c);
        }
    }
    out
}

fn require_result<T>(method: &'static str, path: &str, env: Envelope<T>) -> Result<T> {
    env.result.ok_or_else(|| Error::Decode { method, path: path.to_owned(), message: "missing result".to_owned() })
}

fn enc(segment: &str) -> String {
    // IDs are hex/UUIDs; anything else is rejected rather than allowed to alter the path.
    segment.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').collect()
}

#[async_trait]
impl CloudflareApi for Client {
    async fn list_accounts(&self, name: Option<&str>) -> Result<Vec<Account>> {
        let q: Vec<_> = name.map(|n| ("name", n.to_owned())).into_iter().collect();
        self.paginate("/accounts", &q, PER_PAGE).await
    }

    async fn list_zones(&self, account_id: &str) -> Result<Vec<Zone>> {
        self.paginate("/zones", &[("account.id", account_id.to_owned())], PER_PAGE).await
    }

    async fn create_tunnel(&self, account_id: &str, name: &str) -> Result<Tunnel> {
        let path = format!("/accounts/{}/cfd_tunnel", enc(account_id));
        self.write(Method::POST, &path, &CreateTunnel { name, config_src: "cloudflare" }).await
    }

    async fn get_tunnel(&self, account_id: &str, tunnel_id: &str) -> Result<Option<Tunnel>> {
        self.get_opt(&format!("/accounts/{}/cfd_tunnel/{}", enc(account_id), enc(tunnel_id))).await
    }

    async fn list_tunnels(&self, account_id: &str, name: Option<&str>) -> Result<Vec<Tunnel>> {
        let mut q = vec![("is_deleted", "false".to_owned())];
        if let Some(n) = name {
            q.push(("name", n.to_owned()));
        }
        self.paginate(&format!("/accounts/{}/cfd_tunnel", enc(account_id)), &q, PER_PAGE).await
    }

    async fn delete_tunnel(&self, account_id: &str, tunnel_id: &str) -> Result<()> {
        self.delete(&format!("/accounts/{}/cfd_tunnel/{}", enc(account_id), enc(tunnel_id))).await
    }

    async fn get_tunnel_token(&self, account_id: &str, tunnel_id: &str) -> Result<SecretString> {
        let path = format!("/accounts/{}/cfd_tunnel/{}/token", enc(account_id), enc(tunnel_id));
        let token: String = self.get(&path, &[]).await?;
        Ok(SecretString::from(token))
    }

    async fn cleanup_tunnel_connections(&self, account_id: &str, tunnel_id: &str) -> Result<()> {
        self.delete(&format!("/accounts/{}/cfd_tunnel/{}/connections", enc(account_id), enc(tunnel_id))).await
    }

    async fn get_tunnel_configuration(&self, account_id: &str, tunnel_id: &str) -> Result<Option<TunnelConfiguration>> {
        self.get_opt(&format!("/accounts/{}/cfd_tunnel/{}/configurations", enc(account_id), enc(tunnel_id))).await
    }

    async fn put_tunnel_configuration(
        &self,
        account_id: &str,
        tunnel_id: &str,
        config: &TunnelConfig,
    ) -> Result<TunnelConfiguration> {
        let path = format!("/accounts/{}/cfd_tunnel/{}/configurations", enc(account_id), enc(tunnel_id));
        let body = TunnelConfigurationBody { config: config.clone() };
        self.write(Method::PUT, &path, &body).await
    }

    async fn list_dns_records(&self, zone_id: &str, filter: &DnsRecordFilter) -> Result<Vec<DnsRecord>> {
        let mut q = Vec::new();
        if let Some(n) = &filter.name {
            q.push(("name.exact", n.clone()));
        }
        if let Some(t) = &filter.record_type {
            q.push(("type", t.clone()));
        }
        if let Some(c) = &filter.comment_startswith {
            q.push(("comment.startswith", c.clone()));
        }
        self.paginate(&format!("/zones/{}/dns_records", enc(zone_id)), &q, DNS_PER_PAGE).await
    }

    async fn create_dns_record(&self, zone_id: &str, record: &DnsRecordInput) -> Result<DnsRecord> {
        self.write(Method::POST, &format!("/zones/{}/dns_records", enc(zone_id)), record).await
    }

    async fn update_dns_record(&self, zone_id: &str, record_id: &str, record: &DnsRecordInput) -> Result<DnsRecord> {
        let path = format!("/zones/{}/dns_records/{}", enc(zone_id), enc(record_id));
        self.write(Method::PUT, &path, record).await
    }

    async fn delete_dns_record(&self, zone_id: &str, record_id: &str) -> Result<()> {
        self.delete(&format!("/zones/{}/dns_records/{}", enc(zone_id), enc(record_id))).await
    }

    async fn list_access_policies(&self, account_id: &str) -> Result<Vec<AccessPolicy>> {
        self.paginate(&format!("/accounts/{}/access/policies", enc(account_id)), &[], PER_PAGE).await
    }

    async fn get_access_policy(&self, account_id: &str, policy_id: &str) -> Result<Option<AccessPolicy>> {
        self.get_opt(&format!("/accounts/{}/access/policies/{}", enc(account_id), enc(policy_id))).await
    }

    async fn create_access_policy(&self, account_id: &str, policy: &AccessPolicy) -> Result<AccessPolicy> {
        self.write(Method::POST, &format!("/accounts/{}/access/policies", enc(account_id)), policy).await
    }

    async fn update_access_policy(
        &self,
        account_id: &str,
        policy_id: &str,
        policy: &AccessPolicy,
    ) -> Result<AccessPolicy> {
        let path = format!("/accounts/{}/access/policies/{}", enc(account_id), enc(policy_id));
        self.write(Method::PUT, &path, policy).await
    }

    async fn delete_access_policy(&self, account_id: &str, policy_id: &str) -> Result<()> {
        self.delete(&format!("/accounts/{}/access/policies/{}", enc(account_id), enc(policy_id))).await
    }

    async fn list_access_apps(&self, account_id: &str) -> Result<Vec<AccessApplication>> {
        self.paginate(&format!("/accounts/{}/access/apps", enc(account_id)), &[], PER_PAGE).await
    }

    async fn get_access_app(&self, account_id: &str, app_id: &str) -> Result<Option<AccessApplication>> {
        self.get_opt(&format!("/accounts/{}/access/apps/{}", enc(account_id), enc(app_id))).await
    }

    async fn create_access_app(&self, account_id: &str, app: &AccessApplication) -> Result<AccessApplication> {
        self.write(Method::POST, &format!("/accounts/{}/access/apps", enc(account_id)), app).await
    }

    async fn update_access_app(
        &self,
        account_id: &str,
        app_id: &str,
        app: &AccessApplication,
    ) -> Result<AccessApplication> {
        let path = format!("/accounts/{}/access/apps/{}", enc(account_id), enc(app_id));
        self.write(Method::PUT, &path, app).await
    }

    async fn delete_access_app(&self, account_id: &str, app_id: &str) -> Result<()> {
        self.delete(&format!("/accounts/{}/access/apps/{}", enc(account_id), enc(app_id))).await
    }

    async fn list_service_tokens(&self, account_id: &str) -> Result<Vec<ServiceToken>> {
        self.paginate(&format!("/accounts/{}/access/service_tokens", enc(account_id)), &[], PER_PAGE).await
    }

    async fn create_service_token(&self, account_id: &str, name: &str, duration: &str) -> Result<CreatedServiceToken> {
        let path = format!("/accounts/{}/access/service_tokens", enc(account_id));
        self.write(Method::POST, &path, &serde_json::json!({ "name": name, "duration": duration })).await
    }

    async fn delete_service_token(&self, account_id: &str, token_id: &str) -> Result<()> {
        self.delete(&format!("/accounts/{}/access/service_tokens/{}", enc(account_id), enc(token_id))).await
    }
}

#[cfg(test)]
mod tests {
    use super::redact_quoted;

    #[test]
    fn decode_errors_drop_values() {
        let e = serde_json::from_str::<u32>(r#""eyJhIjoic2VjcmV0In0""#).unwrap_err().to_string();
        assert!(e.contains("eyJ"), "serde_json quotes the value: {e}");
        let r = redact_quoted(&e);
        assert!(!r.contains("eyJ"), "{r}");
        assert!(r.contains("invalid type: string \"<redacted>\""), "{r}");
        assert_eq!(redact_quoted("missing field `client_id` at line 1"), "missing field `client_id` at line 1");
    }
}
