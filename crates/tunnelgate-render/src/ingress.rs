//! Tunnel ingress configuration: route resolution (conflicts, limits), ordering, hashing.

use std::cmp::{Ordering, Reverse};
use std::collections::BTreeMap;

use sha2::{Digest, Sha256};
use tunnelgate_api::conditions::reasons;
use tunnelgate_api::v1alpha1::{Fallback, OriginDefaults, OriginProtocol, RouteOrigin, RouteService, TunnelRouteSpec};
use tunnelgate_cf::types::{IngressRule, OriginRequest, TunnelConfig};

use crate::duration::parse_seconds;

/// Default maximum number of ingress rules (including the fallback) per tunnel configuration.
/// Cloudflare doesn't document an exact limit; this keeps the configuration a reasonable size.
pub const DEFAULT_MAX_RULES: usize = 1000;

/// Mount directory of the CA pool Secret in cloudflared pods.
pub const CA_POOL_DIR: &str = "/etc/tunnelgate/ca";

/// Identifies a route (namespace/name).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RouteKey {
    pub namespace: String,
    pub name: String,
}

impl RouteKey {
    pub fn new(namespace: &str, name: &str) -> Self {
        Self { namespace: namespace.to_owned(), name: name.to_owned() }
    }
}

impl std::fmt::Display for RouteKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.namespace, self.name)
    }
}

/// A route ready to be placed in a tunnel configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct RouteInput {
    pub key: RouteKey,
    /// Creation time (RFC 3339, UTC), used to decide which of two conflicting routes wins.
    pub created: String,
    pub hostname: String,
    pub path: Option<String>,
    pub service: String,
    pub origin: OriginRequest,
}

/// Why a route isn't in the configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejection {
    pub reason: &'static str,
    pub message: String,
}

/// Outcome of resolving a tunnel's routes.
#[derive(Debug, Clone, PartialEq)]
pub struct Resolution {
    /// In ingress order.
    pub accepted: Vec<RouteInput>,
    pub rejected: BTreeMap<RouteKey, Rejection>,
}

/// Normalized path: `None` for the whole host.
fn norm_path(path: &Option<String>) -> Option<&str> {
    path.as_deref().filter(|p| !p.is_empty())
}

fn age_order(a: &RouteInput, b: &RouteInput) -> Ordering {
    a.created.cmp(&b.created).then_with(|| a.key.cmp(&b.key))
}

/// Ingress order: exact hostnames before wildcards (more specific wildcards first), then by
/// hostname, path rules before the host's catch-all, longer paths first, then namespace/name.
pub fn ingress_order(a: &RouteInput, b: &RouteInput) -> Ordering {
    fn key(r: &RouteInput) -> impl Ord + '_ {
        let wildcard = r.hostname.starts_with("*.");
        let labels = r.hostname.split('.').count();
        let path = norm_path(&r.path);
        (
            wildcard,
            Reverse(if wildcard { labels } else { 0 }),
            r.hostname.to_ascii_lowercase(),
            path.is_none(),
            Reverse(path.map_or(0, str::len)),
            path,
            &r.key,
        )
    }
    key(a).cmp(&key(b))
}

/// Resolves conflicts (same hostname and path: the older route wins) and the rule limit (routes
/// that don't fit, newest first, are rejected), and returns the accepted routes in ingress order.
pub fn resolve(mut routes: Vec<RouteInput>, max_rules: usize) -> Resolution {
    routes.sort_by(age_order);
    let mut rejected = BTreeMap::new();
    let mut winners: BTreeMap<(String, Option<String>), RouteKey> = BTreeMap::new();
    let mut accepted = Vec::new();
    for route in routes {
        let slot = (route.hostname.to_ascii_lowercase(), norm_path(&route.path).map(str::to_owned));
        if let Some(winner) = winners.get(&slot) {
            let what = match &slot.1 {
                Some(p) => format!("hostname {} with path {p}", slot.0),
                None => format!("hostname {}", slot.0),
            };
            rejected.insert(
                route.key.clone(),
                Rejection {
                    reason: reasons::CONFLICT,
                    message: format!("{what} is already routed on this tunnel by TunnelRoute {winner}, which is older"),
                },
            );
            continue;
        }
        winners.insert(slot, route.key.clone());
        accepted.push(route);
    }
    let room = max_rules.saturating_sub(1);
    if accepted.len() > room {
        for route in accepted.split_off(room) {
            rejected.insert(
                route.key.clone(),
                Rejection {
                    reason: reasons::CONFIG_LIMIT,
                    message: format!(
                        "the tunnel configuration is full ({max_rules} rules including the fallback); \
                         newer routes are not applied"
                    ),
                },
            );
        }
    }
    accepted.sort_by(ingress_order);
    Resolution { accepted, rejected }
}

/// Builds the remote configuration for accepted routes (already in ingress order).
pub fn render(accepted: &[RouteInput], defaults: OriginRequest, fallback: &Fallback) -> TunnelConfig {
    let mut ingress: Vec<IngressRule> = accepted
        .iter()
        .map(|r| IngressRule {
            hostname: Some(r.hostname.clone()),
            path: norm_path(&r.path).map(str::to_owned),
            service: r.service.clone(),
            origin_request: r.origin.clone(),
        })
        .collect();
    ingress.push(IngressRule { service: fallback_service(fallback), ..Default::default() });
    TunnelConfig { ingress, origin_request: defaults }
}

pub fn fallback_service(fallback: &Fallback) -> String {
    match (&fallback.service, fallback.status) {
        (Some(service), _) => service.clone(),
        (None, Some(status)) => format!("http_status:{status}"),
        (None, None) => "http_status:404".to_owned(),
    }
}

/// Stable hash of a rendered configuration.
pub fn config_hash(config: &TunnelConfig) -> String {
    // Struct fields serialize in declaration order, so the encoding is deterministic.
    let bytes = serde_json::to_vec(config).expect("tunnel config serializes");
    hex::encode(&Sha256::digest(&bytes)[..16])
}

/// Tunnel-wide `originRequest` from `Tunnel.spec.originDefaults`.
pub fn origin_defaults(d: &OriginDefaults) -> Result<OriginRequest, String> {
    let secs = |v: &Option<String>, field: &str| {
        v.as_deref().map(parse_seconds).transpose().map_err(|e| format!("originDefaults.{field}: {e}"))
    };
    Ok(OriginRequest {
        connect_timeout: secs(&d.connect_timeout, "connectTimeout")?,
        tls_timeout: secs(&d.tls_timeout, "tlsTimeout")?,
        keep_alive_timeout: secs(&d.keep_alive_timeout, "keepAliveTimeout")?,
        keep_alive_connections: d.keep_alive_connections,
        no_happy_eyeballs: d.no_happy_eyeballs,
        no_tls_verify: d.no_tls_verify,
        disable_chunked_encoding: d.disable_chunked_encoding,
        http2_origin: d.http2_origin,
        ca_pool: d.ca_pool_secret_ref.as_ref().map(|r| ca_pool_path(r.key.as_deref())),
        ..Default::default()
    })
}

/// Path of the CA bundle inside cloudflared pods.
pub fn ca_pool_path(key: Option<&str>) -> String {
    format!("{CA_POOL_DIR}/{}", key.unwrap_or("ca.crt"))
}

/// Per-rule `originRequest` from `TunnelRoute.spec.origin`.
pub fn route_origin(o: &RouteOrigin) -> Result<OriginRequest, String> {
    let secs = |v: &Option<String>, field: &str| {
        v.as_deref().map(parse_seconds).transpose().map_err(|e| format!("origin.{field}: {e}"))
    };
    Ok(OriginRequest {
        connect_timeout: secs(&o.connect_timeout, "connectTimeout")?,
        keep_alive_timeout: secs(&o.keep_alive_timeout, "keepAliveTimeout")?,
        no_happy_eyeballs: o.no_happy_eyeballs,
        http_host_header: o.http_host_header.clone(),
        origin_server_name: o.server_name.clone(),
        no_tls_verify: o.no_tls_verify,
        disable_chunked_encoding: o.disable_chunked_encoding,
        http2_origin: o.http2,
        ..Default::default()
    })
}

/// The cloudflared `service` for a route. For `backendRef`, `backend_ns` is the resolved
/// namespace of the Service.
pub fn service_target(
    service: &RouteService,
    backend_ns: &str,
    protocol: Option<OriginProtocol>,
) -> Result<String, String> {
    match (&service.backend_ref, &service.url, service.status) {
        (Some(b), None, None) => {
            let scheme = protocol.unwrap_or_default().scheme();
            Ok(format!("{scheme}://{}.{backend_ns}.svc:{}", b.name, b.port))
        }
        (None, Some(url), None) => {
            if !(url.contains("://") || url.starts_with("unix:")) {
                return Err(format!("service.url {url:?} needs a scheme, e.g. https://10.0.0.1:443"));
            }
            Ok(url.clone())
        }
        (None, None, Some(status)) => Ok(format!("http_status:{status}")),
        _ => Err("set exactly one of service.backendRef, service.url or service.status".to_owned()),
    }
}

/// Builds the [`RouteInput`] for a route spec, with its Service namespace already resolved.
pub fn route_input(
    key: RouteKey,
    created: String,
    spec: &TunnelRouteSpec,
    backend_ns: &str,
) -> Result<RouteInput, String> {
    let origin = spec.origin.clone().unwrap_or_default();
    Ok(RouteInput {
        key,
        created,
        hostname: spec.hostname.to_ascii_lowercase(),
        path: norm_path(&spec.path).map(str::to_owned),
        service: service_target(&spec.service, backend_ns, origin.protocol)?,
        origin: route_origin(&origin)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(ns: &str, name: &str, created: &str, host: &str, path: Option<&str>) -> RouteInput {
        RouteInput {
            key: RouteKey::new(ns, name),
            created: created.to_owned(),
            hostname: host.to_owned(),
            path: path.map(str::to_owned),
            service: format!("http://{name}.{ns}.svc:80"),
            origin: OriginRequest::default(),
        }
    }

    fn order(res: &Resolution) -> Vec<String> {
        res.accepted.iter().map(|r| format!("{}{}", r.hostname, r.path.as_deref().unwrap_or(""))).collect()
    }

    #[test]
    fn orders_exact_before_wildcard_paths_before_catch_all() {
        let routes = vec![
            route("a", "wild", "2026-01-01T00:00:00Z", "*.corp.example.org", None),
            route("a", "wild-apps", "2026-01-01T00:00:01Z", "*.apps.corp.example.org", None),
            route("a", "rancher", "2026-01-01T00:00:02Z", "rancher.corp.example.org", None),
            route("a", "connect", "2026-01-01T00:00:03Z", "rancher.corp.example.org", Some("/v3/connect")),
            route("a", "connect-reg", "2026-01-01T00:00:04Z", "rancher.corp.example.org", Some("/v3/connect/register")),
            route("a", "demo", "2026-01-01T00:00:05Z", "demo.apps.corp.example.org", None),
        ];
        let res = resolve(routes.clone(), DEFAULT_MAX_RULES);
        assert!(res.rejected.is_empty());
        assert_eq!(
            order(&res),
            [
                "demo.apps.corp.example.org",
                "rancher.corp.example.org/v3/connect/register",
                "rancher.corp.example.org/v3/connect",
                "rancher.corp.example.org",
                "*.apps.corp.example.org",
                "*.corp.example.org",
            ]
        );
        // Input order doesn't matter.
        let mut reversed = routes;
        reversed.reverse();
        assert_eq!(resolve(reversed, DEFAULT_MAX_RULES), res);
    }

    #[test]
    fn older_route_wins_conflict() {
        let res = resolve(
            vec![
                route("b", "new", "2026-02-01T00:00:00Z", "x.example.org", Some("")),
                route("a", "old", "2026-01-01T00:00:00Z", "X.example.org", None),
                route("c", "other-path", "2026-03-01T00:00:00Z", "x.example.org", Some("/api")),
            ],
            DEFAULT_MAX_RULES,
        );
        assert_eq!(res.accepted.iter().map(|r| r.key.to_string()).collect::<Vec<_>>(), ["c/other-path", "a/old"]);
        let rej = &res.rejected[&RouteKey::new("b", "new")];
        assert_eq!(rej.reason, reasons::CONFLICT);
        assert!(rej.message.contains("a/old"), "{}", rej.message);
    }

    #[test]
    fn limit_rejects_newest() {
        let routes = (0..5).map(|i| {
            route("a", &format!("r{i}"), &format!("2026-01-01T00:00:0{i}Z"), &format!("h{i}.example.org"), None)
        });
        let res = resolve(routes.collect(), 4);
        assert_eq!(res.accepted.len(), 3);
        assert_eq!(res.rejected.keys().map(ToString::to_string).collect::<Vec<_>>(), ["a/r3", "a/r4"]);
        assert!(res.rejected.values().all(|r| r.reason == reasons::CONFIG_LIMIT));
    }

    #[test]
    fn renders_and_hashes_stably() {
        let mut rancher = route("cattle-system", "rancher", "2026-01-01T00:00:00Z", "rancher.example.org", None);
        rancher.service = "https://rke2-traefik.kube-system.svc:443".into();
        rancher.origin = route_origin(&RouteOrigin {
            protocol: Some(OriginProtocol::Https),
            server_name: Some("rancher.example.org".into()),
            http_host_header: Some("rancher.example.org".into()),
            ..Default::default()
        })
        .unwrap();
        let defaults = origin_defaults(&OriginDefaults {
            connect_timeout: Some("30s".into()),
            keep_alive_timeout: Some("90s".into()),
            ca_pool_secret_ref: Some(tunnelgate_api::v1alpha1::SecretKeyRef { name: "origin-ca".into(), key: None }),
            ..Default::default()
        })
        .unwrap();
        let res = resolve(vec![rancher], DEFAULT_MAX_RULES);
        let config = render(&res.accepted, defaults, &Fallback::default());
        insta::with_settings!({ prepend_module_to_snapshot => false }, {
            insta::assert_json_snapshot!("tunnel-config", config);
        });
        let hash = config_hash(&config);
        assert_eq!(hash, config_hash(&config.clone()));
        let mut other = config.clone();
        other.ingress[0].path = Some("/x".into());
        assert_ne!(hash, config_hash(&other));
        insta::with_settings!({ prepend_module_to_snapshot => false }, {
            insta::assert_snapshot!("tunnel-config-hash", hash);
        });
    }

    #[test]
    fn service_targets() {
        use tunnelgate_api::v1alpha1::BackendRef;
        let backend = RouteService {
            backend_ref: Some(BackendRef { name: "rke2-traefik".into(), namespace: None, port: 443 }),
            ..Default::default()
        };
        assert_eq!(
            service_target(&backend, "kube-system", Some(OriginProtocol::Https)).unwrap(),
            "https://rke2-traefik.kube-system.svc:443"
        );
        assert_eq!(service_target(&backend, "ns", None).unwrap(), "http://rke2-traefik.ns.svc:443");
        let status = RouteService { status: Some(503), ..Default::default() };
        assert_eq!(service_target(&status, "ns", None).unwrap(), "http_status:503");
        let url = RouteService { url: Some("10.0.0.1:443".into()), ..Default::default() };
        assert!(service_target(&url, "ns", None).is_err());
        assert_eq!(fallback_service(&Fallback { status: None, service: Some("http://x:80".into()) }), "http://x:80");
    }
}
