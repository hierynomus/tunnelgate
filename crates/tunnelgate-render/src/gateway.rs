//! Gateway API adapter logic, without I/O: minimal `gateway.networking.k8s.io/v1` types
//! for exactly the fields the adapter reads (unknown fields are ignored, so any v1.x bundle from
//! v1.2 on works), listener admission, hostname intersection, and HTTPRoute → TunnelRoute
//! translation.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tunnelgate_api::DOMAIN;
use tunnelgate_api::v1alpha1::{
    BackendRef, ObjectRef, OriginProtocol, RouteAccess, RouteDns, RouteOrigin, RouteService, TunnelRouteSpec,
};

pub const GROUP: &str = "gateway.networking.k8s.io";
/// `GatewayClass.spec.controllerName` handled by tunnelgate.
pub const CONTROLLER_NAME: &str = "tunnelgate.geeko.me/tunnel";

/// Gateway annotation naming its Tunnel: `<namespace>/<name>`, or `<name>` in the Gateway's
/// namespace.
pub fn tunnel_annotation() -> String {
    format!("{DOMAIN}/tunnel")
}
/// HTTPRoute annotations for origin settings and Access.
pub fn origin_protocol_annotation() -> String {
    format!("{DOMAIN}/origin-protocol")
}
pub fn origin_server_name_annotation() -> String {
    format!("{DOMAIN}/origin-server-name")
}
pub fn origin_no_tls_verify_annotation() -> String {
    format!("{DOMAIN}/origin-no-tls-verify")
}
pub fn access_applications_annotation() -> String {
    format!("{DOMAIN}/access-applications")
}
/// Label on generated TunnelRoutes: UID of the HTTPRoute they come from.
pub fn httproute_uid_label() -> String {
    format!("{DOMAIN}/httproute-uid")
}
/// Annotation on generated TunnelRoutes: the Gateway (`<namespace>/<name>`) that attaches them to
/// the Tunnel. It stands in for a grant: see [`gateway_permits`].
pub fn gateway_annotation() -> String {
    format!("{DOMAIN}/gateway")
}

/// Route condition reasons from the Gateway API spec.
pub mod reasons {
    pub const ACCEPTED: &str = "Accepted";
    pub const NO_MATCHING_PARENT: &str = "NoMatchingParent";
    pub const NOT_ALLOWED_BY_LISTENERS: &str = "NotAllowedByListeners";
    pub const NO_MATCHING_LISTENER_HOSTNAME: &str = "NoMatchingListenerHostname";
    pub const UNSUPPORTED_VALUE: &str = "UnsupportedValue";
    pub const RESOLVED_REFS: &str = "ResolvedRefs";
    pub const REF_NOT_PERMITTED: &str = "RefNotPermitted";
    pub const INVALID_KIND: &str = "InvalidKind";
    pub const BACKEND_NOT_FOUND: &str = "BackendNotFound";
    pub const PROGRAMMED: &str = "Programmed";
    pub const PENDING: &str = "Pending";
    pub const INVALID: &str = "Invalid";
    pub const INVALID_PARAMETERS: &str = "InvalidParameters";
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GatewayClassSpec {
    pub controller_name: String,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GatewaySpec {
    pub gateway_class_name: String,
    #[serde(default)]
    pub listeners: Vec<Listener>,
    /// Standard channel since Gateway API v1.2.
    #[serde(default)]
    pub infrastructure: Option<GatewayInfrastructure>,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GatewayInfrastructure {
    #[serde(default)]
    pub parameters_ref: Option<LocalParametersReference>,
}

/// A reference to an object in the Gateway's namespace.
#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
pub struct LocalParametersReference {
    pub group: String,
    pub kind: String,
    pub name: String,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Listener {
    pub name: String,
    #[serde(default)]
    pub hostname: Option<String>,
    pub port: i32,
    pub protocol: String,
    #[serde(default)]
    pub allowed_routes: Option<AllowedRoutes>,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AllowedRoutes {
    #[serde(default)]
    pub namespaces: Option<RouteNamespaces>,
    #[serde(default)]
    pub kinds: Vec<RouteGroupKind>,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RouteNamespaces {
    /// `Same` (default), `All` or `Selector`.
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default)]
    pub selector: Option<LabelSelector>,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LabelSelector {
    #[serde(default)]
    pub match_labels: BTreeMap<String, String>,
    #[serde(default)]
    pub match_expressions: Vec<LabelSelectorRequirement>,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LabelSelectorRequirement {
    pub key: String,
    pub operator: String,
    #[serde(default)]
    pub values: Vec<String>,
}

impl LabelSelector {
    pub fn matches(&self, labels: &BTreeMap<String, String>) -> bool {
        self.match_labels.iter().all(|(k, v)| labels.get(k) == Some(v))
            && self.match_expressions.iter().all(|e| {
                let value = labels.get(&e.key);
                match e.operator.as_str() {
                    "In" => value.is_some_and(|v| e.values.contains(v)),
                    "NotIn" => value.is_none_or(|v| !e.values.contains(v)),
                    "Exists" => value.is_some(),
                    "DoesNotExist" => value.is_none(),
                    _ => false,
                }
            })
    }
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RouteGroupKind {
    #[serde(default)]
    pub group: Option<String>,
    pub kind: String,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HttpRouteSpec {
    #[serde(default)]
    pub parent_refs: Vec<ParentReference>,
    #[serde(default)]
    pub hostnames: Vec<String>,
    #[serde(default)]
    pub rules: Vec<HttpRouteRule>,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct ParentReference {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<i32>,
}

impl ParentReference {
    /// The Gateway this refers to, `(namespace, name)`; `None` for other kinds of parent.
    pub fn gateway(&self, route_ns: &str) -> Option<(String, String)> {
        let group_ok = self.group.as_deref().is_none_or(|g| g == GROUP);
        let kind_ok = self.kind.as_deref().is_none_or(|k| k == "Gateway");
        (group_ok && kind_ok)
            .then(|| (self.namespace.clone().unwrap_or_else(|| route_ns.to_owned()), self.name.clone()))
    }
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HttpRouteRule {
    #[serde(default)]
    pub matches: Vec<HttpRouteMatch>,
    #[serde(default)]
    pub filters: Vec<Value>,
    #[serde(default)]
    pub backend_refs: Vec<HttpBackendRef>,
    /// Fields of newer releases (timeouts, retries, session persistence, …): rejected, not ignored.
    #[serde(flatten)]
    pub other: BTreeMap<String, Value>,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HttpRouteMatch {
    #[serde(default)]
    pub path: Option<HttpPathMatch>,
    #[serde(default)]
    pub headers: Vec<Value>,
    #[serde(default)]
    pub query_params: Vec<Value>,
    #[serde(default)]
    pub method: Option<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HttpPathMatch {
    /// `PathPrefix` (default), `Exact` or `RegularExpression`.
    #[serde(default, rename = "type")]
    pub type_: Option<String>,
    #[serde(default)]
    pub value: Option<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HttpBackendRef {
    #[serde(default)]
    pub group: Option<String>,
    #[serde(default)]
    pub kind: Option<String>,
    pub name: String,
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default)]
    pub port: Option<i32>,
    #[serde(default)]
    pub weight: Option<i32>,
    #[serde(default)]
    pub filters: Vec<Value>,
}

/// The Tunnel a Gateway uses: `spec.infrastructure.parametersRef` (a Tunnel in the Gateway's
/// namespace), or the `tunnelgate.geeko.me/tunnel` annotation, which may name another namespace.
/// When both are set they must name the same Tunnel. Errors are `InvalidParameters` messages.
pub fn gateway_tunnel(
    gateway_ns: &str,
    spec: &GatewaySpec,
    annotations: &BTreeMap<String, String>,
) -> Result<ObjectRef, String> {
    let key = tunnel_annotation();
    let from_params = match spec.infrastructure.as_ref().and_then(|i| i.parameters_ref.as_ref()) {
        None => None,
        Some(p) if p.group == DOMAIN && p.kind == "Tunnel" && !p.name.is_empty() => {
            Some(ObjectRef { name: p.name.clone(), namespace: Some(gateway_ns.to_owned()) })
        }
        Some(p) => {
            return Err(format!(
                "spec.infrastructure.parametersRef must refer to a Tunnel (group {DOMAIN}), not {} {:?} in group {:?}",
                p.kind, p.name, p.group
            ));
        }
    };
    let from_annotation = match annotations.get(&key).map(|v| v.trim()).filter(|v| !v.is_empty()) {
        None => None,
        Some(value) => {
            let (ns, name) = value.split_once('/').unwrap_or((gateway_ns, value));
            if ns.is_empty() || name.is_empty() || name.contains('/') {
                return Err(format!("{key}: expected <namespace>/<name> or <name>, got {value:?}"));
            }
            Some(ObjectRef { name: name.to_owned(), namespace: Some(ns.to_owned()) })
        }
    };
    match (from_params, from_annotation) {
        (Some(p), Some(a)) if p != a => Err(format!(
            "spec.infrastructure.parametersRef names Tunnel {gateway_ns}/{} but the {key} annotation names {}/{}; \
             remove one",
            p.name,
            a.namespace.unwrap_or_default(),
            a.name
        )),
        (Some(r), _) | (None, Some(r)) => Ok(r),
        (None, None) => Err(format!(
            "name the Tunnel in spec.infrastructure.parametersRef (group {DOMAIN}, kind Tunnel) or, for a Tunnel in \
             another namespace, the {key} annotation"
        )),
    }
}

/// Whether a listener accepts HTTPRoutes from `route_ns` (labels `ns_labels`).
pub fn listener_allows(l: &Listener, gateway_ns: &str, route_ns: &str, ns_labels: &BTreeMap<String, String>) -> bool {
    let allowed = l.allowed_routes.clone().unwrap_or_default();
    let kind_ok = allowed.kinds.is_empty()
        || allowed.kinds.iter().any(|k| k.kind == "HTTPRoute" && k.group.as_deref().is_none_or(|g| g == GROUP));
    let ns = allowed.namespaces.unwrap_or_default();
    let ns_ok = match ns.from.as_deref().unwrap_or("Same") {
        "All" => true,
        "Selector" => ns.selector.is_some_and(|s| s.matches(ns_labels)),
        _ => route_ns == gateway_ns,
    };
    kind_ok && ns_ok && matches!(l.protocol.as_str(), "HTTP" | "HTTPS")
}

/// Whether hostname `pattern` (`*.example.com` matches one or more labels) covers `host`.
fn host_matches(pattern: &str, host: &str) -> bool {
    match pattern.strip_prefix("*.") {
        Some(suffix) => host.strip_suffix(suffix).is_some_and(|rest| rest.len() > 1 && rest.ends_with('.')),
        None => pattern == host,
    }
}

/// Hostnames a route gets on a listener (Gateway API intersection rules).
pub fn intersect_hostnames(listener: Option<&str>, route: &[String]) -> Vec<String> {
    match (listener, route.is_empty()) {
        (None, _) => route.to_vec(),
        (Some(l), true) => vec![l.to_owned()],
        (Some(l), false) => route
            .iter()
            .filter_map(|h| {
                if host_matches(l, h) {
                    Some(h.clone())
                } else if host_matches(h, l) {
                    Some(l.to_owned())
                } else {
                    None
                }
            })
            .collect(),
    }
}

/// Why a parentRef doesn't attach: a Gateway API reason and a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotAttached {
    pub reason: &'static str,
    pub message: String,
}

fn not_attached(reason: &'static str, message: impl Into<String>) -> NotAttached {
    NotAttached { reason, message: message.into() }
}

/// Attaches an HTTPRoute to a Gateway through `parent`: the hostnames it gets, or why not.
pub fn attach(
    gateway: &GatewaySpec,
    gateway_ns: &str,
    parent: &ParentReference,
    route_ns: &str,
    ns_labels: &BTreeMap<String, String>,
    route_hostnames: &[String],
) -> Result<Vec<String>, NotAttached> {
    let listeners: Vec<&Listener> = gateway
        .listeners
        .iter()
        .filter(|l| parent.section_name.as_ref().is_none_or(|s| *s == l.name))
        .filter(|l| parent.port.is_none_or(|p| p == l.port))
        .collect();
    if listeners.is_empty() {
        return Err(not_attached(reasons::NO_MATCHING_PARENT, "no listener matches the parentRef's sectionName/port"));
    }
    let admitted: Vec<&&Listener> =
        listeners.iter().filter(|l| listener_allows(l, gateway_ns, route_ns, ns_labels)).collect();
    if admitted.is_empty() {
        return Err(not_attached(
            reasons::NOT_ALLOWED_BY_LISTENERS,
            format!("no HTTP/HTTPS listener allows HTTPRoutes from namespace {route_ns}"),
        ));
    }
    let mut hostnames = BTreeSet::new();
    for l in &admitted {
        if l.hostname.is_none() && route_hostnames.is_empty() {
            return Err(not_attached(
                reasons::UNSUPPORTED_VALUE,
                "a Cloudflare route needs a hostname: set spec.hostnames on the HTTPRoute or hostname on the listener",
            ));
        }
        hostnames.extend(intersect_hostnames(l.hostname.as_deref(), route_hostnames));
    }
    if hostnames.is_empty() {
        return Err(not_attached(
            reasons::NO_MATCHING_LISTENER_HOSTNAME,
            "none of the route's hostnames matches a listener hostname",
        ));
    }
    Ok(hostnames.into_iter().collect())
}

/// Whether `route_ns` may publish `hostname` through the Gateway: some listener admits the
/// namespace and covers the hostname. Used to authorize generated TunnelRoutes.
pub fn gateway_permits(
    gateway: &GatewaySpec,
    gateway_ns: &str,
    route_ns: &str,
    ns_labels: &BTreeMap<String, String>,
    hostname: &str,
) -> bool {
    gateway.listeners.iter().any(|l| {
        listener_allows(l, gateway_ns, route_ns, ns_labels)
            && l.hostname.as_deref().is_none_or(|lh| lh == hostname || host_matches(lh, hostname))
    })
}

/// A TunnelRoute to create for an HTTPRoute.
#[derive(Debug, Clone, PartialEq)]
pub struct Generated {
    pub name: String,
    pub spec: TunnelRouteSpec,
}

/// Translates an HTTPRoute attached through one Gateway into TunnelRoutes: one per hostname ×
/// path match, in the HTTPRoute's namespace. `Err` (an `UnsupportedValue` message) for features
/// tunnelgate can't express, rather than silently dropping them.
pub fn translate(
    route_name: &str,
    route_ns: &str,
    spec: &HttpRouteSpec,
    annotations: &BTreeMap<String, String>,
    hostnames: &[String],
    tunnel: &ObjectRef,
    gateway: (&str, &str),
) -> Result<Vec<Generated>, String> {
    let (origin, access) = annotation_settings(annotations)?;
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for (i, rule) in spec.rules.iter().enumerate() {
        let at = format!("spec.rules[{i}]");
        if let Some(k) = rule.other.keys().find(|k| k.as_str() != "name") {
            return Err(format!("{at}.{k} is not supported"));
        }
        if !rule.filters.is_empty() {
            return Err(format!("{at}.filters are not supported"));
        }
        let [backend] = rule.backend_refs.as_slice() else {
            return Err(format!("{at} needs exactly one backendRef (got {})", rule.backend_refs.len()));
        };
        let service = backend_service(backend, route_ns).map_err(|e| format!("{at}.backendRefs[0]: {e}"))?;
        let default_match = [HttpRouteMatch::default()];
        let matches = if rule.matches.is_empty() { &default_match[..] } else { &rule.matches };
        for (j, m) in matches.iter().enumerate() {
            let path = path_regex(m).map_err(|e| format!("{at}.matches[{j}]: {e}"))?;
            for host in hostnames {
                // The first rule for a hostname and path wins, as in Gateway API.
                if !seen.insert((host.clone(), path.clone())) {
                    continue;
                }
                out.push(Generated {
                    name: generated_name(route_name, gateway, host, path.as_deref()),
                    spec: TunnelRouteSpec {
                        tunnel_ref: tunnel.clone(),
                        hostname: host.clone(),
                        path: path.clone(),
                        service: service.clone(),
                        origin: origin.clone(),
                        dns: RouteDns::default(),
                        access: access.clone(),
                    },
                });
            }
        }
    }
    Ok(out)
}

fn backend_service(b: &HttpBackendRef, route_ns: &str) -> Result<RouteService, String> {
    if b.group.as_deref().is_some_and(|g| !g.is_empty()) || b.kind.as_deref().is_some_and(|k| k != "Service") {
        return Err(format!(
            "only Services are supported (got {}/{})",
            b.group.as_deref().unwrap_or(""),
            b.kind.as_deref().unwrap_or("Service")
        ));
    }
    if !b.filters.is_empty() {
        return Err("filters are not supported".to_owned());
    }
    if b.weight == Some(0) {
        return Err("weight 0 (no traffic) is not supported".to_owned());
    }
    let Some(port) = b.port else { return Err("port is required".to_owned()) };
    Ok(RouteService {
        backend_ref: Some(BackendRef {
            name: b.name.clone(),
            namespace: b.namespace.clone().filter(|ns| ns != route_ns),
            port,
        }),
        ..Default::default()
    })
}

/// Cloudflare path regex for a match: `None` for the whole host.
fn path_regex(m: &HttpRouteMatch) -> Result<Option<String>, String> {
    if !m.headers.is_empty() || !m.query_params.is_empty() || m.method.is_some() {
        return Err("header, query parameter and method matches are not supported".to_owned());
    }
    let path = m.path.clone().unwrap_or_default();
    let value = path.value.as_deref().unwrap_or("/");
    if !value.starts_with('/') {
        return Err(format!("path {value:?} must start with '/'"));
    }
    match path.type_.as_deref().unwrap_or("PathPrefix") {
        "PathPrefix" => {
            // Element-wise prefix: /foo matches /foo and /foo/bar, not /foobar.
            let trimmed = value.trim_end_matches('/');
            Ok((!trimmed.is_empty()).then(|| format!("^{}(/.*)?$", escape(trimmed))))
        }
        "Exact" => Ok(Some(format!("^{}$", escape(value)))),
        other => Err(format!("path type {other} is not supported (use PathPrefix or Exact)")),
    }
}

fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if "\\.+*?()|[]{}^$".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// `<route>-<hash>`: stable for the same Gateway, hostname and path.
fn generated_name(route: &str, gateway: (&str, &str), host: &str, path: Option<&str>) -> String {
    let mut h = Sha256::new();
    for part in [gateway.0, gateway.1, host, path.unwrap_or("")] {
        h.update(part.as_bytes());
        h.update([0]);
    }
    let hash = hex::encode(&h.finalize()[..5]);
    let base: String = route.chars().take(50).collect();
    format!("{}-{hash}", base.trim_end_matches(['-', '.']))
}

fn annotation_settings(
    annotations: &BTreeMap<String, String>,
) -> Result<(Option<RouteOrigin>, Option<RouteAccess>), String> {
    let get = |k: String| annotations.get(&k).map(|v| v.trim().to_owned()).filter(|v| !v.is_empty()).map(|v| (k, v));
    let mut origin = RouteOrigin::default();
    if let Some((k, v)) = get(origin_protocol_annotation()) {
        origin.protocol = Some(match v.as_str() {
            "http" => OriginProtocol::Http,
            "https" => OriginProtocol::Https,
            _ => return Err(format!("annotation {k}: expected http or https, got {v:?}")),
        });
    }
    if let Some((_, v)) = get(origin_server_name_annotation()) {
        origin.server_name = Some(v);
    }
    if let Some((k, v)) = get(origin_no_tls_verify_annotation()) {
        origin.no_tls_verify =
            Some(v.parse().map_err(|_| format!("annotation {k}: expected true or false, got {v:?}"))?);
    }
    let mut access = None;
    if let Some((k, v)) = get(access_applications_annotation()) {
        let refs = v
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| match s.split_once('/') {
                Some((ns, name)) if !ns.is_empty() && !name.is_empty() => {
                    Ok(ObjectRef { name: name.to_owned(), namespace: Some(ns.to_owned()) })
                }
                None => Ok(ObjectRef { name: s.to_owned(), namespace: None }),
                _ => Err(format!("annotation {k}: expected [<namespace>/]<name>, got {s:?}")),
            })
            .collect::<Result<Vec<_>, _>>()?;
        access = Some(RouteAccess { application_refs: refs });
    }
    Ok(((origin != RouteOrigin::default()).then_some(origin), access))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn route(v: Value) -> HttpRouteSpec {
        serde_json::from_value(v).unwrap()
    }

    fn gateway(v: Value) -> GatewaySpec {
        serde_json::from_value(v).unwrap()
    }

    fn tunnel() -> ObjectRef {
        ObjectRef { name: "main".into(), namespace: Some("tunnelgate".into()) }
    }

    fn no_labels() -> BTreeMap<String, String> {
        BTreeMap::new()
    }

    #[test]
    fn tunnel_reference_forms() {
        let ann = |v: &str| BTreeMap::from([(tunnel_annotation(), v.to_owned())]);
        let none = GatewaySpec::default();
        assert_eq!(gateway_tunnel("gw", &none, &ann("tunnelgate/main")).unwrap(), tunnel());
        assert_eq!(gateway_tunnel("gw", &none, &ann("main")).unwrap().namespace.as_deref(), Some("gw"));
        assert!(gateway_tunnel("gw", &none, &ann("a/b/c")).is_err());
        assert!(gateway_tunnel("gw", &none, &ann("/main")).is_err());
        let err = gateway_tunnel("gw", &none, &BTreeMap::new()).unwrap_err();
        assert!(err.contains("parametersRef"), "{err}");

        let params = |group: &str, kind: &str| {
            gateway(json!({ "gatewayClassName": "tunnelgate",
                            "infrastructure": { "parametersRef": { "group": group, "kind": kind, "name": "main" } } }))
        };
        let tg = params(DOMAIN, "Tunnel");
        assert_eq!(gateway_tunnel("tunnelgate", &tg, &BTreeMap::new()).unwrap(), tunnel());
        let err = gateway_tunnel("tunnelgate", &params("", "ConfigMap"), &BTreeMap::new()).unwrap_err();
        assert!(err.contains("must refer to a Tunnel"), "{err}");
        // Both: they must agree.
        assert_eq!(gateway_tunnel("tunnelgate", &tg, &ann("main")).unwrap(), tunnel());
        let err = gateway_tunnel("tunnelgate", &tg, &ann("other/main")).unwrap_err();
        assert!(err.contains("remove one"), "{err}");
    }

    #[test]
    fn hostname_intersection() {
        let r = |hs: &[&str]| hs.iter().map(|h| h.to_string()).collect::<Vec<_>>();
        assert_eq!(intersect_hostnames(None, &r(&["a.example.com"])), r(&["a.example.com"]));
        assert_eq!(intersect_hostnames(Some("*.example.com"), &[]), r(&["*.example.com"]));
        assert_eq!(
            intersect_hostnames(Some("*.example.com"), &r(&["a.example.com", "b.other.com", "x.y.example.com"])),
            r(&["a.example.com", "x.y.example.com"])
        );
        // A wildcard route on a specific listener gets the listener's hostname.
        assert_eq!(intersect_hostnames(Some("a.example.com"), &r(&["*.example.com"])), r(&["a.example.com"]));
        assert!(intersect_hostnames(Some("example.com"), &r(&["*.example.com"])).is_empty());
    }

    #[test]
    fn listener_admission() {
        let gw = gateway(json!({ "gatewayClassName": "tunnelgate", "listeners": [
            { "name": "same", "port": 80, "protocol": "HTTP" },
            { "name": "all", "port": 443, "protocol": "HTTPS", "hostname": "*.example.com",
              "allowedRoutes": { "namespaces": { "from": "All" } } },
            { "name": "team", "port": 8080, "protocol": "HTTP",
              "allowedRoutes": { "namespaces": { "from": "Selector", "selector": {
                  "matchLabels": { "team": "a" },
                  "matchExpressions": [{ "key": "env", "operator": "NotIn", "values": ["prod"] }] } } } },
            { "name": "grpc-only", "port": 9000, "protocol": "HTTP",
              "allowedRoutes": { "kinds": [{ "kind": "GRPCRoute" }], "namespaces": { "from": "All" } } },
            { "name": "tcp", "port": 22, "protocol": "TCP", "allowedRoutes": { "namespaces": { "from": "All" } } },
        ]}));
        let l = |name: &str| gw.listeners.iter().find(|l| l.name == name).unwrap();
        let team_a = BTreeMap::from([("team".to_owned(), "a".to_owned())]);
        let team_a_prod = BTreeMap::from([("team".to_owned(), "a".to_owned()), ("env".to_owned(), "prod".to_owned())]);
        assert!(listener_allows(l("same"), "gw", "gw", &no_labels()));
        assert!(!listener_allows(l("same"), "gw", "apps", &no_labels()));
        assert!(listener_allows(l("all"), "gw", "apps", &no_labels()));
        assert!(listener_allows(l("team"), "gw", "apps", &team_a));
        assert!(!listener_allows(l("team"), "gw", "apps", &team_a_prod));
        assert!(!listener_allows(l("team"), "gw", "apps", &no_labels()));
        assert!(!listener_allows(l("grpc-only"), "gw", "apps", &no_labels()));
        assert!(!listener_allows(l("tcp"), "gw", "apps", &no_labels()));

        let parent = |section: Option<&str>| ParentReference {
            name: "gw".into(),
            section_name: section.map(str::to_owned),
            ..Default::default()
        };
        let hosts = vec!["a.example.com".to_owned()];
        assert_eq!(attach(&gw, "gw", &parent(Some("all")), "apps", &no_labels(), &hosts), Ok(hosts.clone()));
        assert_eq!(
            attach(&gw, "gw", &parent(Some("same")), "apps", &no_labels(), &hosts).unwrap_err().reason,
            reasons::NOT_ALLOWED_BY_LISTENERS
        );
        assert_eq!(
            attach(&gw, "gw", &parent(Some("nope")), "apps", &no_labels(), &hosts).unwrap_err().reason,
            reasons::NO_MATCHING_PARENT
        );
        assert_eq!(
            attach(&gw, "gw", &parent(Some("all")), "apps", &no_labels(), &["a.other.com".to_owned()])
                .unwrap_err()
                .reason,
            reasons::NO_MATCHING_LISTENER_HOSTNAME
        );
        assert_eq!(
            attach(&gw, "gw", &parent(Some("same")), "gw", &no_labels(), &[]).unwrap_err().reason,
            reasons::UNSUPPORTED_VALUE
        );

        assert!(gateway_permits(&gw, "gw", "apps", &no_labels(), "a.example.com"));
        assert!(!gateway_permits(&gw, "gw", "apps", &no_labels(), "a.other.com"));
        assert!(gateway_permits(&gw, "gw", "gw", &no_labels(), "a.other.com"));
    }

    #[test]
    fn parent_refs_to_other_kinds_are_not_gateways() {
        let p = |group: Option<&str>, kind: Option<&str>| ParentReference {
            group: group.map(str::to_owned),
            kind: kind.map(str::to_owned),
            name: "x".into(),
            ..Default::default()
        };
        assert_eq!(p(None, None).gateway("apps"), Some(("apps".into(), "x".into())));
        assert_eq!(p(Some(GROUP), Some("Gateway")).gateway("apps"), Some(("apps".into(), "x".into())));
        assert_eq!(p(Some(""), Some("Service")).gateway("apps"), None);
    }

    #[test]
    fn translates_rules_paths_and_annotations() {
        let spec = route(json!({
            "parentRefs": [{ "name": "gw" }],
            "hostnames": ["rancher.example.com"],
            "rules": [
                { "matches": [{ "path": { "type": "PathPrefix", "value": "/v3/connect/" } },
                              { "path": { "type": "Exact", "value": "/ping" } }],
                  "backendRefs": [{ "name": "rancher", "port": 443 }] },
                { "backendRefs": [{ "name": "rancher", "namespace": "cattle-system", "port": 443, "weight": 1 }] },
                // Same hostname and path as the rule above: the first wins.
                { "matches": [{ "path": { "value": "/" } }], "backendRefs": [{ "name": "other", "port": 80 }] },
            ],
        }));
        let annotations = BTreeMap::from([
            (origin_protocol_annotation(), "https".to_owned()),
            (origin_server_name_annotation(), "rancher.example.com".to_owned()),
            (access_applications_annotation(), "rancher-ui, cattle-system/agents".to_owned()),
        ]);
        let out = translate(
            "rancher",
            "apps",
            &spec,
            &annotations,
            &["rancher.example.com".to_owned()],
            &tunnel(),
            ("gw", "gw"),
        )
        .unwrap();
        let paths: Vec<_> = out.iter().map(|g| g.spec.path.clone()).collect();
        assert_eq!(paths, vec![Some("^/v3/connect(/.*)?$".to_owned()), Some("^/ping$".to_owned()), None]);
        let backend = out[2].spec.service.backend_ref.clone().unwrap();
        assert_eq!(backend.namespace.as_deref(), Some("cattle-system"));
        assert_eq!(out[0].spec.service.backend_ref.as_ref().unwrap().namespace, None);
        let origin = out[0].spec.origin.clone().unwrap();
        assert_eq!(origin.protocol, Some(OriginProtocol::Https));
        assert_eq!(origin.server_name.as_deref(), Some("rancher.example.com"));
        let apps = &out[0].spec.access.as_ref().unwrap().application_refs;
        assert_eq!(apps[0], ObjectRef { name: "rancher-ui".into(), namespace: None });
        assert_eq!(apps[1].namespace.as_deref(), Some("cattle-system"));
        assert_eq!(out[0].spec.tunnel_ref, tunnel());
        // Names are stable and distinct.
        let names: BTreeSet<_> = out.iter().map(|g| g.name.clone()).collect();
        assert_eq!(names.len(), 3);
        assert!(out.iter().all(|g| g.name.starts_with("rancher-")));
        let again = translate(
            "rancher",
            "apps",
            &spec,
            &annotations,
            &["rancher.example.com".to_owned()],
            &tunnel(),
            ("gw", "gw"),
        )
        .unwrap();
        assert_eq!(out, again);
    }

    #[test]
    fn path_regexes_escape_and_respect_segments() {
        let m = |t: &str, v: &str| HttpRouteMatch {
            path: Some(HttpPathMatch { type_: Some(t.into()), value: Some(v.into()) }),
            ..Default::default()
        };
        assert_eq!(path_regex(&m("PathPrefix", "/")), Ok(None));
        assert_eq!(path_regex(&m("PathPrefix", "/a.b")), Ok(Some("^/a\\.b(/.*)?$".into())));
        assert_eq!(path_regex(&m("Exact", "/")), Ok(Some("^/$".into())));
        assert!(path_regex(&m("RegularExpression", "/.*")).is_err());
        assert!(path_regex(&m("PathPrefix", "nope")).is_err());
        assert_eq!(path_regex(&HttpRouteMatch::default()), Ok(None));
    }

    #[test]
    fn unsupported_features_are_rejected() {
        let t = |rule: Value| {
            let spec = route(json!({ "rules": [rule] }));
            translate("r", "apps", &spec, &BTreeMap::new(), &["a.example.com".to_owned()], &tunnel(), ("gw", "gw"))
        };
        let backend = json!([{ "name": "svc", "port": 80 }]);
        assert!(t(json!({ "backendRefs": backend })).is_ok());
        assert!(t(json!({ "backendRefs": backend, "name": "named-rule" })).is_ok());
        for (rule, expect) in [
            (json!({ "backendRefs": backend, "filters": [{ "type": "RequestHeaderModifier" }] }), "filters"),
            (json!({ "backendRefs": backend, "timeouts": { "request": "10s" } }), "timeouts"),
            (json!({ "backendRefs": [] }), "exactly one backendRef"),
            (json!({ "backendRefs": [{ "name": "a", "port": 80 }, { "name": "b", "port": 80 }] }), "exactly one"),
            (json!({ "backendRefs": [{ "name": "svc" }] }), "port is required"),
            (json!({ "backendRefs": [{ "name": "svc", "port": 80, "weight": 0 }] }), "weight 0"),
            (json!({ "backendRefs": [{ "group": "example.com", "kind": "Bucket", "name": "b" }] }), "only Services"),
            (json!({ "backendRefs": backend, "matches": [{ "headers": [{ "name": "x", "value": "y" }] }] }), "header"),
            (json!({ "backendRefs": backend, "matches": [{ "method": "GET" }] }), "method"),
        ] {
            let err = t(rule.clone()).unwrap_err();
            assert!(err.contains(expect), "{rule}: {err}");
        }
        let bad = BTreeMap::from([(origin_protocol_annotation(), "h2c".to_owned())]);
        assert!(
            translate("r", "apps", &route(json!({})), &bad, &[], &tunnel(), ("gw", "gw"))
                .unwrap_err()
                .contains("expected http or https")
        );
    }
}
