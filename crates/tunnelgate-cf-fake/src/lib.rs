//! An in-process fake of the Cloudflare API endpoints tunnelgate uses.
//!
//! It speaks the same envelope, pagination and error shapes as Cloudflare, keeps a request log so
//! tests can assert "no extra writes", and can inject faults (409/429/5xx). Start one with
//! [`FakeCloudflare::start`] and point the client's `base_url` at [`FakeCloudflare::base_url`].

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

pub const ACCOUNT_ID: &str = "bc58f3a1e2d94c7b8a6f5e4d3c2b1a09";
pub const ACCOUNT_NAME: &str = "Lab Account";
pub const TOKEN: &str = "fake-cloudflare-token";

/// One request the fake received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoggedRequest {
    pub method: String,
    pub path: String,
    pub query: String,
}

impl LoggedRequest {
    pub fn is_write(&self) -> bool {
        self.method != "GET"
    }
}

/// A fault to return instead of handling matching requests.
#[derive(Debug, Clone)]
pub struct Fault {
    pub method: Option<String>,
    pub path_contains: String,
    pub status: u16,
    pub code: i64,
    pub message: String,
    pub retry_after: Option<u64>,
    /// How many matching requests fail before the fault is used up.
    pub times: u32,
}

impl Fault {
    pub fn new(method: Option<&str>, path_contains: &str, status: u16) -> Self {
        Self {
            method: method.map(Into::into),
            path_contains: path_contains.to_owned(),
            status,
            code: if status == 429 { 10429 } else { 10000 + i64::from(status) },
            message: format!("injected fault ({status})"),
            retry_after: (status == 429).then_some(0),
            times: 1,
        }
    }

    pub fn times(mut self, n: u32) -> Self {
        self.times = n;
        self
    }
}

#[derive(Debug, Clone)]
pub struct FakeTunnel {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub deleted: bool,
    pub token: String,
    pub connections: u32,
    pub config: Option<Value>,
    pub config_version: i64,
    /// PUTs whose configuration equals the one already stored: a client re-applying unchanged
    /// configuration (Cloudflare bumps the version anyway).
    pub redundant_config_puts: u32,
}

#[derive(Debug, Default)]
pub struct FakeState {
    pub token: String,
    pub accounts: Vec<(String, String)>,
    pub zones: Vec<(String, String)>,
    pub tunnels: BTreeMap<String, FakeTunnel>,
    /// zone id → record id → record JSON
    pub dns: BTreeMap<String, BTreeMap<String, Value>>,
    pub policies: BTreeMap<String, Value>,
    pub apps: BTreeMap<String, Value>,
    pub service_tokens: BTreeMap<String, Value>,
    pub log: Vec<LoggedRequest>,
    pub faults: VecDeque<Fault>,
    counter: u64,
}

impl FakeState {
    fn next_id(&mut self) -> String {
        self.counter += 1;
        format!("{:032x}", 0x7f00_0000_0000_0000_u128 + u128::from(self.counter))
    }

    fn next_uuid(&mut self) -> String {
        self.counter += 1;
        uuid::Uuid::from_u128(0x6f00_0000_0000_4000_8000_0000_0000_0000 + u128::from(self.counter)).to_string()
    }

    fn now(&self) -> String {
        format!("2026-01-01T00:00:{:02}Z", self.counter % 60)
    }
}

/// A running fake. Dropping it stops the server.
pub struct FakeCloudflare {
    addr: SocketAddr,
    state: Arc<Mutex<FakeState>>,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

impl FakeCloudflare {
    /// Starts a fake with one account and the zones `example.org` and `example.com`.
    pub async fn start() -> Self {
        let mut state = FakeState { token: TOKEN.to_owned(), ..Default::default() };
        state.accounts.push((ACCOUNT_ID.to_owned(), ACCOUNT_NAME.to_owned()));
        for zone in ["example.org", "example.com"] {
            let id = state.next_id();
            state.zones.push((id.clone(), zone.to_owned()));
            state.dns.insert(id, BTreeMap::new());
        }
        let state = Arc::new(Mutex::new(state));
        let app = Router::new().fallback(handle).with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind fake cloudflare");
        let addr = listener.local_addr().expect("local addr");
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = rx.await;
                })
                .await;
        });
        Self { addr, state, _shutdown: tx }
    }

    pub fn base_url(&self) -> String {
        format!("http://{}/client/v4", self.addr)
    }

    pub fn state(&self) -> MutexGuard<'_, FakeState> {
        self.state.lock().expect("fake state poisoned")
    }

    pub fn zone_id(&self, name: &str) -> String {
        self.state().zones.iter().find(|(_, n)| n == name).map(|(id, _)| id.clone()).expect("zone exists")
    }

    pub fn inject(&self, fault: Fault) {
        self.state().faults.push_back(fault);
    }

    pub fn requests(&self) -> Vec<LoggedRequest> {
        self.state().log.clone()
    }

    pub fn writes(&self) -> Vec<LoggedRequest> {
        self.state().log.iter().filter(|r| r.is_write()).cloned().collect()
    }

    pub fn clear_log(&self) {
        self.state().log.clear();
    }

    /// Simulates `n` active connector connections on a tunnel.
    pub fn set_connections(&self, tunnel_id: &str, n: u32) {
        if let Some(t) = self.state().tunnels.get_mut(tunnel_id) {
            t.connections = n;
        }
    }

    /// Adds a DNS record directly (e.g. one not owned by the operator).
    pub fn add_dns_record(&self, zone: &str, record: Value) -> String {
        let zone_id = self.zone_id(zone);
        let mut s = self.state();
        let id = s.next_id();
        let mut record = record;
        record["id"] = json!(id);
        record["zone_id"] = json!(zone_id);
        record.as_object_mut().unwrap().entry("ttl").or_insert(json!(1));
        record.as_object_mut().unwrap().entry("proxied").or_insert(json!(false));
        s.dns.get_mut(&zone_id).unwrap().insert(id.clone(), record);
        id
    }

    pub fn dns_records(&self, zone: &str) -> Vec<Value> {
        let zone_id = self.zone_id(zone);
        self.state().dns[&zone_id].values().cloned().collect()
    }

    /// Service tokens (without secrets).
    pub fn service_tokens(&self) -> Vec<Value> {
        self.state().service_tokens.values().cloned().collect()
    }

    /// Moves a service token's expiry, e.g. to make it expire soon.
    pub fn set_service_token_expiry(&self, token_id: &str, expires_at: &str) {
        if let Some(t) = self.state().service_tokens.get_mut(token_id) {
            t["expires_at"] = json!(expires_at);
        }
    }

    pub fn access_policies(&self) -> Vec<Value> {
        self.state().policies.values().cloned().collect()
    }

    pub fn access_apps(&self) -> Vec<Value> {
        self.state().apps.values().cloned().collect()
    }

    pub fn live_tunnels(&self) -> Vec<FakeTunnel> {
        self.state().tunnels.values().filter(|t| !t.deleted).cloned().collect()
    }
}

type Shared = Arc<Mutex<FakeState>>;

fn ok(result: Value) -> Response {
    (StatusCode::OK, axum::Json(json!({ "success": true, "errors": [], "messages": [], "result": result })))
        .into_response()
}

fn err(status: u16, code: i64, message: &str) -> Response {
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (
        status,
        axum::Json(json!({ "success": false, "errors": [{ "code": code, "message": message }], "messages": [], "result": null })),
    )
        .into_response()
}

fn not_found() -> Response {
    err(404, 7003, "Could not route to the requested resource: object not found")
}

fn paged(items: Vec<Value>, query: &HashMap<String, String>) -> Response {
    let per_page: usize = query.get("per_page").and_then(|v| v.parse().ok()).unwrap_or(20).max(1);
    let page: usize = query.get("page").and_then(|v| v.parse().ok()).unwrap_or(1).max(1);
    let total = items.len();
    let total_pages = total.div_ceil(per_page).max(1);
    let slice: Vec<Value> = items.into_iter().skip((page - 1) * per_page).take(per_page).collect();
    let body = json!({
        "success": true, "errors": [], "messages": [], "result": slice,
        "result_info": { "page": page, "per_page": per_page, "count": slice.len(), "total_count": total, "total_pages": total_pages },
    });
    (StatusCode::OK, axum::Json(body)).into_response()
}

fn parse_query(q: &str) -> HashMap<String, String> {
    url_decode_pairs(q).into_iter().collect()
}

fn url_decode_pairs(q: &str) -> Vec<(String, String)> {
    q.split('&')
        .filter(|s| !s.is_empty())
        .map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            (pct_decode(k), pct_decode(v))
        })
        .collect()
}

fn pct_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(b) => {
                        out.push(b);
                        i += 2;
                    }
                    Err(_) => out.push(b'%'),
                }
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

async fn handle(State(state): State<Shared>, req: Request) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let query_str = req.uri().query().unwrap_or("").to_owned();
    let headers: HeaderMap = req.headers().clone();
    let body = axum::body::to_bytes(req.into_body(), 10 * 1024 * 1024).await.unwrap_or_else(|_| Bytes::new());
    let body: Value = if body.is_empty() { Value::Null } else { serde_json::from_slice(&body).unwrap_or(Value::Null) };

    let mut s = state.lock().expect("fake state poisoned");
    s.log.push(LoggedRequest { method: method.to_string(), path: path.clone(), query: query_str.clone() });

    let expected = format!("Bearer {}", s.token);
    if headers.get("authorization").and_then(|v| v.to_str().ok()) != Some(expected.as_str()) {
        return err(401, 10000, "Authentication error");
    }

    if let Some(pos) = s
        .faults
        .iter()
        .position(|f| f.method.as_deref().is_none_or(|m| m == method.as_str()) && path.contains(&f.path_contains))
    {
        let fault = s.faults[pos].clone();
        if fault.times <= 1 {
            s.faults.remove(pos);
        } else {
            s.faults[pos].times -= 1;
        }
        let mut resp = err(fault.status, fault.code, &fault.message);
        if let Some(secs) = fault.retry_after {
            resp.headers_mut().insert("retry-after", secs.into());
        }
        return resp;
    }

    let query = parse_query(&query_str);
    let Some(rest) = path.strip_prefix("/client/v4/") else {
        return not_found();
    };
    let seg: Vec<&str> = rest.split('/').collect();
    route(&mut s, &method, &seg, &query, body)
}

fn route(s: &mut FakeState, method: &Method, seg: &[&str], q: &HashMap<String, String>, body: Value) -> Response {
    match (method.as_str(), seg) {
        ("GET", ["accounts"]) => {
            let items = s
                .accounts
                .iter()
                .filter(|(_, n)| q.get("name").is_none_or(|w| w == n))
                .map(|(id, n)| json!({ "id": id, "name": n }))
                .collect();
            paged(items, q)
        }
        ("GET", ["zones"]) => {
            let account = q.get("account.id");
            if account.is_some_and(|a| s.accounts.iter().all(|(id, _)| id != a)) {
                return paged(vec![], q);
            }
            let (acc_id, acc_name) = s.accounts[0].clone();
            let items = s
                .zones
                .iter()
                .filter(|(_, n)| q.get("name").is_none_or(|w| w == n))
                .map(|(id, n)| json!({ "id": id, "name": n, "account": { "id": acc_id, "name": acc_name } }))
                .collect();
            paged(items, q)
        }
        (_, ["accounts", acc, rest @ ..]) => {
            if s.accounts.iter().all(|(id, _)| id != acc) {
                return err(403, 9109, "Unauthorized to access requested resource");
            }
            match rest {
                ["cfd_tunnel", ..] => tunnels(s, method, &rest[1..], q, body),
                ["access", "policies", ..] => access_collection(s, method, &rest[2..], q, body, Coll::Policies),
                ["access", "apps", ..] => access_collection(s, method, &rest[2..], q, body, Coll::Apps),
                ["access", "service_tokens", ..] => service_tokens(s, method, &rest[2..], q, body),
                _ => not_found(),
            }
        }
        (_, ["zones", zone, "dns_records", rest @ ..]) => dns(s, method, zone, rest, q, body),
        _ => not_found(),
    }
}

fn tunnel_json(t: &FakeTunnel) -> Value {
    let connections: Vec<Value> = (0..t.connections)
        .map(|i| json!({ "id": format!("{}-conn-{i}", t.id), "client_id": format!("client-{i}"), "colo_name": "ams01", "is_pending_reconnect": false }))
        .collect();
    json!({
        "id": t.id, "name": t.name, "created_at": t.created_at,
        "deleted_at": if t.deleted { json!(t.created_at) } else { Value::Null },
        "status": if t.connections > 0 { "healthy" } else { "inactive" },
        "config_src": "cloudflare", "connections": connections,
    })
}

fn tunnels(s: &mut FakeState, method: &Method, seg: &[&str], q: &HashMap<String, String>, body: Value) -> Response {
    match (method.as_str(), seg) {
        ("GET", []) => {
            let include_deleted = q.get("is_deleted").is_some_and(|v| v == "true");
            let items = s
                .tunnels
                .values()
                .filter(|t| include_deleted || !t.deleted)
                .filter(|t| q.get("name").is_none_or(|n| n == &t.name))
                .map(tunnel_json)
                .collect();
            paged(items, q)
        }
        ("POST", []) => {
            let Some(name) = body.get("name").and_then(Value::as_str).map(str::to_owned) else {
                return err(400, 1001, "name is required");
            };
            if body.get("config_src").and_then(Value::as_str) != Some("cloudflare") {
                return err(400, 1001, "fake only supports config_src=cloudflare");
            }
            if s.tunnels.values().any(|t| !t.deleted && t.name == name) {
                return err(409, 1013, "You already have a tunnel with this name");
            }
            let id = s.next_uuid();
            let tunnel = FakeTunnel {
                id: id.clone(),
                name,
                created_at: s.now(),
                deleted: false,
                token: format!("eyJ-fake-connector-token-{id}"),
                connections: 0,
                config: None,
                config_version: 0,
                redundant_config_puts: 0,
            };
            let out = tunnel_json(&tunnel);
            s.tunnels.insert(id, tunnel);
            ok(out)
        }
        (m, [id, rest @ ..]) => {
            let Some(t) = s.tunnels.get_mut(*id) else {
                return not_found();
            };
            match (m, rest) {
                ("GET", []) => ok(tunnel_json(t)),
                ("DELETE", []) => {
                    if t.connections > 0 {
                        return err(400, 1022, "Cannot delete tunnel because it has active connections");
                    }
                    t.deleted = true;
                    ok(tunnel_json(t))
                }
                _ if t.deleted => not_found(),
                ("GET", ["token"]) => ok(json!(t.token)),
                ("DELETE", ["connections"]) => {
                    t.connections = 0;
                    ok(json!({}))
                }
                ("GET", ["configurations"]) => ok(json!({
                    "tunnel_id": t.id, "version": t.config_version, "config": t.config, "source": "cloudflare",
                })),
                ("PUT", ["configurations"]) => {
                    let Some(config) = body.get("config").cloned() else {
                        return err(400, 1001, "config is required");
                    };
                    let rules = config.get("ingress").and_then(Value::as_array).cloned().unwrap_or_default();
                    match rules.last() {
                        Some(last) if last.get("hostname").is_none() && last.get("path").is_none() => {}
                        _ => return err(400, 1056, "The last ingress rule must match all URLs"),
                    }
                    if t.config.as_ref() == Some(&config) {
                        t.redundant_config_puts += 1;
                    }
                    t.config = Some(config.clone());
                    t.config_version += 1;
                    ok(
                        json!({ "tunnel_id": t.id, "version": t.config_version, "config": config, "source": "cloudflare" }),
                    )
                }
                _ => not_found(),
            }
        }
        _ => not_found(),
    }
}

fn dns(
    s: &mut FakeState,
    method: &Method,
    zone: &str,
    seg: &[&str],
    q: &HashMap<String, String>,
    body: Value,
) -> Response {
    if !s.dns.contains_key(zone) {
        return err(404, 7003, "zone not found");
    }
    let zone_name = s.zones.iter().find(|(id, _)| id == zone).map(|(_, n)| n.clone()).unwrap_or_default();
    match (method.as_str(), seg) {
        ("GET", []) => {
            let items = s.dns[zone]
                .values()
                .filter(|r| q.get("name.exact").or(q.get("name")).is_none_or(|n| r["name"] == json!(n)))
                .filter(|r| q.get("type").is_none_or(|t| r["type"] == json!(t)))
                .filter(|r| {
                    q.get("comment.startswith")
                        .is_none_or(|p| r["comment"].as_str().is_some_and(|c| c.starts_with(p.as_str())))
                })
                .cloned()
                .collect();
            paged(items, q)
        }
        ("POST", []) => {
            let name = body["name"].as_str().unwrap_or_default().to_owned();
            if !(name == zone_name || name.ends_with(&format!(".{zone_name}"))) {
                return err(400, 9005, "Content for name is not in the zone");
            }
            if let Some(resp) = check_dns_conflict(s, zone, &name, &body, None) {
                return resp;
            }
            let id = s.next_id();
            let record = dns_record(&id, zone, body);
            s.dns.get_mut(zone).unwrap().insert(id, record.clone());
            ok(record)
        }
        ("PUT", [id]) => {
            if !s.dns[zone].contains_key(*id) {
                return not_found();
            }
            let name = body["name"].as_str().unwrap_or_default().to_owned();
            if let Some(resp) = check_dns_conflict(s, zone, &name, &body, Some(id)) {
                return resp;
            }
            let record = dns_record(id, zone, body);
            s.dns.get_mut(zone).unwrap().insert((*id).to_owned(), record.clone());
            ok(record)
        }
        ("DELETE", [id]) => match s.dns.get_mut(zone).unwrap().remove(*id) {
            Some(_) => ok(json!({ "id": id })),
            None => not_found(),
        },
        _ => not_found(),
    }
}

fn check_dns_conflict(s: &FakeState, zone: &str, name: &str, body: &Value, except: Option<&str>) -> Option<Response> {
    let new_type = body["type"].as_str().unwrap_or_default();
    let exclusive = ["A", "AAAA", "CNAME"];
    let clash = s.dns[zone].values().any(|r| {
        r["name"] == json!(name)
            && except.is_none_or(|e| r["id"] != json!(e))
            && (r["type"] == json!("CNAME") || new_type == "CNAME")
            && exclusive.contains(&r["type"].as_str().unwrap_or_default())
    });
    clash.then(|| err(400, 81053, "An A, AAAA, or CNAME record with that host already exists."))
}

fn dns_record(id: &str, zone: &str, body: Value) -> Value {
    json!({
        "id": id, "zone_id": zone,
        "name": body["name"], "type": body["type"], "content": body["content"],
        "proxied": body["proxied"].as_bool().unwrap_or(false),
        "ttl": body["ttl"].as_u64().unwrap_or(1),
        "comment": body.get("comment").cloned().unwrap_or(Value::Null),
    })
}

#[derive(Clone, Copy)]
enum Coll {
    Policies,
    Apps,
}

fn map(s: &mut FakeState, coll: Coll) -> &mut BTreeMap<String, Value> {
    match coll {
        Coll::Policies => &mut s.policies,
        Coll::Apps => &mut s.apps,
    }
}

fn access_collection(
    s: &mut FakeState,
    method: &Method,
    seg: &[&str],
    q: &HashMap<String, String>,
    body: Value,
    coll: Coll,
) -> Response {
    let validate = |body: &Value| -> Option<Response> {
        match coll {
            Coll::Policies => {
                let decision = body["decision"].as_str().unwrap_or_default();
                if !["allow", "deny", "bypass", "non_identity"].contains(&decision) {
                    return Some(err(400, 12130, "invalid decision"));
                }
                if body["include"].as_array().is_none_or(Vec::is_empty) {
                    return Some(err(400, 12130, "include must contain at least one rule"));
                }
                None
            }
            Coll::Apps => {
                if body["type"] != json!("self_hosted") {
                    return Some(err(400, 12130, "fake only supports self_hosted apps"));
                }
                if body["domain"].as_str().is_none_or(str::is_empty) {
                    return Some(err(400, 12130, "domain is required"));
                }
                None
            }
        }
    };
    let expand = |s: &FakeState, mut v: Value| -> Value {
        // Like Cloudflare, app responses carry the attached policies expanded.
        if let Coll::Apps = coll
            && let Some(policies) = v.get("policies").and_then(Value::as_array).cloned()
        {
            let expanded: Vec<Value> = policies
                .iter()
                .map(|p| {
                    let mut full = s.policies.get(p["id"].as_str().unwrap_or_default()).cloned().unwrap_or(json!({}));
                    full["id"] = p["id"].clone();
                    full["precedence"] = p["precedence"].clone();
                    full
                })
                .collect();
            v["policies"] = json!(expanded);
        }
        v
    };
    match (method.as_str(), seg) {
        ("GET", []) => {
            let items: Vec<Value> = map(s, coll).values().cloned().collect();
            let items = items.into_iter().map(|v| expand(s, v)).collect();
            paged(items, q)
        }
        ("POST", []) => {
            if let Some(resp) = validate(&body) {
                return resp;
            }
            if let Coll::Apps = coll
                && let Some(resp) = check_policies_exist(s, &body)
            {
                return resp;
            }
            let id = s.next_uuid();
            let mut v = body;
            v["id"] = json!(id);
            if let Coll::Apps = coll {
                v["aud"] = json!(format!("{:064x}", s.counter));
            } else {
                v["reusable"] = json!(true);
            }
            map(s, coll).insert(id, v.clone());
            ok(expand(s, v))
        }
        ("GET", [id]) => match map(s, coll).get(*id).cloned() {
            Some(v) => ok(expand(s, v)),
            None => not_found(),
        },
        ("PUT", [id]) => {
            if !map(s, coll).contains_key(*id) {
                return not_found();
            }
            if let Some(resp) = validate(&body) {
                return resp;
            }
            if let Coll::Apps = coll
                && let Some(resp) = check_policies_exist(s, &body)
            {
                return resp;
            }
            let mut v = body;
            v["id"] = json!(id);
            let old = map(s, coll).get(*id).cloned().unwrap_or_default();
            if let Some(aud) = old.get("aud") {
                v["aud"] = aud.clone();
            }
            map(s, coll).insert((*id).to_owned(), v.clone());
            ok(expand(s, v))
        }
        ("DELETE", [id]) => {
            if let Coll::Policies = coll {
                let in_use = s
                    .apps
                    .values()
                    .any(|a| a["policies"].as_array().is_some_and(|ps| ps.iter().any(|p| p["id"] == json!(id))));
                // Cloudflare answers 409 without error details.
                if in_use {
                    return err(409, 12130, "policy is used by one or more applications");
                }
            }
            match map(s, coll).remove(*id) {
                Some(_) => ok(json!({ "id": id })),
                None => not_found(),
            }
        }
        _ => not_found(),
    }
}

fn check_policies_exist(s: &FakeState, body: &Value) -> Option<Response> {
    let missing = body["policies"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|p| !s.policies.contains_key(p["id"].as_str().unwrap_or_default()));
    missing.then(|| err(400, 12130, "policy not found"))
}

fn service_tokens(
    s: &mut FakeState,
    method: &Method,
    seg: &[&str],
    q: &HashMap<String, String>,
    body: Value,
) -> Response {
    match (method.as_str(), seg) {
        ("GET", []) => paged(s.service_tokens.values().cloned().collect(), q),
        ("POST", []) => {
            let id = s.next_uuid();
            let client_id = format!("{}.access", s.next_id());
            let secret = format!("{:064x}", u128::from(s.counter) * 7919);
            let duration = body["duration"].as_str().unwrap_or("8760h").to_owned();
            let Ok(d) = duration.parse::<jiff::SignedDuration>() else {
                return err(400, 12130, "invalid duration");
            };
            let expires_at = jiff::Timestamp::now().checked_add(d).unwrap_or(jiff::Timestamp::MAX);
            let token = json!({
                "id": id, "name": body["name"], "client_id": client_id,
                "duration": duration, "expires_at": expires_at.strftime("%Y-%m-%dT%H:%M:%SZ").to_string(),
            });
            s.service_tokens.insert(id, token.clone());
            let mut created = token;
            created["client_secret"] = json!(secret);
            ok(created)
        }
        ("DELETE", [id]) if token_in_use(s, id) => err(
            400,
            12139,
            "access.api.error.service_token_in_use: cannot delete service token because it is used by a policy",
        ),
        ("DELETE", [id]) => match s.service_tokens.remove(*id) {
            Some(v) => ok(v),
            None => not_found(),
        },
        _ => not_found(),
    }
}

/// Whether a policy includes, requires or excludes the service token.
fn token_in_use(s: &FakeState, id: &str) -> bool {
    s.policies.values().any(|p| {
        ["include", "require", "exclude"].iter().any(|k| {
            p[*k].as_array().is_some_and(|rules| rules.iter().any(|r| r["service_token"]["token_id"] == json!(id)))
        })
    })
}
