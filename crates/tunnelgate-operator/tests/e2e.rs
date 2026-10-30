//! End-to-end test: the controllers run in this process against the k3d test cluster
//! and the real Cloudflare API; a real cloudflared connects from the cluster, and requests go
//! through Cloudflare's edge to in-cluster origins, with and without Access in front.
//!
//! Runs only with TUNNELGATE_E2E_TESTS=1, a KUBECONFIG for the test cluster, and
//! CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID and CLOUDFLARE_TEST_ZONE (see `mise run test-e2e`).
//! Everything it creates is named `tg-spike-e2e-…` (namespace, tunnel, hostnames, Access objects).
//! It checks that the operator itself removes all of it; a final sweep removes leftovers of failed
//! runs. Secrets (API token, tunnel token, service-token client secret) are never printed.

mod common;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use common::*;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{Namespace, Secret, Service};
use kube::api::{Api, DeleteParams, DynamicObject, PostParams};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};
use tunnelgate_api::v1alpha1::{AccessApplication, AccessPolicy, AccessServiceToken, Tunnel, TunnelRoute};
use tunnelgate_cf::types::DnsRecordFilter;
use tunnelgate_cf::{Client, ClientConfig, CloudflareApi};
use tunnelgate_operator::context::{HttpFactory, Settings};

const PREFIX: &str = "tg-spike-";
const WHOAMI_IMAGE: &str = "traefik/whoami:v1.11.0";
/// Image pulls, cloudflared connecting, edge propagation.
const SLOW: Duration = Duration::from_secs(240);

struct Env {
    token: SecretString,
    account: String,
    zone_name: String,
}

fn env() -> Option<Env> {
    if std::env::var("TUNNELGATE_E2E_TESTS").ok().as_deref() != Some("1") {
        eprintln!("skipped: set TUNNELGATE_E2E_TESTS=1 (mise run test-e2e)");
        return None;
    }
    let var = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("{k} must be set for e2e tests"));
    Some(Env {
        token: SecretString::from(var("CLOUDFLARE_API_TOKEN")),
        account: var("CLOUDFLARE_ACCOUNT_ID"),
        zone_name: var("CLOUDFLARE_TEST_ZONE"),
    })
}

fn cf_client(e: &Env) -> Client {
    Client::with_config(e.token.clone(), ClientConfig::default()).unwrap()
}

#[tokio::test]
async fn end_to_end() {
    let Some(e) = env() else { return };
    let _ = tracing_subscriber::fmt().with_env_filter("info,kube=warn").with_test_writer().try_init();
    let client = kube::Client::try_default().await.expect("KUBECONFIG for the k3d test cluster");
    install_crds(&client).await;
    purge_leftovers(&client, PREFIX).await;

    let cf = cf_client(&e);
    let zones = cf.list_zones(&e.account).await.expect("listing zones");
    let zone_id = zones.iter().find(|z| z.name == e.zone_name).expect("CLOUDFLARE_TEST_ZONE not visible").id.clone();
    cloudflare_cleanup(&cf, &e.account, &zone_id, PREFIX).await;

    let cluster_id = tunnelgate_operator::cluster_id(&client).await.unwrap();
    let settings =
        Settings { default_connector_replicas: 1, not_ready_requeue: Duration::from_secs(3), ..Default::default() };
    let operator = tokio::spawn(tunnelgate_operator::run(
        client.clone(),
        settings,
        cluster_id,
        Arc::new(HttpFactory { config: ClientConfig::default() }),
    ));

    let ns = format!("{PREFIX}e2e-{}", uuid_suffix());
    println!("run {ns}");
    // Run the scenario in a task so a panic still reaches the cleanup below.
    let scenario = {
        let (client, ns) = (client.clone(), ns.clone());
        let e = Env { token: e.token.clone(), account: e.account.clone(), zone_name: e.zone_name.clone() };
        let zone_id = zone_id.clone();
        tokio::spawn(async move { scenario(&client, &e, &zone_id, &ns).await })
    };
    let result = scenario.await;
    operator.abort();
    if result.is_err() {
        // The operator is gone: drop our finalizers so the namespace can go, then sweep Cloudflare.
        let namespaces: Api<Namespace> = Api::all(client.clone());
        unfinalize_all(&client, &ns).await;
        let _ = namespaces.delete(&ns, &DeleteParams::default()).await;
        let classes =
            Api::<DynamicObject>::all_with(client.clone(), &tunnelgate_operator::gateway::gateway_class_resource());
        let _ = classes.delete(&ns, &DeleteParams::default()).await;
    }
    cloudflare_cleanup(&cf, &e.account, &zone_id, PREFIX).await;
    let left = cloudflare_leftovers(&cf, &e.account, &zone_id, PREFIX).await;
    result.expect("scenario panicked (see above)");
    assert!(left.is_empty(), "objects left behind after the sweep: {left:?}");
}

async fn scenario(client: &kube::Client, e: &Env, zone_id: &str, ns: &str) {
    let cf = cf_client(e);
    let acc = e.account.as_str();
    let namespaces: Api<Namespace> = Api::all(client.clone());
    let secrets: Api<Secret> = Api::namespaced(client.clone(), ns);
    let tunnels: Api<Tunnel> = Api::namespaced(client.clone(), ns);
    let routes: Api<TunnelRoute> = Api::namespaced(client.clone(), ns);
    let tokens: Api<AccessServiceToken> = Api::namespaced(client.clone(), ns);
    let policies: Api<AccessPolicy> = Api::namespaced(client.clone(), ns);
    let apps: Api<AccessApplication> = Api::namespaced(client.clone(), ns);
    // One label below the zone: covered by the zone's universal certificate.
    let echo_host = format!("{ns}-echo.{}", e.zone_name);
    let tls_host = format!("{ns}-tls.{}", e.zone_name);

    namespaces
        .create(&PostParams::default(), &serde_json::from_value(json!({ "metadata": { "name": ns } })).unwrap())
        .await
        .unwrap();
    apply(
        &secrets,
        json!({
            "apiVersion": "v1", "kind": "Secret", "metadata": { "name": "cloudflare-api" },
            "stringData": { "CLOUDFLARE_API_TOKEN": e.token.expose_secret() },
        }),
    )
    .await;

    // == Origins: whoami over HTTP, and over HTTPS with a certificate from our own CA.
    let tls_origin = format!("whoami-tls.{ns}.svc");
    let (ca_pem, cert_pem, key_pem) = certificates(&tls_origin);
    apply(
        &secrets,
        json!({ "apiVersion": "v1", "kind": "Secret", "metadata": { "name": "origin-ca" }, "stringData": { "ca.crt": ca_pem } }),
    )
    .await;
    apply(
        &secrets,
        json!({
            "apiVersion": "v1", "kind": "Secret", "metadata": { "name": "whoami-tls" }, "type": "kubernetes.io/tls",
            "stringData": { "tls.crt": cert_pem, "tls.key": key_pem },
        }),
    )
    .await;
    whoami(client, ns, "whoami", 80, &[], None).await;
    whoami(
        client,
        ns,
        "whoami-tls",
        443,
        &["--port", "8443", "--cert", "/certs/tls.crt", "--key", "/certs/tls.key"],
        Some("whoami-tls"),
    )
    .await;

    // == Tunnel: created in Cloudflare; the connector Deployment runs the real cloudflared, which
    // must connect with the token from TUNNEL_TOKEN.
    apply(
        &tunnels,
        json!({
            "apiVersion": "tunnelgate.geeko.me/v1alpha1", "kind": "Tunnel", "metadata": { "name": "e2e" },
            "spec": {
                "cloudflare": { "accountId": acc, "credentialsSecretRef": { "name": "cloudflare-api" } },
                "originDefaults": { "caPoolSecretRef": { "name": "origin-ca", "key": "ca.crt" } },
            },
        }),
    )
    .await;
    wait_cond_for(&tunnels, "e2e", "Ready", "True", SLOW).await;
    println!("  ok    cloudflared connected with the token from TUNNEL_TOKEN");
    let tunnel_id = status_field(&tunnels, "e2e", "tunnelId").await.unwrap();

    // == Routes: plain HTTP, and HTTPS verified against the CA pool mounted into cloudflared.
    for (name, host, service, origin) in
        [("echo", &echo_host, "whoami", json!({})), ("tls", &tls_host, "whoami-tls", json!({ "protocol": "https" }))]
    {
        let port = if name == "tls" { 443 } else { 80 };
        apply(
            &routes,
            json!({
                "apiVersion": "tunnelgate.geeko.me/v1alpha1", "kind": "TunnelRoute", "metadata": { "name": name },
                "spec": { "tunnelRef": { "name": "e2e" }, "hostname": host,
                          "service": { "backendRef": { "name": service, "port": port } }, "origin": origin },
            }),
        )
        .await;
    }
    wait_cond_for(&routes, "echo", "Ready", "True", SLOW).await;
    wait_cond_for(&routes, "tls", "Ready", "True", SLOW).await;

    let edge = Edge::new();
    let r = edge.wait(&echo_host, "/hello?x=1", &[], |r| r.status == 200 && r.body.contains("GET /hello?x=1")).await;
    assert!(r.body.contains(&format!("Host: {echo_host}")), "{}", r.body);
    println!("  ok    HTTP origin reachable through the tunnel");
    edge.wait(&tls_host, "/secure", &[], |r| r.status == 200 && r.body.contains("GET /secure")).await;
    println!("  ok    HTTPS origin verified with caPool");

    // == Gateway API: an HTTPRoute on a Gateway of our class, published through the same tunnel.
    use tunnelgate_operator::gateway::{gateway_class_resource, gateway_resource, httproute_resource};
    let gw_host = format!("{ns}-gw.{}", e.zone_name);
    apply(
        &Api::<DynamicObject>::all_with(client.clone(), &gateway_class_resource()),
        json!({ "apiVersion": "gateway.networking.k8s.io/v1", "kind": "GatewayClass", "metadata": { "name": ns },
                "spec": { "controllerName": "tunnelgate.geeko.me/tunnel" } }),
    )
    .await;
    apply(
        &Api::<DynamicObject>::namespaced_with(client.clone(), ns, &gateway_resource()),
        json!({
            "apiVersion": "gateway.networking.k8s.io/v1", "kind": "Gateway",
            "metadata": { "name": "public" },
            "spec": { "gatewayClassName": ns,
                      "infrastructure": { "parametersRef": { "group": "tunnelgate.geeko.me", "kind": "Tunnel", "name": "e2e" } },
                      "listeners": [{ "name": "http", "port": 80, "protocol": "HTTP" }] },
        }),
    )
    .await;
    let httproutes = Api::<DynamicObject>::namespaced_with(client.clone(), ns, &httproute_resource());
    apply(
        &httproutes,
        json!({
            "apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute", "metadata": { "name": "gw" },
            "spec": { "parentRefs": [{ "name": "public" }], "hostnames": [gw_host],
                      "rules": [{ "matches": [{ "path": { "type": "PathPrefix", "value": "/via-gateway" } }],
                                  "backendRefs": [{ "name": "whoami", "port": 80 }] }] },
        }),
    )
    .await;
    // Resolving the name before its record exists would cache NXDOMAIN for the zone's negative TTL.
    eventually_for("HTTPRoute hostname in DNS", SLOW, || async {
        let records = cf.list_dns_records(zone_id, &DnsRecordFilter::default()).await.ok()?;
        records.iter().any(|r| r.name == gw_host).then_some(())
    })
    .await;
    edge.wait(&gw_host, "/via-gateway/x", &[], |r| r.status == 200 && r.body.contains("GET /via-gateway/x")).await;
    // Outside the PathPrefix the tunnel's fallback answers (404).
    let r = edge.wait(&gw_host, "/elsewhere", &[], |r| r.status == 404).await;
    println!("  ok    HTTPRoute published through the Gateway's tunnel (outside its path: {})", r.status);
    httproutes.delete("gw", &DeleteParams::default()).await.unwrap();
    eventually_for("HTTPRoute hostname removed from DNS", SLOW, || async {
        let records = cf.list_dns_records(zone_id, &DnsRecordFilter::default()).await.ok()?;
        (!records.iter().any(|r| r.name == gw_host)).then_some(())
    })
    .await;
    Api::<DynamicObject>::all_with(client.clone(), &gateway_class_resource())
        .delete(ns, &DeleteParams::default())
        .await
        .unwrap();
    println!("  ok    deleting the HTTPRoute removes its hostname");

    // == Access: the whole host for (nonexistent) admins, a path for a service token.
    let cfr = json!({ "accountId": acc, "credentialsSecretRef": { "name": "cloudflare-api" } });
    apply(
        &tokens,
        json!({
            "apiVersion": "tunnelgate.geeko.me/v1alpha1", "kind": "AccessServiceToken", "metadata": { "name": "ci" },
            "spec": { "cloudflare": cfr, "secretName": "ci-token" },
        }),
    )
    .await;
    wait_cond(&tokens, "ci", "Ready", "True").await;
    for (name, spec) in [
        ("admins", json!({ "decision": "allow", "include": [{ "emails": ["nobody@example.invalid"] }] })),
        ("ci-only", json!({ "decision": "non_identity", "include": [{ "serviceTokens": [{ "name": "ci" }] }] })),
    ] {
        let mut spec = spec;
        spec["cloudflare"] = cfr.clone();
        apply(
            &policies,
            json!({ "apiVersion": "tunnelgate.geeko.me/v1alpha1", "kind": "AccessPolicy", "metadata": { "name": name }, "spec": spec }),
        )
        .await;
        wait_cond(&policies, name, "Ready", "True").await;
    }
    for (name, destinations, policy) in
        [("site", json!([echo_host]), "admins"), ("agents", json!([format!("{echo_host}/agents")]), "ci-only")]
    {
        apply(
            &apps,
            json!({
                "apiVersion": "tunnelgate.geeko.me/v1alpha1", "kind": "AccessApplication", "metadata": { "name": name },
                "spec": { "cloudflare": cfr, "destinations": destinations, "policies": [{ "name": policy }] },
            }),
        )
        .await;
        wait_cond(&apps, name, "Ready", "True").await;
    }
    apply(
        &routes,
        json!({
            "apiVersion": "tunnelgate.geeko.me/v1alpha1", "kind": "TunnelRoute", "metadata": { "name": "echo" },
            "spec": { "tunnelRef": { "name": "e2e" }, "hostname": echo_host,
                      "service": { "backendRef": { "name": "whoami", "port": 80 } }, "origin": {},
                      "access": { "applicationRefs": [{ "name": "site" }, { "name": "agents" }] } },
        }),
    )
    .await;
    wait_cond(&routes, "echo", "AccessReady", "True").await;

    let secret = secrets.get("ci-token").await.unwrap().data.unwrap();
    let field = |k: &str| String::from_utf8(secret[k].0.clone()).unwrap();
    let creds = [
        ("CF-Access-Client-Id", field("CF-Access-Client-Id")),
        ("CF-Access-Client-Secret", field("CF-Access-Client-Secret")),
    ];

    let r = edge.wait(&echo_host, "/", &[], |r| r.status == 302 && r.location.contains(".cloudflareaccess.com")).await;
    println!("  ok    host app: anonymous request redirected to the Access login ({})", r.status);
    edge.wait(&echo_host, "/agents/v3/register", &creds, |r| {
        r.status == 200 && r.body.contains("GET /agents/v3/register")
    })
    .await;
    println!("  ok    path app wins over the host app, and matches by prefix (service token accepted below /agents)");
    // Access changes reach the edge at different times; a refusal must show up eventually.
    let start = tokio::time::Instant::now();
    let r = edge.wait(&echo_host, "/agents/v3/register", &[], |r| r.status != 200).await;
    println!(
        "  ok    path app: anonymous request refused ({}{}) after {:?}",
        r.status,
        location_note(&r),
        start.elapsed()
    );
    let start = tokio::time::Instant::now();
    let r = edge.wait(&echo_host, "/other", &creds, |r| r.status != 200).await;
    println!(
        "  ok    host app: service token refused outside the path app ({}{}) after {:?}",
        r.status,
        location_note(&r),
        start.elapsed()
    );
    let r = edge.get(&echo_host, "/agentsX", &creds).await;
    println!("  note  /agentsX with the service token: {}{}", r.status, location_note(&r));

    // == Deleting the Tunnel while cloudflared is connected: DNS records, connections and the
    // tunnel go away.
    tunnels.delete("e2e", &DeleteParams::default()).await.unwrap();
    eventually_for("Tunnel deleted", SLOW, || async { tunnels.get_opt("e2e").await.ok()?.is_none().then_some(()) })
        .await;
    let gone = cf.get_tunnel(acc, &tunnel_id).await.unwrap();
    assert!(gone.is_none_or(|t| t.deleted_at.is_some()), "Cloudflare tunnel deleted");
    let records = cf.list_dns_records(zone_id, &DnsRecordFilter::default()).await.unwrap();
    assert!(!records.iter().any(|r| r.name.starts_with(ns)), "DNS records removed with the tunnel");
    println!("  ok    deleting a connected tunnel removes its DNS records and the tunnel");

    // == The rest: Access objects, routes, the namespace.
    for name in ["site", "agents"] {
        apps.delete(name, &DeleteParams::default()).await.unwrap();
    }
    for name in ["admins", "ci-only"] {
        policies.delete(name, &DeleteParams::default()).await.unwrap();
    }
    tokens.delete("ci", &DeleteParams::default()).await.unwrap();
    for name in ["echo", "tls"] {
        routes.delete(name, &DeleteParams::default()).await.unwrap();
    }
    namespaces.delete(ns, &DeleteParams::default()).await.unwrap();
    eventually_for("namespace gone", SLOW, || async { namespaces.get_opt(ns).await.ok()?.is_none().then_some(()) })
        .await;
    let left = cloudflare_leftovers(&cf, acc, zone_id, ns).await;
    assert!(left.is_empty(), "the operator left Cloudflare objects behind: {left:?}");
    let cluster_id = tunnelgate_operator::cluster_id(client).await.unwrap();
    let found = tunnelgate_cli::find_leftovers(&cf, &cluster_id, acc).await.unwrap();
    let marked: Vec<_> = found.leftovers.iter().map(|l| format!("{} {}", l.kind(), l.describe())).collect();
    assert!(marked.is_empty(), "`tunnelgate sweep` still finds objects for this cluster: {marked:?}");
    println!("  ok    the operator removed everything it created; sweep finds nothing");
}

fn location_note(r: &Response) -> String {
    if r.location.is_empty() { String::new() } else { format!(" → {}", r.location.split('?').next().unwrap_or("")) }
}

/// A self-signed CA and a server certificate for `host` signed by it, as PEM.
fn certificates(host: &str) -> (String, String, String) {
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.distinguished_name.push(DnType::CommonName, "tunnelgate e2e CA");
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca_params, ca_key);
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec![host.to_owned()]).unwrap().signed_by(&key, &issuer).unwrap();
    (ca.pem(), cert.pem(), key.serialize_pem())
}

/// A whoami Deployment and Service; `tls_secret` is mounted at /certs.
async fn whoami(client: &kube::Client, ns: &str, name: &str, port: i32, args: &[&str], tls_secret: Option<&str>) {
    let target = if tls_secret.is_some() { 8443 } else { 80 };
    let (volumes, mounts) = match tls_secret {
        Some(s) => (
            json!([{ "name": "certs", "secret": { "secretName": s } }]),
            json!([{ "name": "certs", "mountPath": "/certs", "readOnly": true }]),
        ),
        None => (json!([]), json!([])),
    };
    apply(
        &Api::<Deployment>::namespaced(client.clone(), ns),
        json!({
            "apiVersion": "apps/v1", "kind": "Deployment", "metadata": { "name": name },
            "spec": {
                "selector": { "matchLabels": { "app": name } },
                "template": {
                    "metadata": { "labels": { "app": name } },
                    "spec": {
                        "containers": [{ "name": "whoami", "image": WHOAMI_IMAGE, "args": args,
                                         "ports": [{ "containerPort": target }], "volumeMounts": mounts }],
                        "volumes": volumes,
                    },
                },
            },
        }),
    )
    .await;
    apply(
        &Api::<Service>::namespaced(client.clone(), ns),
        json!({
            "apiVersion": "v1", "kind": "Service", "metadata": { "name": name },
            "spec": { "selector": { "app": name }, "ports": [{ "port": port, "targetPort": target }] },
        }),
    )
    .await;
}

struct Response {
    status: u16,
    location: String,
    body: String,
}

/// Requests through Cloudflare's edge. Hostnames are resolved over DNS-over-HTTPS rather than
/// the local resolver, which may have cached the name as nonexistent from an earlier run.
///
/// A public resolver that asked Cloudflare's nameservers a moment before a new record reached them
/// caches NXDOMAIN for the zone's negative TTL (up to 30 minutes), however long we wait on the
/// API first. Every proxied hostname of a zone is served by the same edge addresses, so once one
/// hostname has resolved, a name that doesn't resolve yet is sent to those addresses (with its own
/// SNI and Host). DNS resolution itself is proven by the first hostname.
struct Edge {
    http: reqwest::Client,
    edge_ips: std::sync::Mutex<Vec<IpAddr>>,
}

impl Edge {
    fn new() -> Self {
        Self {
            http: reqwest::Client::builder().timeout(Duration::from_secs(20)).build().unwrap(),
            edge_ips: Default::default(),
        }
    }

    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, String> {
        let v: Value = self
            .http
            .get("https://cloudflare-dns.com/dns-query")
            .query(&[("name", host), ("type", "A")])
            .header("accept", "application/dns-json")
            .send()
            .await
            .map_err(|e| format!("DNS-over-HTTPS: {e}"))?
            .json()
            .await
            .map_err(|e| format!("DNS-over-HTTPS: {e}"))?;
        let ips: Vec<IpAddr> = v["Answer"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|a| a["type"] == 1)
            .filter_map(|a| a["data"].as_str()?.parse().ok())
            .collect();
        if ips.is_empty() { Err(format!("no A records (DNS status {})", v["Status"])) } else { Ok(ips) }
    }

    async fn try_get(&self, host: &str, path: &str, headers: &[(&str, String)]) -> Result<Response, String> {
        let ips = match self.resolve(host).await {
            Ok(ips) => {
                *self.edge_ips.lock().unwrap() = ips.clone();
                ips
            }
            Err(e) => {
                let known = self.edge_ips.lock().unwrap().clone();
                if known.is_empty() {
                    return Err(e);
                }
                known
            }
        };
        let addrs: Vec<SocketAddr> = ips.into_iter().map(|ip| SocketAddr::new(ip, 443)).collect();
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .redirect(reqwest::redirect::Policy::none())
            .resolve_to_addrs(host, &addrs)
            .build()
            .map_err(|e| e.to_string())?;
        let mut req = http.get(format!("https://{host}{path}"));
        for (k, v) in headers {
            req = req.header(*k, v);
        }
        // The source chain says what failed (connect, TLS, timeout).
        let resp = req.send().await.map_err(|e| {
            let mut msg = e.to_string();
            let mut src = std::error::Error::source(&e);
            while let Some(s) = src {
                msg.push_str(&format!(": {s}"));
                src = s.source();
            }
            msg
        })?;
        let status = resp.status().as_u16();
        let location = resp.headers().get("location").and_then(|l| l.to_str().ok()).unwrap_or_default().to_owned();
        let body = resp.text().await.unwrap_or_default();
        Ok(Response { status, location, body })
    }

    async fn get(&self, host: &str, path: &str, headers: &[(&str, String)]) -> Response {
        self.wait(host, path, headers, |_| true).await
    }

    /// Retries until `ok` holds: DNS, tunnel configuration and Access changes take a while to
    /// reach the edge.
    async fn wait(
        &self,
        host: &str,
        path: &str,
        headers: &[(&str, String)],
        ok: impl Fn(&Response) -> bool,
    ) -> Response {
        let deadline = tokio::time::Instant::now() + SLOW;
        loop {
            let last = match self.try_get(host, path, headers).await {
                Ok(r) if ok(&r) => return r,
                Ok(r) => format!("{}{}", r.status, location_note(&r)),
                Err(e) => e,
            };
            assert!(tokio::time::Instant::now() < deadline, "https://{host}{path}: still {last}");
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    }
}
