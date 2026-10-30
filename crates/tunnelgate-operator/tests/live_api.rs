//! Contract tests against the live Cloudflare API: every endpoint
//! tunnelgate uses, with the request bodies the controllers send, checked against the
//! assumptions the fake API encodes.
//!
//! Runs only with TUNNELGATE_LIVE_TESTS=1 and CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID and
//! CLOUDFLARE_TEST_ZONE set (see `mise.local.toml`). Everything it creates is named `tg-spike-…`;
//! the cleanup at the end (and at the start, for leftovers) deletes objects with that prefix only.
//! Secrets (tunnel token, service-token client secret) are never printed.

mod common;

use std::time::Duration;

use common::{cloudflare_cleanup, cloudflare_leftovers};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};
use tunnelgate_api::v1alpha1::{AccessApplicationSpec, AccessDecision, AccessPolicySpec, AccessRule};
use tunnelgate_cf::types::*;
use tunnelgate_cf::{Client, ClientConfig, CloudflareApi};
use tunnelgate_render::access::{application_matches, policy_matches, render_application, render_policy};

const PREFIX: &str = "tg-spike-";

struct Env {
    cf: Client,
    account: String,
    zone_name: String,
}

fn env() -> Option<Env> {
    if std::env::var("TUNNELGATE_LIVE_TESTS").ok().as_deref() != Some("1") {
        eprintln!("skipped: set TUNNELGATE_LIVE_TESTS=1 (mise run test-live)");
        return None;
    }
    let var = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("{k} must be set for live tests"));
    let token = SecretString::from(var("CLOUDFLARE_API_TOKEN"));
    Some(Env {
        cf: Client::with_config(token, ClientConfig::default()).unwrap(),
        account: var("CLOUDFLARE_ACCOUNT_ID"),
        zone_name: var("CLOUDFLARE_TEST_ZONE"),
    })
}

/// Collects findings: what matched our assumptions and what didn't.
#[derive(Default)]
struct Report {
    mismatches: Vec<String>,
}

impl Report {
    fn ok(&self, what: &str) {
        println!("  ok    {what}");
    }

    fn note(&self, what: &str) {
        println!("  note  {what}");
    }

    fn check(&mut self, cond: bool, what: &str, detail: impl FnOnce() -> String) {
        if cond {
            self.ok(what);
        } else {
            let d = detail();
            println!("  FAIL  {what}: {d}");
            self.mismatches.push(format!("{what}: {d}"));
        }
    }
}

/// JSON fields that differ between two values (top level), for mismatch details.
fn diff(a: &impl serde::Serialize, b: &impl serde::Serialize) -> String {
    let (a, b) = (serde_json::to_value(a).unwrap(), serde_json::to_value(b).unwrap());
    let (Some(a), Some(b)) = (a.as_object(), b.as_object()) else { return format!("{a} vs {b}") };
    let keys: std::collections::BTreeSet<_> = a.keys().chain(b.keys()).collect();
    keys.into_iter()
        .filter(|k| a.get(*k) != b.get(*k))
        .map(|k| format!("{k}: sent {} got {}", b.get(k).unwrap_or(&Value::Null), a.get(k).unwrap_or(&Value::Null)))
        .collect::<Vec<_>>()
        .join("; ")
}

async fn cleanup(e: &Env, zone_id: &str) {
    cloudflare_cleanup(&e.cf, &e.account, zone_id, PREFIX).await;
}

async fn leftovers(e: &Env, zone_id: &str) -> Vec<String> {
    cloudflare_leftovers(&e.cf, &e.account, zone_id, PREFIX).await
}

#[tokio::test]
async fn live_api_contract() {
    let Some(e) = env() else { return };
    let zones = e.cf.list_zones(&e.account).await.expect("listing zones");
    let zone = zones.iter().find(|z| z.name == e.zone_name).expect("CLOUDFLARE_TEST_ZONE not visible to the token");
    let zone_id = zone.id.clone();
    cleanup(&e, &zone_id).await;

    let run = format!("{PREFIX}{:x}", std::process::id() as u64 * 7919 % 0xfffff);
    println!("run {run}");
    // Run the checks in a task so a panic still reaches the cleanup below.
    let checks = {
        let e = Env {
            cf: Client::with_config(
                SecretString::from(std::env::var("CLOUDFLARE_API_TOKEN").unwrap()),
                ClientConfig::default(),
            )
            .unwrap(),
            account: e.account.clone(),
            zone_name: e.zone_name.clone(),
        };
        let (run, zone_id) = (run.clone(), zone_id.clone());
        tokio::spawn(async move {
            let mut r = Report::default();
            checks(&e, &zone_id, &run, &mut r).await;
            r.mismatches
        })
    };
    let result = checks.await;
    cleanup(&e, &zone_id).await;
    let left = leftovers(&e, &zone_id).await;
    let mismatches = result.expect("checks panicked (see above)");
    assert!(left.is_empty(), "objects left behind after cleanup: {left:?}");
    assert!(mismatches.is_empty(), "{} assumption(s) don't hold:\n{}", mismatches.len(), mismatches.join("\n"));
}

async fn checks(e: &Env, zone_id: &str, run: &str, r: &mut Report) {
    let (cf, acc) = (&e.cf, e.account.as_str());
    let host = format!("{run}.{}", e.zone_name);

    println!("== accounts and zones");
    match cf.list_accounts(None).await {
        Ok(accounts) => {
            r.check(accounts.iter().any(|a| a.id == acc), "GET /accounts lists the token's account", || {
                format!("{} account(s), not ours", accounts.len())
            })
        }
        Err(err) => r.check(false, "GET /accounts works (needed for accountName)", || err.to_string()),
    }
    r.ok("GET /zones?account.id finds the test zone");

    println!("== tunnel");
    let tunnel = cf.create_tunnel(acc, run).await.expect("creating a tunnel");
    r.check(tunnel.name == run, "POST cfd_tunnel {name, config_src: cloudflare}", || format!("{tunnel:?}"));
    match cf.create_tunnel(acc, run).await {
        Ok(t) => {
            r.check(false, "a duplicate tunnel name is rejected", || format!("created a second tunnel {}", t.id));
        }
        Err(err) => {
            r.check(err.is_conflict() || err.has_code(1013), "duplicate name: 409 / code 1013", || err.to_string())
        }
    }
    let token = cf.get_tunnel_token(acc, &tunnel.id).await.expect("tunnel token");
    r.check(token.expose_secret().len() > 20, "GET …/token returns the connector token", || "empty".into());
    match cf.get_tunnel_configuration(acc, &tunnel.id).await {
        Ok(c) => r.note(&format!(
            "fresh tunnel configuration: {}",
            c.map(|c| format!("version {} config {}", c.version, c.config.is_some())).unwrap_or("404".into())
        )),
        Err(err) => r.check(false, "GET …/configurations on a fresh tunnel", || err.to_string()),
    }

    let origin = OriginRequest {
        connect_timeout: Some(30),
        no_tls_verify: Some(false),
        origin_server_name: Some(host.clone()),
        http_host_header: Some(host.clone()),
        ca_pool: Some("/etc/tunnelgate/ca/ca.crt".into()),
        http2_origin: Some(true),
        keep_alive_timeout: Some(90),
        no_happy_eyeballs: Some(true),
        ..Default::default()
    };
    let config = TunnelConfig {
        ingress: vec![
            IngressRule {
                hostname: Some(host.clone()),
                path: Some("/v3/connect".into()),
                service: "https://rancher.cattle-system.svc:443".into(),
                origin_request: origin.clone(),
            },
            IngressRule {
                hostname: Some(host.clone()),
                service: "http://echo.default.svc:80".into(),
                ..Default::default()
            },
            IngressRule { service: "http_status:404".into(), ..Default::default() },
        ],
        origin_request: OriginRequest { connect_timeout: Some(10), ..Default::default() },
    };
    match cf.put_tunnel_configuration(acc, &tunnel.id, &config).await {
        Ok(applied) => {
            r.note(&format!("PUT configuration → version {}", applied.version));
            let got = cf.get_tunnel_configuration(acc, &tunnel.id).await.unwrap().unwrap();
            r.check(got.version == applied.version, "GET returns the version PUT returned", || {
                format!("{} vs {}", got.version, applied.version)
            });
            r.check(got.config.as_ref() == Some(&config), "GET echoes the configuration exactly", || {
                format!("sent {} got {}", json!(config), json!(got.config))
            });
            let again = cf.put_tunnel_configuration(acc, &tunnel.id, &config).await.unwrap();
            r.note(&format!("an identical PUT bumps the version: {}", again.version != applied.version));
        }
        Err(err) => r.check(false, "PUT configuration with all originRequest fields", || err.to_string()),
    }
    let bad = TunnelConfig {
        ingress: vec![IngressRule {
            hostname: Some(host.clone()),
            service: "http://x:80".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    match cf.put_tunnel_configuration(acc, &tunnel.id, &bad).await {
        Ok(_) => r.check(false, "a configuration without catch-all rule is rejected", || "accepted".into()),
        Err(err) => r.note(&format!("no catch-all rule: {err}")),
    }

    println!("== DNS");
    let marker = format!("tunnelgate:spike/{run}/Tunnel/main");
    let input = DnsRecordInput {
        name: host.clone(),
        record_type: "CNAME".into(),
        content: format!("{}.cfargotunnel.com", tunnel.id),
        proxied: true,
        ttl: 1,
        comment: Some(marker.clone()),
    };
    match cf.create_dns_record(zone_id, &input).await {
        Ok(rec) => {
            r.check(rec.comment.as_deref() == Some(marker.as_str()), "DNS comment stored (ownership marker)", || {
                format!("{:?}", rec.comment)
            });
            let by_comment = cf
                .list_dns_records(
                    zone_id,
                    &DnsRecordFilter { comment_startswith: Some("tunnelgate:spike/".into()), ..Default::default() },
                )
                .await
                .unwrap();
            r.check(by_comment.iter().any(|x| x.id == rec.id), "list by comment.startswith", || {
                format!("{} records", by_comment.len())
            });
            let by_name = cf
                .list_dns_records(zone_id, &DnsRecordFilter { name: Some(host.clone()), ..Default::default() })
                .await
                .unwrap();
            r.check(by_name.len() == 1, "list by exact name", || format!("{} records", by_name.len()));
            match cf.create_dns_record(zone_id, &input).await {
                Ok(dup) => r.check(false, "a duplicate CNAME is rejected", || format!("created {}", dup.id)),
                Err(err) => r.check(err.has_code(81053), "duplicate CNAME: code 81053", || err.to_string()),
            }
            let mut updated = input.clone();
            updated.comment = Some(format!("{marker}-adopted"));
            match cf.update_dns_record(zone_id, &rec.id, &updated).await {
                Ok(u) => r.check(u.comment == updated.comment, "PUT record updates the comment", || {
                    format!("{:?}", u.comment)
                }),
                Err(err) => r.check(false, "PUT record", || err.to_string()),
            }
        }
        Err(err) => r.check(false, "POST proxied CNAME with comment", || err.to_string()),
    }

    println!("== Access");
    let token_name = format!("{run}-token");
    let created = cf.create_service_token(acc, &token_name, "8760h").await;
    let token_id = match &created {
        Ok(t) => {
            r.check(!t.client_secret.expose_secret().is_empty(), "service token create returns client_secret", || {
                "empty".into()
            });
            r.check(t.token.client_id.ends_with(".access"), "client_id format", || "unexpected format".into());
            r.note(&format!("expires_at {:?}, duration {:?}", t.token.expires_at, t.token.duration));
            let listed = cf.list_service_tokens(acc).await.unwrap();
            let l = listed.iter().find(|x| x.id == t.token.id);
            r.check(l.is_some_and(|l| l.expires_at.is_some()), "listed tokens carry expires_at", || format!("{l:?}"));
            t.token.id.clone()
        }
        Err(err) => {
            r.check(false, "POST service token", || err.to_string());
            String::new()
        }
    };

    let policy = |decision, include: Vec<AccessRule>| AccessPolicySpec {
        cloudflare: Default::default(),
        name: None,
        decision,
        include,
        require: vec![],
        exclude: vec![],
        session_duration: Some("24h".into()),
    };
    let specs = [
        (
            "admins",
            policy(
                AccessDecision::Allow,
                vec![AccessRule { emails: vec!["spike@example.com".into()], ..Default::default() }],
            ),
        ),
        ("bypass", policy(AccessDecision::Bypass, vec![AccessRule { everyone: true, ..Default::default() }])),
        (
            "ci",
            policy(
                AccessDecision::NonIdentity,
                vec![AccessRule {
                    service_tokens: vec![tunnelgate_api::v1alpha1::ObjectRef { name: "t".into(), namespace: None }],
                    ..Default::default()
                }],
            ),
        ),
    ];
    let mut policy_ids = Vec::new();
    for (name, spec) in &specs {
        let desired =
            render_policy(spec, format!("{run}-{name} [tunnelgate:spike000]"), &|_| Ok(token_id.clone())).unwrap();
        match cf.create_access_policy(acc, &desired).await {
            Ok(p) => {
                let got = cf.get_access_policy(acc, &p.id).await.unwrap().unwrap();
                r.check(
                    policy_matches(&got, &desired),
                    &format!("policy {name}: GET matches what we sent (no update loop)"),
                    || diff(&got, &desired),
                );
                policy_ids.push(p.id);
            }
            Err(err) => r.check(false, &format!("POST reusable policy {name}"), || err.to_string()),
        }
    }

    let app_spec = |destinations: Vec<String>| AccessApplicationSpec {
        cloudflare: Default::default(),
        name: None,
        destinations,
        policies: vec![],
        session_duration: Some("24h".into()),
        allowed_idps: vec![],
        app_launcher_visible: false,
        options: None,
    };
    if policy_ids.len() == 3 {
        let ui = render_application(
            &app_spec(vec![host.clone()]),
            format!("{run}-ui [tunnelgate:spike000]"),
            &policy_ids[..1],
        )
        .unwrap();
        let agents_spec = app_spec(vec![format!("{host}/v3/connect"), format!("{host}/ping")]);
        let agents =
            render_application(&agents_spec, format!("{run}-agents [tunnelgate:spike000]"), &policy_ids[1..]).unwrap();
        for (name, desired) in [("ui", &ui), ("agents (path destinations)", &agents)] {
            match cf.create_access_app(acc, desired).await {
                Ok(app) => {
                    r.check(app.aud.is_some(), &format!("app {name}: aud returned"), || "missing".into());
                    let got = cf.get_access_app(acc, &app.id).await.unwrap().unwrap();
                    r.check(
                        application_matches(&got, desired),
                        &format!("app {name}: GET matches what we sent"),
                        || diff(&got, desired),
                    );
                    if name.starts_with("agents") {
                        let mut changed = desired.clone();
                        changed.destinations[1].uri = format!("{host}/v3/import");
                        match cf.update_access_app(acc, &app.id, &changed).await {
                            Ok(u) => r.check(
                                u.id == app.id && application_matches(&u, &changed),
                                "PUT app updates destinations in place",
                                || diff(&u, &changed),
                            ),
                            Err(err) => r.check(false, "PUT app", || err.to_string()),
                        }
                    }
                }
                Err(err) => r.check(false, &format!("POST app {name}"), || err.to_string()),
            }
        }
        match cf.delete_access_policy(acc, &policy_ids[0]).await {
            Ok(()) => r.note("Cloudflare deletes a policy that an app still uses (detaching it)"),
            Err(err) => r.note(&format!("deleting a policy in use: HTTP {:?}: {err}", err.status())),
        }
    }

    println!("== deletion");
    match cf.delete_tunnel(acc, &tunnel.id).await {
        Ok(()) => r.ok("DELETE a tunnel without connections"),
        Err(err) => r.check(false, "DELETE a tunnel without connections", || err.to_string()),
    }
    let after = cf.get_tunnel(acc, &tunnel.id).await;
    r.note(&format!(
        "GET a deleted tunnel: {}",
        match after {
            Ok(Some(t)) => format!("still returned (deleted_at {:?})", t.deleted_at),
            Ok(None) => "404".into(),
            Err(err) => err.to_string(),
        }
    ));
    let live = cf.list_tunnels(acc, Some(run)).await.unwrap();
    r.check(live.is_empty(), "list_tunnels hides deleted tunnels", || format!("{} listed", live.len()));
    tokio::time::sleep(Duration::from_millis(1)).await;
}
