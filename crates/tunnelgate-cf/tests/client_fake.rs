//! The reqwest client against the fake: envelope handling, pagination, retries, errors.

use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use tunnelgate_cf::types::*;
use tunnelgate_cf::{Client, ClientConfig, CloudflareApi, RateLimit};
use tunnelgate_cf_fake::{ACCOUNT_ID, FakeCloudflare, Fault, TOKEN};

fn client(fake: &FakeCloudflare) -> Client {
    let config = ClientConfig {
        base_url: fake.base_url(),
        initial_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(5),
        rate_limit: None,
        ..Default::default()
    };
    Client::with_config(SecretString::from(TOKEN), config).unwrap()
}

#[tokio::test]
async fn tunnel_lifecycle() {
    let fake = FakeCloudflare::start().await;
    let cf = client(&fake);

    let t = cf.create_tunnel(ACCOUNT_ID, "main-tunnel").await.unwrap();
    assert_eq!(t.name, "main-tunnel");
    let err = cf.create_tunnel(ACCOUNT_ID, "main-tunnel").await.unwrap_err();
    assert!(err.is_conflict(), "{err}");

    let token = cf.get_tunnel_token(ACCOUNT_ID, &t.id).await.unwrap();
    assert!(token.expose_secret().contains(&t.id));

    let config = TunnelConfig {
        ingress: vec![
            IngressRule { hostname: Some("a.example.org".into()), service: "http://a:80".into(), ..Default::default() },
            IngressRule { service: "http_status:404".into(), ..Default::default() },
        ],
        origin_request: OriginRequest { connect_timeout: Some(30), ..Default::default() },
    };
    let applied = cf.put_tunnel_configuration(ACCOUNT_ID, &t.id, &config).await.unwrap();
    assert_eq!(applied.version, 1);
    let fetched = cf.get_tunnel_configuration(ACCOUNT_ID, &t.id).await.unwrap().unwrap();
    assert_eq!(fetched.config, Some(config));

    fake.set_connections(&t.id, 2);
    let got = cf.get_tunnel(ACCOUNT_ID, &t.id).await.unwrap().unwrap();
    assert_eq!(got.active_connections(), 2);
    assert!(cf.delete_tunnel(ACCOUNT_ID, &t.id).await.is_err(), "active connections block deletion");
    cf.cleanup_tunnel_connections(ACCOUNT_ID, &t.id).await.unwrap();
    cf.delete_tunnel(ACCOUNT_ID, &t.id).await.unwrap();
    assert!(cf.list_tunnels(ACCOUNT_ID, Some("main-tunnel")).await.unwrap().is_empty());
    assert!(cf.get_tunnel(ACCOUNT_ID, "00000000-0000-0000-0000-000000000000").await.unwrap().is_none());
}

#[tokio::test]
async fn paginates_dns_records() {
    let fake = FakeCloudflare::start().await;
    let cf = client(&fake);
    let zone = fake.zone_id("example.org");
    for i in 0..1203 {
        fake.add_dns_record(
            "example.org",
            serde_json::json!({ "name": format!("r{i}.example.org"), "type": "A", "content": "10.0.0.1" }),
        );
    }
    fake.clear_log();
    let all = cf.list_dns_records(&zone, &DnsRecordFilter::default()).await.unwrap();
    assert_eq!(all.len(), 1203);
    assert_eq!(fake.requests().len(), 2, "1000 per page");

    let one = cf
        .list_dns_records(&zone, &DnsRecordFilter { name: Some("r7.example.org".into()), ..Default::default() })
        .await
        .unwrap();
    assert_eq!(one.len(), 1);
}

#[tokio::test]
async fn dns_conflicts_and_comments() {
    let fake = FakeCloudflare::start().await;
    let cf = client(&fake);
    let zone = fake.zone_id("example.org");
    let rec = DnsRecordInput::proxied_cname("x.corp.example.org", "abc.cfargotunnel.com", "tunnelgate:c/ns/Tunnel/t");
    let created = cf.create_dns_record(&zone, &rec).await.unwrap();
    assert!(rec.matches(&created));
    let err = cf.create_dns_record(&zone, &rec).await.unwrap_err();
    assert!(err.has_code(81053), "{err}");
    let found = cf
        .list_dns_records(
            &zone,
            &DnsRecordFilter { comment_startswith: Some("tunnelgate:c/".into()), ..Default::default() },
        )
        .await
        .unwrap();
    assert_eq!(found, vec![created.clone()]);
    cf.delete_dns_record(&zone, &created.id).await.unwrap();
    cf.delete_dns_record(&zone, &created.id).await.unwrap(); // idempotent
}

#[tokio::test]
async fn retries_429_and_5xx_but_not_post_5xx() {
    let fake = FakeCloudflare::start().await;
    let cf = client(&fake);

    fake.inject(Fault::new(Some("GET"), "/zones", 503).times(2));
    assert_eq!(cf.list_zones(ACCOUNT_ID).await.unwrap().len(), 2);

    fake.inject(Fault::new(Some("POST"), "/cfd_tunnel", 429));
    cf.create_tunnel(ACCOUNT_ID, "after-429").await.unwrap();

    fake.inject(Fault::new(Some("POST"), "/cfd_tunnel", 502));
    fake.clear_log();
    let err = cf.create_tunnel(ACCOUNT_ID, "after-502").await.unwrap_err();
    assert_eq!(err.status(), Some(502));
    assert_eq!(fake.requests().len(), 1, "a POST that may have been applied is not retried");

    fake.inject(Fault::new(None, "/zones", 500).times(10));
    let err = cf.list_zones(ACCOUNT_ID).await.unwrap_err();
    assert!(err.is_transient());
}

#[tokio::test]
async fn requests_stay_within_the_budget() {
    let fake = FakeCloudflare::start().await;
    let config = ClientConfig {
        base_url: fake.base_url(),
        rate_limit: Some(RateLimit { per_second: 20.0, burst: 2 }),
        ..Default::default()
    };
    let cf = Client::with_config(SecretString::from(TOKEN), config).unwrap();
    let start = std::time::Instant::now();
    // Clones share the budget: 2 at once, then one per 50 ms.
    let calls = (0..6).map(|_| {
        let cf = cf.clone();
        tokio::spawn(async move { cf.list_zones(ACCOUNT_ID).await.unwrap() })
    });
    for c in calls {
        c.await.unwrap();
    }
    assert!(start.elapsed() >= Duration::from_millis(190), "took {:?}", start.elapsed());
}

#[tokio::test]
async fn bad_token_is_unauthorized_and_not_leaked() {
    let fake = FakeCloudflare::start().await;
    let config = ClientConfig { base_url: fake.base_url(), ..Default::default() };
    let cf = Client::with_config(SecretString::from("wrong-secret-value"), config).unwrap();
    let err = cf.list_zones(ACCOUNT_ID).await.unwrap_err();
    assert!(err.is_unauthorized());
    assert!(!err.to_string().contains("wrong-secret-value"));
    assert!(!format!("{cf:?}").contains("wrong-secret-value"));
}

#[tokio::test]
async fn access_objects() {
    let fake = FakeCloudflare::start().await;
    let cf = client(&fake);
    let policy = AccessPolicy {
        id: String::new(),
        name: "bypass".into(),
        decision: "bypass".into(),
        include: vec![serde_json::json!({ "everyone": {} })],
        require: vec![],
        exclude: vec![],
        session_duration: None,
    };
    let p = cf.create_access_policy(ACCOUNT_ID, &policy).await.unwrap();
    let app = AccessApplication {
        id: String::new(),
        aud: None,
        name: "agents".into(),
        app_type: "self_hosted".into(),
        domain: Some("r.example.org/v3/connect".into()),
        destinations: vec![AccessDestination {
            destination_type: "public".into(),
            uri: "r.example.org/v3/connect".into(),
        }],
        policies: vec![AppPolicyRef { id: p.id.clone(), precedence: 1 }],
        session_duration: None,
        allowed_idps: vec![],
        app_launcher_visible: false,
        extra: Default::default(),
    };
    let a = cf.create_access_app(ACCOUNT_ID, &app).await.unwrap();
    assert!(a.aud.is_some());
    assert_eq!(a.policies, app.policies);
    assert!(cf.delete_access_policy(ACCOUNT_ID, &p.id).await.unwrap_err().is_conflict(), "in use");
    cf.delete_access_app(ACCOUNT_ID, &a.id).await.unwrap();
    cf.delete_access_policy(ACCOUNT_ID, &p.id).await.unwrap();

    let tok = cf.create_service_token(ACCOUNT_ID, "ci", "8760h").await.unwrap();
    assert!(!tok.client_secret.expose_secret().is_empty());
    assert_eq!(cf.list_service_tokens(ACCOUNT_ID).await.unwrap(), vec![tok.token.clone()]);
    cf.delete_service_token(ACCOUNT_ID, &tok.token.id).await.unwrap();
}
