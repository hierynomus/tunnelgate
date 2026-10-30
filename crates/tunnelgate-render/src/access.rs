//! Rendering of Access policies and applications into Cloudflare request bodies.

use serde_json::{Map, Value, json};
use tunnelgate_api::v1alpha1::{AccessApplicationSpec, AccessDecision, AccessPolicySpec, AccessRule, ObjectRef};
use tunnelgate_cf::types::{AccessApplication, AccessDestination, AccessPolicy, AppPolicyRef};

/// Expands typed rules into Cloudflare rule objects. `token_id` resolves an `AccessServiceToken`
/// reference to its Cloudflare token ID.
pub fn render_rules(
    rules: &[AccessRule],
    token_id: &dyn Fn(&ObjectRef) -> Result<String, String>,
) -> Result<Vec<Value>, String> {
    let mut out = Vec::new();
    for rule in rules {
        let before = out.len();
        out.extend(rule.emails.iter().map(|e| json!({ "email": { "email": e } })));
        out.extend(
            rule.email_domains.iter().map(|d| json!({ "email_domain": { "domain": d.trim_start_matches('@') } })),
        );
        if rule.everyone {
            out.push(json!({ "everyone": {} }));
        }
        out.extend(rule.ip_ranges.iter().map(|ip| json!({ "ip": { "ip": ip } })));
        for t in &rule.service_tokens {
            out.push(json!({ "service_token": { "token_id": token_id(t)? } }));
        }
        if rule.any_valid_service_token {
            out.push(json!({ "any_valid_service_token": {} }));
        }
        out.extend(rule.groups.iter().map(|g| json!({ "group": { "id": g } })));
        out.extend(rule.login_methods.iter().map(|m| json!({ "login_method": { "id": m } })));
        if out.len() == before {
            return Err("an Access rule has no selector set (emails, emailDomains, everyone, …)".to_owned());
        }
    }
    Ok(out)
}

/// A warning for combinations that are allowed but probably not intended.
pub fn policy_warning(spec: &AccessPolicySpec) -> Option<String> {
    let everyone = spec.include.iter().any(|r| r.everyone);
    (spec.decision == AccessDecision::Allow && everyone && spec.require.is_empty()).then(|| {
        "decision allow with include everyone admits anyone who can log in with any identity provider; \
         use bypass for public paths or add require rules"
            .to_owned()
    })
}

pub fn render_policy(
    spec: &AccessPolicySpec,
    name: String,
    token_id: &dyn Fn(&ObjectRef) -> Result<String, String>,
) -> Result<AccessPolicy, String> {
    Ok(AccessPolicy {
        id: String::new(),
        name,
        decision: spec.decision.as_str().to_owned(),
        include: render_rules(&spec.include, token_id).map_err(|e| format!("include: {e}"))?,
        require: render_rules(&spec.require, token_id).map_err(|e| format!("require: {e}"))?,
        exclude: render_rules(&spec.exclude, token_id).map_err(|e| format!("exclude: {e}"))?,
        session_duration: spec.session_duration.clone(),
    })
}

/// `policy_ids` are the reusable policy IDs in precedence order.
pub fn render_application(
    spec: &AccessApplicationSpec,
    name: String,
    policy_ids: &[String],
) -> Result<AccessApplication, String> {
    let destinations: Vec<String> =
        spec.destinations.iter().map(|d| normalize_destination(d)).collect::<Result<_, _>>()?;
    let extra: Map<String, Value> = spec
        .options
        .iter()
        .flatten()
        .map(|(k, v)| (snake_case(k), v.clone()))
        .filter(|(k, _)| !RESERVED_APP_FIELDS.contains(&k.as_str()))
        .collect();
    Ok(AccessApplication {
        id: String::new(),
        aud: None,
        name,
        app_type: "self_hosted".to_owned(),
        domain: destinations.first().cloned(),
        destinations: destinations
            .into_iter()
            .map(|uri| AccessDestination { destination_type: "public".to_owned(), uri })
            .collect(),
        policies: policy_ids
            .iter()
            .enumerate()
            .map(|(i, id)| AppPolicyRef { id: id.clone(), precedence: i as u32 + 1 })
            .collect(),
        session_duration: spec.session_duration.clone(),
        allowed_idps: spec.allowed_idps.clone(),
        app_launcher_visible: spec.app_launcher_visible,
        extra,
    })
}

/// Fields `options` may not override.
const RESERVED_APP_FIELDS: [&str; 9] =
    ["id", "aud", "name", "type", "domain", "destinations", "self_hosted_domains", "policies", "allowed_idps"];

fn normalize_destination(d: &str) -> Result<String, String> {
    let d = d.trim();
    let d = d.strip_prefix("https://").or_else(|| d.strip_prefix("http://")).unwrap_or(d);
    let d = d.trim_end_matches('/');
    if d.is_empty() || d.starts_with('/') {
        return Err(format!("destination {d:?} must be a hostname or hostname/path"));
    }
    Ok(d.to_ascii_lowercase())
}

fn snake_case(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    for c in s.chars() {
        if c.is_ascii_uppercase() {
            out.push('_');
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// Whether an Access application in Cloudflare already matches the rendered one (ignoring
/// server-assigned fields and expanded policy bodies).
pub fn application_matches(current: &AccessApplication, desired: &AccessApplication) -> bool {
    current.name == desired.name
        && current.app_type == desired.app_type
        && current.domain == desired.domain
        && current.destinations == desired.destinations
        && current.policies == desired.policies
        && current.session_duration.as_ref().is_none_or(|_| current.session_duration == desired.session_duration)
        && current.allowed_idps == desired.allowed_idps
        && current.app_launcher_visible == desired.app_launcher_visible
        && desired.extra.iter().all(|(k, v)| current.extra.get(k) == Some(v))
}

pub fn policy_matches(current: &AccessPolicy, desired: &AccessPolicy) -> bool {
    current.name == desired.name
        && current.decision == desired.decision
        && current.include == desired.include
        && current.require == desired.require
        && current.exclude == desired.exclude
        && (desired.session_duration.is_none() || current.session_duration == desired.session_duration)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_tokens(r: &ObjectRef) -> Result<String, String> {
        Err(format!("unknown token {}", r.name))
    }

    #[test]
    fn renders_all_selectors() {
        let rules = vec![
            AccessRule { emails: vec!["alice@example.com".into()], ..Default::default() },
            AccessRule { email_domains: vec!["@example.net".into()], ..Default::default() },
            AccessRule { everyone: true, ..Default::default() },
            AccessRule { ip_ranges: vec!["192.0.2.0/24".into()], ..Default::default() },
            AccessRule { service_tokens: vec![ObjectRef { name: "ci".into(), namespace: None }], ..Default::default() },
            AccessRule { any_valid_service_token: true, ..Default::default() },
            AccessRule { groups: vec!["g1".into()], login_methods: vec!["idp1".into()], ..Default::default() },
        ];
        let out = render_rules(&rules, &|r| Ok(format!("token-{}", r.name))).unwrap();
        insta::with_settings!({ prepend_module_to_snapshot => false }, {
            insta::assert_json_snapshot!("access-rules", out);
        });
        assert!(render_rules(&rules, &no_tokens).unwrap_err().contains("ci"));
        assert!(render_rules(&[AccessRule::default()], &no_tokens).is_err());
    }

    #[test]
    fn warns_on_allow_everyone() {
        let mut spec = AccessPolicySpec {
            cloudflare: Default::default(),
            name: None,
            decision: AccessDecision::Allow,
            include: vec![AccessRule { everyone: true, ..Default::default() }],
            require: vec![],
            exclude: vec![],
            session_duration: None,
        };
        assert!(policy_warning(&spec).is_some());
        spec.decision = AccessDecision::Bypass;
        assert!(policy_warning(&spec).is_none());
    }

    #[test]
    fn renders_path_scoped_application() {
        let spec = AccessApplicationSpec {
            cloudflare: Default::default(),
            name: None,
            destinations: vec!["rancher.example.org/v3/connect".into(), "https://rancher.example.org/cacerts/".into()],
            policies: vec![],
            session_duration: Some("24h".into()),
            allowed_idps: vec![],
            app_launcher_visible: false,
            options: Some(serde_json::from_value(json!({ "skipInterstitial": true, "domain": "evil" })).unwrap()),
        };
        let app = render_application(&spec, "Rancher agents [tunnelgate:3f2a9c1e]".into(), &["p1".into(), "p2".into()])
            .unwrap();
        insta::with_settings!({ prepend_module_to_snapshot => false }, {
            insta::assert_json_snapshot!("access-application", app);
        });
        assert!(application_matches(&app, &app));
    }
}
