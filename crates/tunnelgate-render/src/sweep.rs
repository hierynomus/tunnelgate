//! Which Cloudflare objects belong to a cluster. Used by `tunnelgate sweep`.

use tunnelgate_cf::types::{AccessApplication, AccessPolicy, DnsRecord, ServiceToken, Tunnel};

use crate::marker::{OwnerMarker, has_name_suffix, is_default_tunnel_name};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Leftover {
    DnsRecord { zone_id: String, id: String, name: String, owner: String },
    AccessApplication { id: String, name: String },
    AccessPolicy { id: String, name: String },
    ServiceToken { id: String, name: String },
    Tunnel { id: String, name: String },
}

impl Leftover {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::DnsRecord { .. } => "dns-record",
            Self::AccessApplication { .. } => "access-app",
            Self::AccessPolicy { .. } => "access-policy",
            Self::ServiceToken { .. } => "service-token",
            Self::Tunnel { .. } => "tunnel",
        }
    }

    pub fn id(&self) -> &str {
        match self {
            Self::DnsRecord { id, .. }
            | Self::AccessApplication { id, .. }
            | Self::AccessPolicy { id, .. }
            | Self::ServiceToken { id, .. }
            | Self::Tunnel { id, .. } => id,
        }
    }

    /// The name, plus the owning resource for DNS records.
    pub fn describe(&self) -> String {
        match self {
            Self::DnsRecord { name, owner, .. } => format!("{name} (owner {owner})"),
            Self::AccessApplication { name, .. }
            | Self::AccessPolicy { name, .. }
            | Self::ServiceToken { name, .. }
            | Self::Tunnel { name, .. } => name.clone(),
        }
    }
}

/// Everything in the given lists marked for `cluster_id`, in safe deletion order (DNS first,
/// tunnels last).
pub fn select(
    cluster_id: &str,
    dns: &[(String, DnsRecord)],
    apps: &[AccessApplication],
    policies: &[AccessPolicy],
    tokens: &[ServiceToken],
    tunnels: &[Tunnel],
) -> Vec<Leftover> {
    let mut out = Vec::new();
    for (zone_id, r) in dns {
        if let Some(m) = r.comment.as_deref().and_then(OwnerMarker::parse)
            && m.cluster_id == cluster_id
        {
            out.push(Leftover::DnsRecord {
                zone_id: zone_id.clone(),
                id: r.id.clone(),
                name: r.name.clone(),
                owner: format!("{}/{}/{}", m.namespace, m.kind, m.name),
            });
        }
    }
    out.extend(
        apps.iter()
            .filter(|a| has_name_suffix(&a.name, cluster_id))
            .map(|a| Leftover::AccessApplication { id: a.id.clone(), name: a.name.clone() }),
    );
    out.extend(
        policies
            .iter()
            .filter(|p| has_name_suffix(&p.name, cluster_id))
            .map(|p| Leftover::AccessPolicy { id: p.id.clone(), name: p.name.clone() }),
    );
    out.extend(
        tokens
            .iter()
            .filter(|t| has_name_suffix(&t.name, cluster_id))
            .map(|t| Leftover::ServiceToken { id: t.id.clone(), name: t.name.clone() }),
    );
    out.extend(
        tunnels
            .iter()
            .filter(|t| t.deleted_at.is_none() && is_default_tunnel_name(&t.name, cluster_id))
            .map(|t| Leftover::Tunnel { id: t.id.clone(), name: t.name.clone() }),
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLUSTER: &str = "3f2a9c1e-7b44-4d0e-9a51-0c8d2e6f1b7a";

    #[test]
    fn selects_only_this_cluster() {
        let rec = |id: &str, comment: Option<&str>| {
            (
                "z".to_owned(),
                DnsRecord {
                    id: id.into(),
                    name: format!("{id}.example.org"),
                    record_type: "CNAME".into(),
                    content: "x.cfargotunnel.com".into(),
                    proxied: true,
                    ttl: 1,
                    comment: comment.map(Into::into),
                },
            )
        };
        let dns = vec![
            rec("mine", Some(&format!("tunnelgate:{CLUSTER}/tunnelgate/Tunnel/main"))),
            rec("other-cluster", Some("tunnelgate:00000000-0000/tunnelgate/Tunnel/main")),
            rec("hand-made", Some("my record")),
            rec("plain", None),
        ];
        let tunnel = |name: &str| Tunnel {
            id: format!("id-{name}"),
            name: name.into(),
            created_at: None,
            deleted_at: None,
            status: None,
            config_src: None,
            connections: vec![],
        };
        let tunnels =
            vec![tunnel("tunnelgate-main-3f2a9c1e"), tunnel("tunnelgate-main-00000000"), tunnel("unrelated-tunnel")];
        let tokens = vec![
            ServiceToken {
                id: "t1".into(),
                name: "ci [tunnelgate:3f2a9c1e]".into(),
                client_id: "c".into(),
                expires_at: None,
                duration: None,
            },
            ServiceToken {
                id: "t2".into(),
                name: "ci".into(),
                client_id: "c".into(),
                expires_at: None,
                duration: None,
            },
        ];
        let found = select(CLUSTER, &dns, &[], &[], &tokens, &tunnels);
        assert_eq!(
            found,
            vec![
                Leftover::DnsRecord {
                    zone_id: "z".into(),
                    id: "mine".into(),
                    name: "mine.example.org".into(),
                    owner: "tunnelgate/Tunnel/main".into()
                },
                Leftover::ServiceToken { id: "t1".into(), name: "ci [tunnelgate:3f2a9c1e]".into() },
                Leftover::Tunnel { id: "id-tunnelgate-main-3f2a9c1e".into(), name: "tunnelgate-main-3f2a9c1e".into() },
            ]
        );
    }
}
