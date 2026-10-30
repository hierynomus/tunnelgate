//! Ownership markers on Cloudflare objects.

use std::fmt;

const PREFIX: &str = "tunnelgate:";

/// Identifies the cluster and resource that own a Cloudflare object:
/// `tunnelgate:<clusterId>/<namespace>/<kind>/<name>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OwnerMarker {
    pub cluster_id: String,
    pub namespace: String,
    pub kind: String,
    pub name: String,
}

impl OwnerMarker {
    pub fn new(cluster_id: &str, namespace: &str, kind: &str, name: &str) -> Self {
        Self {
            cluster_id: cluster_id.to_owned(),
            namespace: namespace.to_owned(),
            kind: kind.to_owned(),
            name: name.to_owned(),
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        let rest = s.strip_prefix(PREFIX)?;
        let mut parts = rest.splitn(4, '/');
        let (cluster_id, namespace, kind, name) = (parts.next()?, parts.next()?, parts.next()?, parts.next()?);
        if [cluster_id, namespace, kind, name].iter().any(|p| p.is_empty()) || name.contains('/') {
            return None;
        }
        Some(Self::new(cluster_id, namespace, kind, name))
    }

    /// Prefix shared by all markers of a cluster, for `comment.startswith` queries.
    pub fn cluster_prefix(cluster_id: &str) -> String {
        format!("{PREFIX}{cluster_id}/")
    }
}

impl fmt::Display for OwnerMarker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{PREFIX}{}/{}/{}/{}", self.cluster_id, self.namespace, self.kind, self.name)
    }
}

/// First 8 characters of the cluster ID (the `kube-system` namespace UID).
pub fn short_cluster_id(cluster_id: &str) -> &str {
    let end = cluster_id.char_indices().nth(8).map_or(cluster_id.len(), |(i, _)| i);
    &cluster_id[..end]
}

/// Suffix appended to the names of Access objects: ` [tunnelgate:<clusterId short>]`.
pub fn name_suffix(cluster_id: &str) -> String {
    format!(" [{PREFIX}{}]", short_cluster_id(cluster_id))
}

/// `name` with the ownership suffix.
pub fn marked_name(name: &str, cluster_id: &str) -> String {
    format!("{name}{}", name_suffix(cluster_id))
}

/// Whether a Cloudflare object name carries this cluster's suffix.
pub fn has_name_suffix(name: &str, cluster_id: &str) -> bool {
    name.ends_with(&name_suffix(cluster_id))
}

/// Default Cloudflare tunnel name: `<namespace>-<name>-<clusterId[:8]>`.
pub fn default_tunnel_name(namespace: &str, name: &str, cluster_id: &str) -> String {
    format!("{namespace}-{name}-{}", short_cluster_id(cluster_id))
}

/// Whether a tunnel name follows the default naming for this cluster.
pub fn is_default_tunnel_name(tunnel_name: &str, cluster_id: &str) -> bool {
    tunnel_name.ends_with(&format!("-{}", short_cluster_id(cluster_id)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLUSTER: &str = "3f2a9c1e-7b44-4d0e-9a51-0c8d2e6f1b7a";

    #[test]
    fn round_trips() {
        let m = OwnerMarker::new(CLUSTER, "tunnelgate", "Tunnel", "main");
        let s = m.to_string();
        assert_eq!(s, "tunnelgate:3f2a9c1e-7b44-4d0e-9a51-0c8d2e6f1b7a/tunnelgate/Tunnel/main");
        assert_eq!(OwnerMarker::parse(&s), Some(m));
        assert!(s.starts_with(&OwnerMarker::cluster_prefix(CLUSTER)));
    }

    #[test]
    fn rejects_foreign_or_malformed() {
        for bad in [
            "",
            "managed by terraform",
            "tunnelgate:",
            "tunnelgate:c/ns/Tunnel",
            "tunnelgate:c//Tunnel/x",
            "tunnelgate:c/ns/Tunnel/a/b",
            "cfgate:c/ns/Tunnel/x",
        ] {
            assert_eq!(OwnerMarker::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn names() {
        assert_eq!(short_cluster_id(CLUSTER), "3f2a9c1e");
        assert_eq!(short_cluster_id("abc"), "abc");
        assert_eq!(marked_name("Rancher", CLUSTER), "Rancher [tunnelgate:3f2a9c1e]");
        assert!(has_name_suffix("Rancher [tunnelgate:3f2a9c1e]", CLUSTER));
        assert!(!has_name_suffix("Rancher [tunnelgate:00000000]", CLUSTER));
        let t = default_tunnel_name("tunnelgate", "main", CLUSTER);
        assert_eq!(t, "tunnelgate-main-3f2a9c1e");
        assert!(is_default_tunnel_name(&t, CLUSTER));
    }
}
