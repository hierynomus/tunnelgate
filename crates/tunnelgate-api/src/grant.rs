use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Same shape and semantics as Gateway API's `ReferenceGrant`, for clusters without it: lives in
/// the namespace of the referenced objects (`to`) and permits references from `from`.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
#[kube(
    group = "tunnelgate.geeko.me",
    version = "v1alpha1",
    kind = "RouteGrant",
    namespaced,
    shortname = "rg",
    category = "tunnelgate",
    doc = "Permits references from other namespaces into this one (ReferenceGrant semantics)."
)]
#[serde(rename_all = "camelCase")]
pub struct RouteGrantSpec {
    pub from: Vec<GrantFrom>,
    pub to: Vec<GrantTo>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GrantFrom {
    /// API group; `""` for the core group.
    pub group: String,
    pub kind: String,
    pub namespace: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GrantTo {
    pub group: String,
    pub kind: String,
    /// A specific object; omitted means all objects of the kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Whether a set of grants (ReferenceGrant or RouteGrant specs, in the target namespace)
/// permits a reference.
pub fn grants_permit<'a>(
    grants: impl IntoIterator<Item = &'a RouteGrantSpec>,
    from: (&str, &str, &str),
    to: (&str, &str, &str),
) -> bool {
    let (from_group, from_kind, from_ns) = from;
    let (to_group, to_kind, to_name) = to;
    grants.into_iter().any(|g| {
        g.from.iter().any(|f| f.group == from_group && f.kind == from_kind && f.namespace == from_ns)
            && g.to
                .iter()
                .any(|t| t.group == to_group && t.kind == to_kind && t.name.as_deref().is_none_or(|n| n == to_name))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(name: Option<&str>) -> RouteGrantSpec {
        RouteGrantSpec {
            from: vec![GrantFrom {
                group: "tunnelgate.geeko.me".into(),
                kind: "TunnelRoute".into(),
                namespace: "cattle-system".into(),
            }],
            to: vec![GrantTo {
                group: "tunnelgate.geeko.me".into(),
                kind: "Tunnel".into(),
                name: name.map(Into::into),
            }],
        }
    }

    #[test]
    fn permits_matching_reference() {
        let from = ("tunnelgate.geeko.me", "TunnelRoute", "cattle-system");
        let to = ("tunnelgate.geeko.me", "Tunnel", "main");
        assert!(grants_permit([&grant(None)], from, to));
        assert!(grants_permit([&grant(Some("main"))], from, to));
        assert!(!grants_permit([&grant(Some("other"))], from, to));
        assert!(!grants_permit([&grant(None)], ("tunnelgate.geeko.me", "TunnelRoute", "default"), to));
        assert!(!grants_permit([&grant(None)], from, ("", "Service", "main")));
    }
}
