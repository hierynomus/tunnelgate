//! The in-cluster objects for a tunnel's connector: token Secret, cloudflared Deployment, PDB.

use std::collections::BTreeMap;

use k8s_openapi::ByteString;
use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec};
use k8s_openapi::api::core::v1::{
    Affinity, Capabilities, Container, ContainerPort, EnvVar, EnvVarSource, HTTPGetAction, KeyToPath, PodAffinityTerm,
    PodAntiAffinity, PodSecurityContext, PodSpec, PodTemplateSpec, Probe, ResourceRequirements, SeccompProfile, Secret,
    SecretKeySelector, SecretVolumeSource, SecurityContext, Volume, VolumeMount, WeightedPodAffinityTerm,
};
use k8s_openapi::api::policy::v1::{PodDisruptionBudget, PodDisruptionBudgetSpec};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::{Resource, ResourceExt};
use tunnelgate_api::DOMAIN;
use tunnelgate_api::v1alpha1::Tunnel;
use tunnelgate_render::ingress::CA_POOL_DIR;

/// Key in the token Secret.
pub const TOKEN_KEY: &str = "token";
pub const METRICS_PORT: i32 = 2000;
/// Annotation recording which tunnel a token Secret belongs to.
pub fn tunnel_id_annotation() -> String {
    format!("{DOMAIN}/tunnel-id")
}

pub fn token_secret_name(tunnel: &Tunnel) -> String {
    format!("{}-token", tunnel.name_any())
}

pub fn deployment_name(tunnel: &Tunnel) -> String {
    format!("{}-cloudflared", tunnel.name_any())
}

pub fn selector_labels(tunnel: &Tunnel) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("app.kubernetes.io/name".to_owned(), "cloudflared".to_owned()),
        ("app.kubernetes.io/instance".to_owned(), tunnel.name_any()),
        (format!("{DOMAIN}/tunnel"), tunnel.name_any()),
    ])
}

fn labels(tunnel: &Tunnel) -> BTreeMap<String, String> {
    let mut l = selector_labels(tunnel);
    l.insert("app.kubernetes.io/managed-by".to_owned(), "tunnelgate".to_owned());
    l.insert("app.kubernetes.io/component".to_owned(), "connector".to_owned());
    l
}

fn meta(tunnel: &Tunnel, name: String) -> ObjectMeta {
    ObjectMeta {
        name: Some(name),
        namespace: tunnel.namespace(),
        labels: Some(labels(tunnel)),
        owner_references: tunnel.controller_owner_ref(&()).map(|o| vec![o]),
        ..Default::default()
    }
}

pub fn token_secret(tunnel: &Tunnel, tunnel_id: &str, token: &str) -> Secret {
    let mut m = meta(tunnel, token_secret_name(tunnel));
    m.annotations = Some(BTreeMap::from([(tunnel_id_annotation(), tunnel_id.to_owned())]));
    Secret {
        metadata: m,
        type_: Some("Opaque".to_owned()),
        data: Some(BTreeMap::from([(TOKEN_KEY.to_owned(), ByteString(token.as_bytes().to_vec()))])),
        ..Default::default()
    }
}

/// The CA pool to mount, with a hash of its data so changes roll the pods.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaPool {
    pub secret_name: String,
    pub key: String,
    pub data_hash: String,
}

#[derive(Debug, Clone)]
pub struct ConnectorParams {
    pub image: String,
    pub replicas: i32,
    pub ca_pool: Option<CaPool>,
}

pub fn deployment(tunnel: &Tunnel, p: &ConnectorParams) -> Deployment {
    let spec = &tunnel.spec.connector;
    let mut args = vec![
        "tunnel".to_owned(),
        "--no-autoupdate".to_owned(),
        "--metrics".to_owned(),
        format!("0.0.0.0:{METRICS_PORT}"),
        "--protocol".to_owned(),
        spec.protocol.as_str().to_owned(),
    ];
    args.extend(spec.extra_args.iter().cloned());
    args.push("run".to_owned());

    let mut annotations = BTreeMap::new();
    let mut volumes = Vec::new();
    let mut mounts = Vec::new();
    if let Some(ca) = &p.ca_pool {
        annotations.insert(format!("{DOMAIN}/ca-pool-hash"), ca.data_hash.clone());
        volumes.push(Volume {
            name: "ca-pool".to_owned(),
            secret: Some(SecretVolumeSource {
                secret_name: Some(ca.secret_name.clone()),
                items: Some(vec![KeyToPath { key: ca.key.clone(), path: ca.key.clone(), mode: None }]),
                ..Default::default()
            }),
            ..Default::default()
        });
        mounts.push(VolumeMount {
            name: "ca-pool".to_owned(),
            mount_path: CA_POOL_DIR.to_owned(),
            read_only: Some(true),
            ..Default::default()
        });
    }

    let probe = |initial: i32, failures: i32| Probe {
        http_get: Some(HTTPGetAction {
            path: Some("/ready".to_owned()),
            port: IntOrString::Int(METRICS_PORT),
            ..Default::default()
        }),
        initial_delay_seconds: Some(initial),
        period_seconds: Some(10),
        failure_threshold: Some(failures),
        ..Default::default()
    };

    let container = Container {
        name: "cloudflared".to_owned(),
        image: Some(p.image.clone()),
        args: Some(args),
        env: Some(vec![
            // cloudflared reads the token from TUNNEL_TOKEN, keeping it out of the pod's args.
            EnvVar {
                name: "TUNNEL_TOKEN".to_owned(),
                value_from: Some(EnvVarSource {
                    secret_key_ref: Some(SecretKeySelector {
                        name: token_secret_name(tunnel),
                        key: TOKEN_KEY.to_owned(),
                        optional: Some(false),
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ]),
        ports: Some(vec![ContainerPort {
            name: Some("metrics".to_owned()),
            container_port: METRICS_PORT,
            protocol: Some("TCP".to_owned()),
            ..Default::default()
        }]),
        readiness_probe: Some(probe(5, 3)),
        liveness_probe: Some(probe(30, 6)),
        resources: Some(spec.resources.clone().unwrap_or_else(default_resources)),
        security_context: Some(SecurityContext {
            allow_privilege_escalation: Some(false),
            read_only_root_filesystem: Some(true),
            run_as_non_root: Some(true),
            capabilities: Some(Capabilities { drop: Some(vec!["ALL".to_owned()]), add: None }),
            seccomp_profile: Some(SeccompProfile { type_: "RuntimeDefault".to_owned(), localhost_profile: None }),
            ..Default::default()
        }),
        volume_mounts: (!mounts.is_empty()).then_some(mounts),
        ..Default::default()
    };

    let pod = PodSpec {
        automount_service_account_token: Some(false),
        enable_service_links: Some(false),
        security_context: Some(PodSecurityContext {
            run_as_non_root: Some(true),
            run_as_user: Some(65532),
            run_as_group: Some(65532),
            seccomp_profile: Some(SeccompProfile { type_: "RuntimeDefault".to_owned(), localhost_profile: None }),
            ..Default::default()
        }),
        containers: vec![container],
        volumes: (!volumes.is_empty()).then_some(volumes),
        node_selector: (!spec.node_selector.is_empty()).then(|| spec.node_selector.clone()),
        tolerations: (!spec.tolerations.is_empty()).then(|| spec.tolerations.clone()),
        affinity: (p.replicas > 1).then(|| anti_affinity(tunnel)),
        termination_grace_period_seconds: Some(30),
        ..Default::default()
    };

    Deployment {
        metadata: meta(tunnel, deployment_name(tunnel)),
        spec: Some(DeploymentSpec {
            replicas: Some(p.replicas),
            selector: LabelSelector { match_labels: Some(selector_labels(tunnel)), ..Default::default() },
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(labels(tunnel)),
                    annotations: (!annotations.is_empty()).then_some(annotations),
                    ..Default::default()
                }),
                spec: Some(pod),
            },
            ..Default::default()
        }),
        status: None,
    }
}

fn anti_affinity(tunnel: &Tunnel) -> Affinity {
    Affinity {
        pod_anti_affinity: Some(PodAntiAffinity {
            preferred_during_scheduling_ignored_during_execution: Some(vec![WeightedPodAffinityTerm {
                weight: 100,
                pod_affinity_term: PodAffinityTerm {
                    label_selector: Some(LabelSelector {
                        match_labels: Some(selector_labels(tunnel)),
                        ..Default::default()
                    }),
                    topology_key: "kubernetes.io/hostname".to_owned(),
                    ..Default::default()
                },
            }]),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn default_resources() -> ResourceRequirements {
    ResourceRequirements {
        requests: Some(BTreeMap::from([
            ("cpu".to_owned(), Quantity("10m".to_owned())),
            ("memory".to_owned(), Quantity("32Mi".to_owned())),
        ])),
        limits: Some(BTreeMap::from([("memory".to_owned(), Quantity("256Mi".to_owned()))])),
        ..Default::default()
    }
}

/// A PDB keeping one connector up during voluntary disruptions; only with more than one replica.
pub fn pdb(tunnel: &Tunnel, replicas: i32) -> Option<PodDisruptionBudget> {
    (replicas > 1).then(|| PodDisruptionBudget {
        metadata: meta(tunnel, deployment_name(tunnel)),
        spec: Some(PodDisruptionBudgetSpec {
            max_unavailable: Some(IntOrString::Int(1)),
            selector: Some(LabelSelector { match_labels: Some(selector_labels(tunnel)), ..Default::default() }),
            ..Default::default()
        }),
        status: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunnelgate_api::v1alpha1::TunnelSpec;

    fn tunnel() -> Tunnel {
        let spec: TunnelSpec = serde_json::from_value(serde_json::json!({
            "cloudflare": { "accountRef": "main" },
            "connector": { "replicas": 2, "protocol": "quic", "extraArgs": ["--edge-ip-version=4"] },
        }))
        .unwrap();
        let mut t = Tunnel::new("main", spec);
        t.metadata.namespace = Some("tunnelgate".into());
        t.metadata.uid = Some("0f0f0f0f-0000-0000-0000-000000000001".into());
        t
    }

    #[test]
    fn connector_objects() {
        let t = tunnel();
        let params = ConnectorParams {
            image: "cloudflare/cloudflared:2026.10.5@sha256:1b1d34d0a9c0bfca9de72db8460d328db3f19edd2b96169114e3e893a97bbe53".into(),
            replicas: 2,
            ca_pool: Some(CaPool { secret_name: "origin-ca".into(), key: "ca.crt".into(), data_hash: "abc123".into() }),
        };
        insta::with_settings!({ prepend_module_to_snapshot => false }, {
            insta::assert_yaml_snapshot!("connector-deployment", deployment(&t, &params));
            insta::assert_yaml_snapshot!("connector-pdb", pdb(&t, 2));
        });
        assert!(pdb(&t, 1).is_none());
        let s = token_secret(&t, "6f00", "secret-token");
        assert_eq!(s.metadata.name.as_deref(), Some("main-token"));
        assert_eq!(s.metadata.owner_references.unwrap()[0].kind, "Tunnel");
    }
}
