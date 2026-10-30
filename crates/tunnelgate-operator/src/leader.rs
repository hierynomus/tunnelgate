//! Lease-based leader election (`coordination.k8s.io/v1`).
//!
//! [`acquire`] blocks until this process holds the lease, then renews it in the background. If a
//! renewal fails for longer than the lease duration the process exits, so two leaders never act
//! at once.

use std::time::Duration;

use k8s_openapi::api::coordination::v1::{Lease, LeaseSpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{MicroTime, ObjectMeta};
use k8s_openapi::jiff::{SignedDuration, Timestamp};
use kube::api::{Api, PostParams};
use tracing::{error, info, warn};

#[derive(Debug, Clone)]
pub struct LeaseConfig {
    pub namespace: String,
    pub name: String,
    pub identity: String,
    pub lease_duration: Duration,
    pub renew_interval: Duration,
}

pub async fn acquire(client: kube::Client, cfg: LeaseConfig) -> anyhow::Result<()> {
    let api: Api<Lease> = Api::namespaced(client, &cfg.namespace);
    loop {
        match try_acquire(&api, &cfg).await {
            Ok(true) => break,
            Ok(false) => {}
            Err(e) => warn!(error = %e, "leader election attempt failed"),
        }
        tokio::time::sleep(cfg.renew_interval).await;
    }
    info!(identity = %cfg.identity, lease = %cfg.name, "acquired leadership");
    tokio::spawn(async move {
        let mut last_renewal = tokio::time::Instant::now();
        loop {
            tokio::time::sleep(cfg.renew_interval).await;
            match try_acquire(&api, &cfg).await {
                Ok(true) => last_renewal = tokio::time::Instant::now(),
                Ok(false) => {
                    error!("lost leadership to another instance; exiting");
                    std::process::exit(1);
                }
                Err(e) => {
                    warn!(error = %e, "renewing the lease failed");
                    if last_renewal.elapsed() > cfg.lease_duration {
                        error!("could not renew the lease within its duration; exiting");
                        std::process::exit(1);
                    }
                }
            }
        }
    });
    Ok(())
}

/// One acquire-or-renew attempt; `Ok(true)` when we hold the lease afterwards.
async fn try_acquire(api: &Api<Lease>, cfg: &LeaseConfig) -> Result<bool, kube::Error> {
    let now = Timestamp::now();
    let duration_secs = cfg.lease_duration.as_secs() as i32;
    let Some(mut lease) = api.get_opt(&cfg.name).await? else {
        let lease = Lease {
            metadata: ObjectMeta { name: Some(cfg.name.clone()), ..Default::default() },
            spec: Some(LeaseSpec {
                holder_identity: Some(cfg.identity.clone()),
                lease_duration_seconds: Some(duration_secs),
                acquire_time: Some(MicroTime(now)),
                renew_time: Some(MicroTime(now)),
                lease_transitions: Some(0),
                ..Default::default()
            }),
        };
        return match api.create(&PostParams::default(), &lease).await {
            Ok(_) => Ok(true),
            Err(kube::Error::Api(s)) if s.code == 409 => Ok(false),
            Err(e) => Err(e),
        };
    };
    let spec = lease.spec.get_or_insert_with(Default::default);
    let ours = spec.holder_identity.as_deref() == Some(cfg.identity.as_str());
    let expired = spec.renew_time.as_ref().is_none_or(|t| {
        let held_for = i64::from(spec.lease_duration_seconds.unwrap_or(duration_secs));
        now > t.0 + SignedDuration::from_secs(held_for)
    });
    if !ours && !expired {
        return Ok(false);
    }
    if !ours {
        spec.holder_identity = Some(cfg.identity.clone());
        spec.acquire_time = Some(MicroTime(now));
        spec.lease_transitions = Some(spec.lease_transitions.unwrap_or(0) + 1);
    }
    spec.renew_time = Some(MicroTime(now));
    spec.lease_duration_seconds = Some(duration_secs);
    // `replace` carries the resourceVersion we read, so concurrent writers conflict.
    match api.replace(&cfg.name, &PostParams::default(), &lease).await {
        Ok(_) => Ok(true),
        Err(kube::Error::Api(s)) if s.code == 409 => Ok(false),
        Err(e) => Err(e),
    }
}
