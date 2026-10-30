//! Helpers for `status.conditions`.

use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};
use k8s_openapi::jiff::Timestamp;
use tunnelgate_api::conditions::{reasons, types};

/// A condition value before it's written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cond {
    pub type_: &'static str,
    pub status: bool,
    pub reason: &'static str,
    pub message: String,
}

impl Cond {
    pub fn ok(type_: &'static str, reason: &'static str, message: impl Into<String>) -> Self {
        Self { type_, status: true, reason, message: message.into() }
    }

    pub fn fail(type_: &'static str, reason: &'static str, message: impl Into<String>) -> Self {
        Self { type_, status: false, reason, message: message.into() }
    }
}

/// A failed condition for a Cloudflare error; points at the permissions doc on 401/403.
pub fn cf_cond(type_: &'static str, what: &str, e: &tunnelgate_cf::Error) -> Cond {
    if e.is_unauthorized() {
        Cond::fail(
            type_,
            reasons::CLOUDFLARE_UNAUTHORIZED,
            format!("{what}: {e}; check that the API token has the permissions in docs/permissions.md"),
        )
    } else {
        Cond::fail(type_, reasons::CLOUDFLARE_ERROR, format!("{what}: {e}"))
    }
}

/// Sets a condition, keeping `lastTransitionTime` when the status doesn't change.
pub fn set(conditions: &mut Vec<Condition>, c: Cond, generation: Option<i64>) {
    let status = if c.status { "True" } else { "False" }.to_owned();
    let existing = conditions.iter_mut().find(|x| x.type_ == c.type_);
    match existing {
        Some(x) => {
            if x.status != status {
                x.last_transition_time = Time(Timestamp::now());
            }
            x.status = status;
            x.reason = c.reason.to_owned();
            x.message = c.message;
            x.observed_generation = generation;
        }
        None => conditions.push(Condition {
            type_: c.type_.to_owned(),
            status,
            reason: c.reason.to_owned(),
            message: c.message,
            observed_generation: generation,
            last_transition_time: Time(Timestamp::now()),
        }),
    }
}

/// Sets all `conds` and a `Ready` condition that is True only when all of them are.
pub fn set_all_with_ready(conditions: &mut Vec<Condition>, conds: Vec<Cond>, generation: Option<i64>) {
    let ready = match conds.iter().find(|c| !c.status) {
        None => Cond::ok(types::READY, reasons::RECONCILED, "all conditions are met"),
        Some(first) => Cond::fail(types::READY, first.reason, format!("{}: {}", first.type_, first.message)),
    };
    for c in conds {
        set(conditions, c, generation);
    }
    set(conditions, ready, generation);
}

/// Whether `conditions` has `type_` with status True.
pub fn is_true(conditions: &[Condition], type_: &str) -> bool {
    conditions.iter().any(|c| c.type_ == type_ && c.status == "True")
}

/// Compares two condition lists ignoring `lastTransitionTime`.
pub fn same(a: &[Condition], b: &[Condition]) -> bool {
    let key =
        |c: &Condition| (c.type_.clone(), c.status.clone(), c.reason.clone(), c.message.clone(), c.observed_generation);
    let mut ka: Vec<_> = a.iter().map(key).collect();
    let mut kb: Vec<_> = b.iter().map(key).collect();
    ka.sort();
    kb.sort();
    ka == kb
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ready_reflects_first_failure_and_keeps_transition_time() {
        let mut conds = Vec::new();
        set_all_with_ready(
            &mut conds,
            vec![
                Cond::ok(types::TUNNEL_CREATED, reasons::CREATED, "tunnel x"),
                Cond::fail(types::CONNECTOR_READY, reasons::NO_CONNECTIONS, "no connector is connected"),
            ],
            Some(1),
        );
        let ready = conds.iter().find(|c| c.type_ == "Ready").unwrap().clone();
        assert_eq!(ready.status, "False");
        assert_eq!(ready.reason, reasons::NO_CONNECTIONS);
        assert_eq!(ready.message, "ConnectorReady: no connector is connected");

        let created_at = conds[0].last_transition_time.clone();
        let before = conds.clone();
        set(&mut conds, Cond::ok(types::TUNNEL_CREATED, reasons::CREATED, "tunnel x"), Some(1));
        assert_eq!(conds[0].last_transition_time, created_at);
        assert!(same(&before, &conds));
        set(&mut conds, Cond::ok(types::CONNECTOR_READY, reasons::CONNECTED, "2 connections"), Some(1));
        assert!(!same(&before, &conds));
        assert!(is_true(&conds, types::CONNECTOR_READY));
    }
}
