//! DNS record planning: given the hostnames a tunnel should publish and the records
//! that exist, decide what to create, update and delete, without touching records we don't own.

use std::collections::{BTreeMap, BTreeSet};

use tunnelgate_cf::types::{DnsRecord, DnsRecordInput, Zone};

/// Record types that can't coexist with a CNAME of the same name.
const EXCLUSIVE_TYPES: [&str; 3] = ["A", "AAAA", "CNAME"];

/// A hostname that should point at the tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredRecord {
    pub hostname: String,
    pub zone_id: String,
    /// Take over a conflicting record that isn't ours.
    pub adopt: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsAction {
    Create { zone_id: String, record: DnsRecordInput },
    Update { zone_id: String, record_id: String, record: DnsRecordInput },
    Delete { zone_id: String, record_id: String, name: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostOutcome {
    /// Will be correct once the planned actions are applied.
    Ready,
    /// A record we don't own is in the way.
    Conflict { message: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DnsPlan {
    pub actions: Vec<DnsAction>,
    pub outcomes: BTreeMap<String, HostOutcome>,
}

/// Plans DNS changes.
///
/// `existing` must contain, per zone, every record that has `marker` as comment and every
/// A/AAAA/CNAME record whose name is a desired hostname.
pub fn plan(desired: &[DesiredRecord], existing: &[(String, DnsRecord)], target: &str, marker: &str) -> DnsPlan {
    let mut plan = DnsPlan::default();
    let mut wanted: BTreeSet<(String, String)> = BTreeSet::new();

    for d in desired {
        let host = d.hostname.to_ascii_lowercase();
        wanted.insert((d.zone_id.clone(), host.clone()));
        let input = DnsRecordInput::proxied_cname(&host, target, marker);
        let same_name: Vec<&DnsRecord> = existing
            .iter()
            .filter(|(z, r)| *z == d.zone_id && r.name.eq_ignore_ascii_case(&host))
            .map(|(_, r)| r)
            .filter(|r| EXCLUSIVE_TYPES.contains(&r.record_type.as_str()))
            .collect();
        let (ours, theirs): (Vec<&DnsRecord>, Vec<&DnsRecord>) =
            same_name.into_iter().partition(|r| r.comment.as_deref() == Some(marker));

        if !theirs.is_empty() && !d.adopt {
            let what = theirs.iter().map(|r| format!("{} {}", r.record_type, r.content)).collect::<Vec<_>>().join(", ");
            plan.outcomes.insert(
                host.clone(),
                HostOutcome::Conflict {
                    message: format!(
                        "DNS record(s) for {host} exist and are not managed by this tunnel ({what}); \
                         remove them or set spec.dns.adopt: true to take them over"
                    ),
                },
            );
            continue;
        }

        // Keep one record: ours if any, else an adoptable CNAME. Everything else goes.
        let keep = ours.first().copied().or_else(|| theirs.iter().copied().find(|r| r.record_type == "CNAME"));
        match keep {
            Some(r) if input.matches(r) => {}
            Some(r) => plan.actions.push(DnsAction::Update {
                zone_id: d.zone_id.clone(),
                record_id: r.id.clone(),
                record: input.clone(),
            }),
            None => {}
        }
        for r in ours.iter().chain(theirs.iter()) {
            if keep.is_none_or(|k| k.id != r.id) {
                plan.actions.push(DnsAction::Delete {
                    zone_id: d.zone_id.clone(),
                    record_id: r.id.clone(),
                    name: r.name.clone(),
                });
            }
        }
        if keep.is_none() {
            plan.actions.push(DnsAction::Create { zone_id: d.zone_id.clone(), record: input });
        }
        plan.outcomes.insert(host, HostOutcome::Ready);
    }

    // Our records for hostnames no longer published.
    for (zone_id, r) in existing {
        if r.comment.as_deref() == Some(marker) && !wanted.contains(&(zone_id.clone(), r.name.to_ascii_lowercase())) {
            plan.actions.push(DnsAction::Delete {
                zone_id: zone_id.clone(),
                record_id: r.id.clone(),
                name: r.name.clone(),
            });
        }
    }

    // Deletes first, so a CNAME can replace an adopted A record.
    plan.actions.sort_by_key(|a| !matches!(a, DnsAction::Delete { .. }));
    plan
}

/// The zone for a hostname: `explicit` if given (and the hostname is inside it), otherwise the
/// longest matching zone.
pub fn pick_zone<'a>(hostname: &str, zones: &'a [Zone], explicit: Option<&str>) -> Result<&'a Zone, String> {
    let host = hostname.trim_start_matches("*.").to_ascii_lowercase();
    let inside = |z: &Zone| host == z.name || host.ends_with(&format!(".{}", z.name));
    match explicit {
        Some(name) => {
            let zone = zones
                .iter()
                .find(|z| z.name.eq_ignore_ascii_case(name))
                .ok_or_else(|| format!("zone {name} is not visible to the API token"))?;
            if !inside(zone) {
                return Err(format!("hostname {hostname} is not inside zone {name}"));
            }
            Ok(zone)
        }
        None => zones
            .iter()
            .filter(|z| inside(z))
            .max_by_key(|z| z.name.len())
            .ok_or_else(|| format!("no zone visible to the API token contains {hostname}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MARKER: &str = "tunnelgate:c1/tunnelgate/Tunnel/main";
    const TARGET: &str = "6f.cfargotunnel.com";

    fn rec(id: &str, name: &str, t: &str, content: &str, comment: Option<&str>) -> (String, DnsRecord) {
        (
            "z".into(),
            DnsRecord {
                id: id.into(),
                name: name.into(),
                record_type: t.into(),
                content: content.into(),
                proxied: true,
                ttl: 1,
                comment: comment.map(Into::into),
            },
        )
    }

    fn want(host: &str, adopt: bool) -> DesiredRecord {
        DesiredRecord { hostname: host.into(), zone_id: "z".into(), adopt }
    }

    #[test]
    fn creates_missing_and_keeps_matching() {
        let existing = vec![rec("1", "a.example.org", "CNAME", TARGET, Some(MARKER))];
        let p = plan(&[want("a.example.org", false), want("b.example.org", false)], &existing, TARGET, MARKER);
        assert_eq!(
            p.actions,
            vec![DnsAction::Create {
                zone_id: "z".into(),
                record: DnsRecordInput::proxied_cname("b.example.org", TARGET, MARKER)
            }]
        );
        assert!(p.outcomes.values().all(|o| *o == HostOutcome::Ready));
    }

    #[test]
    fn updates_drifted_and_deletes_stale_owned() {
        let existing = vec![
            rec("1", "a.example.org", "CNAME", "old.cfargotunnel.com", Some(MARKER)),
            rec("2", "gone.example.org", "CNAME", TARGET, Some(MARKER)),
            rec("3", "other.example.org", "CNAME", TARGET, Some("tunnelgate:c1/x/Tunnel/other")),
        ];
        let p = plan(&[want("a.example.org", false)], &existing, TARGET, MARKER);
        assert_eq!(
            p.actions,
            vec![
                DnsAction::Delete { zone_id: "z".into(), record_id: "2".into(), name: "gone.example.org".into() },
                DnsAction::Update {
                    zone_id: "z".into(),
                    record_id: "1".into(),
                    record: DnsRecordInput::proxied_cname("a.example.org", TARGET, MARKER)
                },
            ]
        );
    }

    #[test]
    fn conflict_without_adopt_leaves_foreign_record() {
        let existing = vec![rec("9", "a.example.org", "A", "203.0.113.7", None)];
        let p = plan(&[want("a.example.org", false)], &existing, TARGET, MARKER);
        assert!(p.actions.is_empty());
        assert!(
            matches!(&p.outcomes["a.example.org"], HostOutcome::Conflict { message } if message.contains("A 203.0.113.7"))
        );
    }

    #[test]
    fn adopt_takes_over_cname_or_replaces_addresses() {
        let cname = vec![rec("9", "a.example.org", "CNAME", "elsewhere.example.com", Some("hand-made"))];
        let p = plan(&[want("a.example.org", true)], &cname, TARGET, MARKER);
        assert_eq!(
            p.actions,
            vec![DnsAction::Update {
                zone_id: "z".into(),
                record_id: "9".into(),
                record: DnsRecordInput::proxied_cname("a.example.org", TARGET, MARKER)
            }]
        );

        let addrs = vec![
            rec("7", "a.example.org", "A", "203.0.113.7", None),
            rec("8", "a.example.org", "AAAA", "2001:db8::1", None),
        ];
        let p = plan(&[want("a.example.org", true)], &addrs, TARGET, MARKER);
        assert_eq!(p.actions.len(), 3);
        assert!(matches!(p.actions[0], DnsAction::Delete { .. }));
        assert!(matches!(p.actions[1], DnsAction::Delete { .. }));
        assert!(matches!(p.actions[2], DnsAction::Create { .. }));
    }

    #[test]
    fn picks_longest_zone() {
        let zones = vec![
            Zone { id: "1".into(), name: "example.org".into(), account: None },
            Zone { id: "2".into(), name: "corp.example.org".into(), account: None },
        ];
        assert_eq!(pick_zone("rancher.corp.example.org", &zones, None).unwrap().id, "2");
        assert_eq!(pick_zone("*.apps.example.org", &zones, None).unwrap().id, "1");
        assert_eq!(pick_zone("rancher.corp.example.org", &zones, Some("example.org")).unwrap().id, "1");
        assert!(pick_zone("x.example.com", &zones, None).is_err());
        assert!(pick_zone("x.example.com", &zones, Some("example.org")).is_err());
        assert!(pick_zone("x.example.org", &zones, Some("other.org")).is_err());
    }
}
