//! Routes this proxy serves but does not supervise.
//!
//! The seam for the cluster migration. When `soli-oned` runs a workload on
//! another node, the proxy still has to route to it — but it did not start it,
//! has no PID for it, and must not try to manage it. So those routes arrive
//! from outside and live here, beside the ones the proxy owns.
//!
//! **Inert until something pushes a table.** An empty external table changes no
//! behaviour anywhere: `resolve_app_target` finds nothing here and falls through
//! exactly as before. That is deliberate — this ships alongside 30-odd running
//! apps, and the first version of a migration seam has to be provably a no-op.
//!
//! # Full URLs, not ports
//!
//! A target is `http://10.0.0.12:20001`, not `20001`. On a single node it reads
//! `http://127.0.0.1:20001` and behaves identically to what the proxy builds
//! for its own apps; on a cluster it names another machine, and *nothing here
//! changes*. Storing a port would work today and cost a second migration on the
//! day the second node arrives.
//!
//! # Why the index
//!
//! The table is pushed, and pushes can arrive out of order — a retry overtaking
//! the write that superseded it. Without a monotonic index, a late-arriving old
//! table silently reinstates routes that were deliberately removed, and it looks
//! exactly like a rollback nobody asked for.

use super::AppAuth;
use crate::config::Target;
use std::collections::HashMap;

/// A pushed routing table.
#[derive(Debug, Clone, Default)]
pub struct ExternalRoutes {
    /// Monotonic, chosen by the pusher. A push with an index at or below the
    /// current one is refused.
    pub index: u64,
    pub table: HashMap<String, Vec<Target>>,
    /// Basic Auth and forward-auth per pushed domain, enforced by this proxy.
    ///
    /// A pushed target is the workload's raw port on another node, with no
    /// proxy in front of it there, so an app's `[auth]` is enforced here or
    /// not at all. Pushed with the routes and replaced with them, so a domain
    /// can never be served under another table's credentials.
    pub auth: HashMap<String, AppAuth>,
}

impl ExternalRoutes {
    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }

    pub fn domains(&self) -> impl Iterator<Item = &String> {
        self.table.keys()
    }

    /// The first target for a host, with no balancing and no health check.
    ///
    /// What the pushed table was served by before [`ExternalRouteTable::pick`]:
    /// kept for the callers that only need to know a host is routed.
    pub fn target(&self, host: &str) -> Option<Target> {
        self.table.get(host)?.first().cloned()
    }

    /// The target at `turn` for a host, by weight, skipping unavailable ones.
    ///
    /// Weighted round-robin — the proxy's own `Weighted` policy — over the
    /// pushed targets, starting where `turn` lands and walking on past any
    /// target `is_available` refuses. When every target is refused the one
    /// the turn landed on is returned anyway: a request tried and answered 502
    /// says what is wrong, where "no target" would answer 421 for a domain that
    /// is routed.
    pub fn pick(
        &self,
        host: &str,
        turn: usize,
        is_available: &(dyn Fn(&str) -> bool + Sync),
    ) -> Option<Target> {
        let targets = self.table.get(host)?;
        if targets.is_empty() {
            return None;
        }
        // A weight of zero still gets a turn: the pusher sends 1 for every
        // instance, and a zero would otherwise remove it without saying so.
        let total: usize = targets.iter().map(|t| usize::from(t.weight.max(1))).sum();
        let slot = turn % total;
        let mut cumulative = 0;
        let mut first = 0;
        for (i, target) in targets.iter().enumerate() {
            cumulative += usize::from(target.weight.max(1));
            if slot < cumulative {
                first = i;
                break;
            }
        }
        (0..targets.len())
            .map(|k| &targets[(first + k) % targets.len()])
            .find(|t| is_available(t.url.as_str()))
            .or_else(|| targets.get(first))
            .cloned()
    }
}

/// Holds the current table, and refuses a stale push.
#[derive(Debug, Default)]
pub struct ExternalRouteTable {
    inner: parking_lot::RwLock<ExternalRoutes>,
    /// Whether any table was applied since start. Kept apart from the index
    /// because 0 is a legitimate index (a fresh Raft log) and not a "nothing
    /// yet" sentinel: with `current.index != 0` standing in for this flag, a
    /// table pushed at index 0 left the guard open, and any later push —
    /// including a replay of that same index 0 — was applied.
    applied: std::sync::atomic::AtomicBool,
    /// Advanced on every pick, so consecutive requests rotate across a
    /// domain's instances. Shared by all domains: the order within one domain
    /// is still a rotation, and one counter is one atomic on the hot path.
    turn: std::sync::atomic::AtomicUsize,
}

impl ExternalRouteTable {
    /// Replaces the table if `index` is newer. Returns whether it applied.
    ///
    /// Replaces rather than merges. A merge would make a route removable only
    /// by an explicit delete, and the pusher's whole model is "here is the
    /// complete set" — which is also what makes a missed push self-correcting
    /// on the next one.
    pub fn push(&self, routes: ExternalRoutes) -> bool {
        use std::sync::atomic::Ordering;
        let mut current = self.inner.write();
        // Read and set under the write lock, so two racing first pushes cannot
        // both see "nothing applied yet".
        if self.applied.load(Ordering::Acquire) && routes.index <= current.index {
            tracing::warn!(
                pushed = routes.index,
                current = current.index,
                "refusing an out-of-order routing table push"
            );
            return false;
        }
        tracing::info!(
            index = routes.index,
            domains = routes.table.len(),
            "external routing table updated"
        );
        *current = routes;
        self.applied.store(true, Ordering::Release);
        true
    }

    /// Auth (Basic and/or forward) pushed for a host, if any.
    pub fn auth(&self, host: &str) -> Option<AppAuth> {
        self.inner
            .read()
            .auth
            .get(host)
            .filter(|auth| auth.is_active())
            .cloned()
    }

    pub fn snapshot(&self) -> ExternalRoutes {
        self.inner.read().clone()
    }

    pub fn target(&self, host: &str) -> Option<Target> {
        self.inner.read().target(host)
    }

    /// The next target for a host, rotating across its instances and skipping
    /// those `is_available` refuses — the circuit breaker, on the request path.
    pub fn pick(&self, host: &str, is_available: &(dyn Fn(&str) -> bool + Sync)) -> Option<Target> {
        let turn = self.turn.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.inner.read().pick(host, turn, is_available)
    }

    /// How many instances the cluster pushed for this host — whether a
    /// failed request has anywhere else to go.
    pub fn instances(&self, host: &str) -> usize {
        self.inner.read().table.get(host).map_or(0, Vec::len)
    }

    /// Whether the cluster routes this host.
    pub fn serves(&self, host: &str) -> bool {
        self.inner.read().table.contains_key(host)
    }

    pub fn domains(&self) -> Vec<String> {
        self.inner.read().table.keys().cloned().collect()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use url::Url;

    fn target(url: &str) -> Target {
        Target {
            url: Url::parse(url).unwrap(),
            weight: 100,
        }
    }

    fn routes(index: u64, pairs: &[(&str, &str)]) -> ExternalRoutes {
        ExternalRoutes {
            index,
            table: pairs
                .iter()
                .map(|(host, url)| (host.to_string(), vec![target(url)]))
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn an_empty_table_resolves_nothing() {
        // The property that makes this safe to ship beside running production:
        // until something pushes, behaviour is byte-identical.
        let table = ExternalRouteTable::default();
        assert!(table.is_empty());
        assert!(table.target("x.soli.app").is_none());
        assert!(table.domains().is_empty());
    }

    #[test]
    fn a_pushed_route_resolves_to_its_full_url() {
        let table = ExternalRouteTable::default();
        assert!(table.push(routes(1, &[("x.soli.app", "http://10.0.0.12:20001")])));
        assert_eq!(
            table.target("x.soli.app").unwrap().url.as_str(),
            "http://10.0.0.12:20001/"
        );
    }

    #[test]
    fn an_out_of_order_push_is_refused() {
        // A retry overtaking the write that superseded it. Without the index a
        // late old table silently reinstates routes that were deliberately
        // removed, and it looks exactly like a rollback nobody asked for.
        let table = ExternalRouteTable::default();
        assert!(table.push(routes(5, &[("x.soli.app", "http://10.0.0.12:20001")])));
        assert!(!table.push(routes(4, &[("x.soli.app", "http://10.0.0.99:20001")])));
        assert!(!table.push(routes(5, &[("x.soli.app", "http://10.0.0.99:20001")])));
        assert_eq!(
            table.target("x.soli.app").unwrap().url.as_str(),
            "http://10.0.0.12:20001/",
            "a stale push overwrote the current table"
        );
        assert!(table.push(routes(6, &[("x.soli.app", "http://10.0.0.99:20001")])));
    }

    #[test]
    fn a_push_replaces_rather_than_merges() {
        // The pusher's model is "here is the complete set". Merging would make
        // a route removable only by an explicit delete, and a missed push would
        // no longer be self-correcting.
        let table = ExternalRouteTable::default();
        table.push(routes(
            1,
            &[
                ("a.soli.app", "http://10.0.0.11:20001"),
                ("b.soli.app", "http://10.0.0.11:20002"),
            ],
        ));
        table.push(routes(2, &[("a.soli.app", "http://10.0.0.11:20001")]));
        assert!(table.target("b.soli.app").is_none(), "b survived a replace");
        assert_eq!(table.domains(), vec!["a.soli.app".to_string()]);
    }

    #[test]
    fn the_first_push_is_accepted_at_any_index() {
        // A pusher restarting with a fresh counter must not be locked out by a
        // table it has no memory of.
        let table = ExternalRouteTable::default();
        assert!(table.push(routes(1, &[("x", "http://10.0.0.1:1")])));
    }

    #[test]
    fn a_push_at_index_zero_cannot_be_replayed() {
        // Index 0 is a real Raft index on a fresh cluster. It used to double as
        // "nothing applied yet", so once a table at 0 was in place every later
        // push was accepted — a replay of that very request included.
        let table = ExternalRouteTable::default();
        assert!(table.push(routes(0, &[("x.soli.app", "http://10.0.0.1:1")])));
        assert!(!table.push(routes(0, &[("x.soli.app", "http://10.0.0.66:1")])));
        assert_eq!(
            table.target("x.soli.app").unwrap().url.as_str(),
            "http://10.0.0.1:1/"
        );
        assert!(table.push(routes(1, &[("x.soli.app", "http://10.0.0.2:1")])));
    }

    #[test]
    fn pushed_auth_travels_and_is_replaced_with_its_table() {
        let table = ExternalRouteTable::default();
        let mut first = routes(1, &[("x.soli.app", "http://10.0.0.1:1")]);
        first.auth.insert(
            "x.soli.app".to_string(),
            AppAuth {
                users: vec![crate::auth::BasicAuth {
                    username: "admin".to_string(),
                    hash: format!("$2b$12${}", "a".repeat(53)),
                }],
                noauth: vec![],
                forward: None,
            },
        );
        assert!(table.push(first));
        assert_eq!(table.auth("x.soli.app").unwrap().users[0].username, "admin");
        assert!(table.auth("y.soli.app").is_none());
        // Le tableau suivant ne la porte plus : elle disparait avec lui.
        assert!(table.push(routes(2, &[("x.soli.app", "http://10.0.0.1:1")])));
        assert!(table.auth("x.soli.app").is_none());
    }

    #[test]
    fn several_targets_for_one_host_are_kept() {
        // Replicas. Only the first is used today, but dropping the rest at push
        // time would make adding a balancing policy a wire-format change.
        let table = ExternalRouteTable::default();
        table.push(ExternalRoutes {
            index: 1,
            table: HashMap::from([(
                "x.soli.app".to_string(),
                vec![
                    target("http://10.0.0.11:20001"),
                    target("http://10.0.0.12:20001"),
                ],
            )]),
            ..Default::default()
        });
        assert_eq!(table.snapshot().table["x.soli.app"].len(), 2);
    }

    fn two(weights: [u8; 2]) -> ExternalRoutes {
        ExternalRoutes {
            index: 1,
            table: [(
                "x.soli.app".to_string(),
                vec![
                    Target {
                        url: Url::parse("http://10.0.0.1:20001").unwrap(),
                        weight: weights[0],
                    },
                    Target {
                        url: Url::parse("http://10.0.0.2:20001").unwrap(),
                        weight: weights[1],
                    },
                ],
            )]
            .into(),
            ..Default::default()
        }
    }

    fn host_of(t: Option<Target>) -> String {
        t.unwrap().url.host_str().unwrap().to_string()
    }

    #[test]
    fn a_domain_with_two_instances_is_served_by_both_in_turn() {
        // It used to be the first instance, always: a second replica took no
        // traffic, and a dead first one took all of it.
        let routes = two([1, 1]);
        let all = |_: &str| true;
        let seen: Vec<String> = (0..4)
            .map(|turn| host_of(routes.pick("x.soli.app", turn, &all)))
            .collect();
        assert_eq!(seen, ["10.0.0.1", "10.0.0.2", "10.0.0.1", "10.0.0.2"]);
    }

    #[test]
    fn an_instance_whose_circuit_is_open_is_passed_over() {
        let routes = two([1, 1]);
        let not_first = |url: &str| !url.contains("10.0.0.1");
        for turn in 0..4 {
            assert_eq!(
                host_of(routes.pick("x.soli.app", turn, &not_first)),
                "10.0.0.2"
            );
        }
        // Every circuit open: the turn's own target is still tried, so the
        // answer is a 502 from a routed domain rather than a 421.
        let none = |_: &str| false;
        assert_eq!(host_of(routes.pick("x.soli.app", 1, &none)), "10.0.0.2");
    }

    #[test]
    fn weights_share_the_turns_and_a_zero_still_gets_one() {
        let routes = two([3, 1]);
        let all = |_: &str| true;
        let firsts = (0..4)
            .filter(|turn| host_of(routes.pick("x.soli.app", *turn, &all)) == "10.0.0.1")
            .count();
        assert_eq!(firsts, 3);
        let zero = two([0, 1]);
        let seen: Vec<String> = (0..2)
            .map(|turn| host_of(zero.pick("x.soli.app", turn, &all)))
            .collect();
        assert!(seen.contains(&"10.0.0.1".to_string()), "{seen:?}");
    }

    #[test]
    fn the_table_rotates_across_requests_and_knows_what_it_serves() {
        let table = ExternalRouteTable::default();
        assert!(table.push(two([1, 1])));
        assert!(table.serves("x.soli.app"));
        assert!(!table.serves("y.soli.app"));
        let all = |_: &str| true;
        let a = host_of(table.pick("x.soli.app", &all));
        let b = host_of(table.pick("x.soli.app", &all));
        assert_ne!(a, b, "two requests in a row went to the same instance");
    }
}
