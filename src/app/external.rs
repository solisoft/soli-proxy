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

use crate::config::Target;
use std::collections::HashMap;

/// A pushed routing table.
#[derive(Debug, Clone, Default)]
pub struct ExternalRoutes {
    /// Monotonic, chosen by the pusher. A push with an index at or below the
    /// current one is refused.
    pub index: u64,
    pub table: HashMap<String, Vec<Target>>,
}

impl ExternalRoutes {
    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }

    pub fn domains(&self) -> impl Iterator<Item = &String> {
        self.table.keys()
    }

    /// The first healthy-looking target for a host.
    ///
    /// Weight is carried but not yet used to balance: one backend is the common
    /// case today, and a load-balancing policy that nobody has exercised is
    /// worse than an obvious first-match. It is here so the *format* does not
    /// have to change when the policy arrives.
    pub fn target(&self, host: &str) -> Option<Target> {
        self.table.get(host)?.first().cloned()
    }
}

/// Holds the current table, and refuses a stale push.
#[derive(Debug, Default)]
pub struct ExternalRouteTable {
    inner: parking_lot::RwLock<ExternalRoutes>,
}

impl ExternalRouteTable {
    /// Replaces the table if `index` is newer. Returns whether it applied.
    ///
    /// Replaces rather than merges. A merge would make a route removable only
    /// by an explicit delete, and the pusher's whole model is "here is the
    /// complete set" — which is also what makes a missed push self-correcting
    /// on the next one.
    pub fn push(&self, routes: ExternalRoutes) -> bool {
        let mut current = self.inner.write();
        if routes.index <= current.index && current.index != 0 {
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
        true
    }

    pub fn snapshot(&self) -> ExternalRoutes {
        self.inner.read().clone()
    }

    pub fn target(&self, host: &str) -> Option<Target> {
        self.inner.read().target(host)
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
        });
        assert_eq!(table.snapshot().table["x.soli.app"].len(), 2);
    }
}
