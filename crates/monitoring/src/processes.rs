//! Filtering and sorting for the process manager.
//!
//! Separated from collection so the ordering rules can be tested against fixed data
//! rather than against whatever happens to be running.

use rc_protocol::system::ProcessInfo;

/// Largest number of processes returned in one listing.
///
/// A busy server can have thousands. The client paginates and filters; sending the lot
/// in one frame would push against the channel ceiling to display a screenful.
pub const MAX_PROCESS_RESULTS: usize = 500;

/// Which column a listing is ordered by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum ProcessSort {
    /// Highest CPU first. The default, because it answers "what is making this slow".
    #[default]
    CpuDescending,
    /// Highest resident memory first.
    MemoryDescending,
    /// Alphabetical by name, case-insensitively.
    NameAscending,
    /// Lowest process id first, which is roughly oldest first.
    PidAscending,
}

/// What to include in a listing.
#[derive(Debug, Clone, Default)]
pub struct ProcessFilter {
    /// Case-insensitive substring matched against the name and the executable path.
    pub query: String,
    /// When set, only processes owned by this user.
    pub user: Option<String>,
    /// Ordering.
    pub sort: ProcessSort,
}

impl ProcessFilter {
    /// Whether `process` passes this filter.
    #[must_use]
    pub fn matches(&self, process: &ProcessInfo) -> bool {
        if let Some(user) = &self.user
            && process.user.as_deref() != Some(user.as_str())
        {
            return false;
        }

        if self.query.is_empty() {
            return true;
        }

        // Lowercased on both sides so a search for "chrome" finds "Chrome.exe". ASCII
        // case folding only: full Unicode case folding would make the match depend on
        // locale, and a process list is not the place for that surprise.
        let needle = self.query.to_ascii_lowercase();
        process.name.to_ascii_lowercase().contains(&needle)
            || process
                .executable_path
                .as_deref()
                .is_some_and(|path| path.to_ascii_lowercase().contains(&needle))
    }
}

/// Apply a filter and ordering, and bound the result.
#[must_use]
pub fn apply(mut processes: Vec<ProcessInfo>, filter: &ProcessFilter) -> Vec<ProcessInfo> {
    processes.retain(|process| filter.matches(process));

    match filter.sort {
        // Every comparison falls back to the pid. Without a total order, processes with
        // equal CPU — which on an idle machine is nearly all of them — would reshuffle
        // on every refresh and be impossible to click.
        ProcessSort::CpuDescending => processes.sort_by(|a, b| {
            b.cpu_percent
                .partial_cmp(&a.cpu_percent)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(b.memory_bytes.cmp(&a.memory_bytes))
                .then(a.pid.cmp(&b.pid))
        }),
        ProcessSort::MemoryDescending => {
            processes.sort_by(|a, b| b.memory_bytes.cmp(&a.memory_bytes).then(a.pid.cmp(&b.pid)));
        }
        ProcessSort::NameAscending => processes.sort_by(|a, b| {
            a.name
                .to_ascii_lowercase()
                .cmp(&b.name.to_ascii_lowercase())
                .then(a.pid.cmp(&b.pid))
        }),
        ProcessSort::PidAscending => processes.sort_by_key(|process| process.pid),
    }

    processes.truncate(MAX_PROCESS_RESULTS);
    processes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process(pid: u32, name: &str, cpu: f32, memory: u64) -> ProcessInfo {
        ProcessInfo {
            pid,
            parent_pid: None,
            name: name.to_owned(),
            executable_path: Some(format!("/usr/bin/{name}")),
            user: Some("koren".to_owned()),
            cpu_percent: cpu,
            memory_bytes: memory,
            started_at_ms: None,
        }
    }

    fn sample() -> Vec<ProcessInfo> {
        vec![
            process(30, "Chrome.exe", 5.0, 900),
            process(10, "idle-a", 0.0, 200),
            process(20, "idle-b", 0.0, 100),
            process(40, "backup", 50.0, 50),
        ]
    }

    #[test]
    fn cpu_ordering_puts_the_busiest_first() {
        let sorted = apply(sample(), &ProcessFilter::default());
        assert_eq!(sorted[0].name, "backup");
        assert_eq!(sorted[1].name, "Chrome.exe");
    }

    #[test]
    fn equal_processes_keep_a_stable_order_across_refreshes() {
        // On an idle machine nearly everything reads 0% CPU. Without a total order the
        // list would reshuffle every second and be impossible to click.
        let first = apply(sample(), &ProcessFilter::default());
        let mut shuffled = sample();
        shuffled.reverse();
        let second = apply(shuffled, &ProcessFilter::default());

        let ids = |list: &[ProcessInfo]| list.iter().map(|p| p.pid).collect::<Vec<_>>();
        assert_eq!(ids(&first), ids(&second));
    }

    #[test]
    fn memory_ordering_puts_the_largest_first() {
        let filter = ProcessFilter {
            sort: ProcessSort::MemoryDescending,
            ..ProcessFilter::default()
        };
        let sorted = apply(sample(), &filter);
        assert_eq!(sorted[0].memory_bytes, 900);
    }

    #[test]
    fn name_ordering_ignores_case() {
        let filter = ProcessFilter {
            sort: ProcessSort::NameAscending,
            ..ProcessFilter::default()
        };
        let sorted = apply(sample(), &filter);
        let names: Vec<&str> = sorted.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["backup", "Chrome.exe", "idle-a", "idle-b"]);
    }

    #[test]
    fn pid_ordering_is_ascending() {
        let filter = ProcessFilter {
            sort: ProcessSort::PidAscending,
            ..ProcessFilter::default()
        };
        let sorted = apply(sample(), &filter);
        assert_eq!(
            sorted.iter().map(|p| p.pid).collect::<Vec<_>>(),
            vec![10, 20, 30, 40]
        );
    }

    #[test]
    fn a_search_is_case_insensitive_and_matches_the_path() {
        let by_name = ProcessFilter {
            query: "chrome".to_owned(),
            ..ProcessFilter::default()
        };
        assert_eq!(apply(sample(), &by_name).len(), 1);

        let by_path = ProcessFilter {
            query: "/usr/bin/BACKUP".to_owned(),
            ..ProcessFilter::default()
        };
        assert_eq!(apply(sample(), &by_path).len(), 1);
    }

    #[test]
    fn an_empty_search_matches_everything() {
        assert_eq!(apply(sample(), &ProcessFilter::default()).len(), 4);
    }

    #[test]
    fn a_search_that_matches_nothing_returns_nothing_rather_than_everything() {
        // The failure mode worth avoiding: a filter that silently degrades to "show
        // all" when it does not understand its input.
        let filter = ProcessFilter {
            query: "no-such-process".to_owned(),
            ..ProcessFilter::default()
        };
        assert!(apply(sample(), &filter).is_empty());
    }

    #[test]
    fn filtering_by_user_excludes_other_owners() {
        let mut processes = sample();
        processes.push(ProcessInfo {
            user: Some("root".to_owned()),
            ..process(50, "systemd", 0.0, 10)
        });

        let filter = ProcessFilter {
            user: Some("root".to_owned()),
            ..ProcessFilter::default()
        };
        let filtered = apply(processes, &filter);

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "systemd");
    }

    #[test]
    fn a_process_with_no_owner_is_excluded_by_a_user_filter() {
        // Unknown is not the same as matching. Including it would show another user's
        // processes to someone who asked only for their own.
        let processes = vec![ProcessInfo {
            user: None,
            ..process(60, "mystery", 0.0, 10)
        }];
        let filter = ProcessFilter {
            user: Some("koren".to_owned()),
            ..ProcessFilter::default()
        };
        assert!(apply(processes, &filter).is_empty());
    }

    #[test]
    fn a_listing_is_bounded() {
        let many: Vec<ProcessInfo> = (0..2_000)
            .map(|pid| process(pid, "many", 0.0, u64::from(pid)))
            .collect();
        assert_eq!(
            apply(many, &ProcessFilter::default()).len(),
            MAX_PROCESS_RESULTS
        );
    }

    #[test]
    fn a_process_with_no_path_still_matches_by_name() {
        let processes = vec![ProcessInfo {
            executable_path: None,
            ..process(70, "kthreadd", 0.0, 0)
        }];
        let filter = ProcessFilter {
            query: "kthread".to_owned(),
            ..ProcessFilter::default()
        };
        assert_eq!(apply(processes, &filter).len(), 1);
    }
}
