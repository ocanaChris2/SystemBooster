//! Safety classification — the most important module. Deny-by-default for
//! anything that could destabilise the OS. A process or service is only ever
//! eligible for suspension when it is NOT on the hard allowlist and the active
//! profile opts it in.

use crate::process::ProcessInfo;
use crate::service::{ServiceInfo, ServiceState};

/// Processes that must never be suspended under any profile. Lower-cased.
pub const CRITICAL_PROCESSES: &[&str] = &[
    "system",
    "system idle process",
    "registry",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "dwm.exe",
    "fontdrvhost.exe",
    "wudfhost.exe",
    "msmpeng.exe",  // Defender
    "explorer.exe", // killing the shell is hostile; user can opt-in via Custom
    // SystemBooster's own components:
    "booster-service.exe",
    "booster-app.exe",
];

/// Services that must never be paused/stopped. Lower-cased service (key) names.
pub const CRITICAL_SERVICES: &[&str] = &[
    "rpcss",
    "dcomlaunch",
    "rpceptmapper",
    "power",
    "lsm",
    "schedule",
    "dnscache",
    "nsi",
    "brokerinfrastructure",
    "systemeventsbroker",
    "bfe",
    "mpssvc", // firewall
    "windefend",
    "wscsvc",
    "eventlog",
    "plugplay",
    "profsvc",
    "gpsvc",
    // SystemBooster's own service:
    "systembooster",
];

/// A named set of rules for what a profile is willing to suspend.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Profile {
    pub name: String,
    /// Suspend eligible user-space processes.
    pub suspend_processes: bool,
    /// Pause/stop eligible non-critical services.
    pub suspend_services: bool,
    /// Extra process names (lower-cased) the user explicitly never wants touched.
    pub user_excludes: Vec<String>,
    /// Extra process names (lower-cased) a Custom profile explicitly opts in,
    /// even if they would otherwise be skipped (but never if critical).
    pub user_includes: Vec<String>,
}

impl Profile {
    pub fn gaming() -> Self {
        Self {
            name: "Gaming".into(),
            suspend_processes: true,
            suspend_services: true,
            user_excludes: Vec::new(),
            user_includes: Vec::new(),
        }
    }

    pub fn work() -> Self {
        Self {
            name: "Work".into(),
            suspend_processes: true,
            suspend_services: false,
            user_excludes: Vec::new(),
            user_includes: Vec::new(),
        }
    }
}

/// Holds the allowlists and applies them. Allowlists are data so they can be
/// extended from a shipped JSON file without recompiling.
#[derive(Clone)]
pub struct Classifier {
    critical_processes: Vec<String>,
    critical_services: Vec<String>,
}

impl Default for Classifier {
    fn default() -> Self {
        Self {
            critical_processes: CRITICAL_PROCESSES.iter().map(|s| s.to_string()).collect(),
            critical_services: CRITICAL_SERVICES.iter().map(|s| s.to_string()).collect(),
        }
    }
}

impl Classifier {
    /// Build a classifier, merging extra critical entries (e.g. loaded from a
    /// shipped JSON allowlist) on top of the built-in defaults.
    pub fn with_extra(extra_processes: Vec<String>, extra_services: Vec<String>) -> Self {
        let mut c = Self::default();
        c.critical_processes
            .extend(extra_processes.into_iter().map(|s| s.to_lowercase()));
        c.critical_services
            .extend(extra_services.into_iter().map(|s| s.to_lowercase()));
        c
    }

    pub fn is_critical_process(&self, name: &str) -> bool {
        let n = name.to_lowercase();
        self.critical_processes.iter().any(|c| c == &n)
    }

    pub fn is_critical_service(&self, name: &str) -> bool {
        let n = name.to_lowercase();
        self.critical_services.iter().any(|c| c == &n)
    }

    /// Decide whether a process may be suspended under `profile`.
    pub fn process_eligible(&self, p: &ProcessInfo, profile: &Profile) -> bool {
        if !profile.suspend_processes {
            return false;
        }
        let name = p.name.to_lowercase();
        if self.is_critical_process(&name) {
            return false;
        }
        if profile.user_excludes.contains(&name) {
            return false;
        }
        // pid 0 and 4 are kernel-owned regardless of name.
        if p.pid == 0 || p.pid == 4 {
            return false;
        }
        true
    }

    /// Decide whether a service may be paused/stopped under `profile`.
    pub fn service_eligible(&self, s: &ServiceInfo, profile: &Profile) -> bool {
        if !profile.suspend_services {
            return false;
        }
        if self.is_critical_service(&s.name) {
            return false;
        }
        // Only touch services that are currently running.
        if s.state != ServiceState::Running {
            return false;
        }
        true
    }
}
