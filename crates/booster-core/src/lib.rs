//! `booster-core` — the privilege-agnostic engine behind SystemBooster.
//!
//! The engine knows how to scan the system, classify what is safe to touch,
//! apply a boost (suspend processes / pause services), and restore everything
//! afterwards. All OS interaction is hidden behind the [`ProcessController`]
//! and [`ServiceController`] traits so the decision logic can be unit-tested
//! on any platform with the mock backends, while the real Win32 backends are
//! compiled only on Windows.

pub mod classify;
pub mod process;
pub mod service;
pub mod session;
pub mod snapshot;

use std::sync::Arc;

use classify::Classifier;
use process::ProcessController;
use service::ServiceController;
use session::{ProcessRecord, RestoreSession, ServiceRecord, SessionStore};

/// Errors surfaced by the engine and its backends.
#[derive(Debug, thiserror::Error)]
pub enum BoosterError {
    #[error("OS error: {0}")]
    Os(String),
    #[error("item is protected and may never be modified: {0}")]
    Protected(String),
    #[error("no active boost session")]
    NoActiveSession,
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, BoosterError>;

/// The result of applying a boost.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BoostReport {
    pub session_id: uuid::Uuid,
    pub suspended_processes: usize,
    pub changed_services: usize,
    pub skipped: Vec<String>,
}

/// Ties together the backends, classifier and session store. This is the type
/// the service host drives in response to IPC requests.
pub struct BoosterEngine {
    processes: Arc<dyn ProcessController>,
    services: Arc<dyn ServiceController>,
    classifier: Classifier,
    store: SessionStore,
    active: Option<RestoreSession>,
}

impl BoosterEngine {
    pub fn new(
        processes: Arc<dyn ProcessController>,
        services: Arc<dyn ServiceController>,
        classifier: Classifier,
        store: SessionStore,
    ) -> Self {
        Self {
            processes,
            services,
            classifier,
            store,
            active: None,
        }
    }

    /// True if a boost is currently applied.
    pub fn is_boosted(&self) -> bool {
        self.active.is_some()
    }

    /// On startup the service calls this: if a persisted session exists it means
    /// a previous boost did not get cleanly restored (crash / reboot), so we
    /// restore it immediately before doing anything else.
    pub fn recover(&mut self) -> Result<bool> {
        if let Some(session) = self.store.load()? {
            self.active = Some(session);
            self.end_boost()?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Enumerate every process/service and mark which ones the given profile is
    /// eligible to suspend. Critical items are always reported as locked.
    pub fn scan(&self, profile: &classify::Profile) -> Result<ScanResult> {
        let mut processes = Vec::new();
        for p in self.processes.enumerate()? {
            let eligible = self.classifier.process_eligible(&p, profile);
            processes.push(Candidate {
                key: p.pid.to_string(),
                name: p.name,
                eligible,
            });
        }
        let mut services = Vec::new();
        for s in self.services.enumerate()? {
            let eligible = self.classifier.service_eligible(&s, profile);
            services.push(Candidate {
                key: s.name.clone(),
                name: s.display_name.unwrap_or(s.name),
                eligible,
            });
        }
        Ok(ScanResult {
            processes,
            services,
        })
    }

    /// Apply a boost for `profile`. Writes the restore session to disk *before*
    /// making any change (write-ahead), so a crash mid-apply is still
    /// recoverable.
    pub fn start_boost(&mut self, profile: &classify::Profile) -> Result<BoostReport> {
        if self.active.is_some() {
            // Idempotent-ish: refuse to stack boosts.
            return Err(BoosterError::Os("a boost is already active".into()));
        }
        let mut session = RestoreSession::new(profile.name.clone());
        let mut skipped = Vec::new();

        // Reserve the session on disk first.
        self.store.save(&session)?;

        for p in self.processes.enumerate()? {
            if !self.classifier.process_eligible(&p, profile) {
                continue;
            }
            match self.processes.suspend(p.pid) {
                Ok(()) => {
                    session.suspended_processes.push(ProcessRecord {
                        pid: p.pid,
                        name: p.name,
                        image_path: p.image_path,
                        start_time: p.start_time,
                    });
                    self.store.save(&session)?;
                }
                Err(e) => skipped.push(format!("process {}: {e}", p.name)),
            }
        }

        for s in self.services.enumerate()? {
            if !self.classifier.service_eligible(&s, profile) {
                continue;
            }
            match self.services.pause_or_stop(&s.name) {
                Ok(action) => {
                    session.changed_services.push(ServiceRecord {
                        name: s.name,
                        original_state: s.state,
                        action,
                    });
                    self.store.save(&session)?;
                }
                Err(e) => skipped.push(format!("service {}: {e}", s.name)),
            }
        }

        let report = BoostReport {
            session_id: session.id,
            suspended_processes: session.suspended_processes.len(),
            changed_services: session.changed_services.len(),
            skipped,
        };
        self.active = Some(session);
        Ok(report)
    }

    /// Restore everything recorded in the active session, then clear it from
    /// disk. Best-effort: a failure on one item does not stop the rest.
    pub fn end_boost(&mut self) -> Result<()> {
        let session = self.active.take().ok_or(BoosterError::NoActiveSession)?;

        for rec in session.changed_services.iter().rev() {
            let _ = self
                .services
                .restore(&rec.name, &rec.original_state, &rec.action);
        }
        for rec in session.suspended_processes.iter().rev() {
            // Verify the PID was not recycled before resuming.
            if self.processes.matches(rec.pid, rec.start_time) {
                let _ = self.processes.resume(rec.pid);
            }
        }
        self.store.clear()?;
        Ok(())
    }

    /// Refresh the heartbeat deadline; the service's watchdog auto-restores if
    /// this stops being called (UI died).
    pub fn heartbeat(&mut self, ttl: std::time::Duration) {
        if let Some(session) = self.active.as_mut() {
            session.bump_heartbeat(ttl);
        }
    }

    /// Whether the watchdog deadline has passed.
    pub fn heartbeat_expired(&self) -> bool {
        self.active
            .as_ref()
            .map(|s| s.heartbeat_expired())
            .unwrap_or(false)
    }
}

/// A process or service the UI can present, with whether it may be suspended.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Candidate {
    /// PID (as string) for processes, service name for services.
    pub key: String,
    pub name: String,
    pub eligible: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanResult {
    pub processes: Vec<Candidate>,
    pub services: Vec<Candidate>,
}
