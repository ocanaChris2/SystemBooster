//! The restore session — SystemBooster's safety backbone. Everything we change
//! is written here (write-ahead) and persisted, so a crash/reboot mid-boost is
//! still fully recoverable.

use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use crate::service::{ServiceAction, ServiceState};
use crate::Result;

/// One suspended process, with enough info to detect PID recycling on resume.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProcessRecord {
    pub pid: u32,
    pub name: String,
    pub image_path: Option<String>,
    pub start_time: u64,
}

/// One service we paused/stopped, plus its original state for restore.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ServiceRecord {
    pub name: String,
    pub original_state: ServiceState,
    pub action: ServiceAction,
}

/// The full record of an applied boost.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RestoreSession {
    pub id: uuid::Uuid,
    pub started_at: SystemTime,
    pub profile: String,
    pub suspended_processes: Vec<ProcessRecord>,
    pub changed_services: Vec<ServiceRecord>,
    /// After this instant with no heartbeat, the watchdog auto-restores.
    pub heartbeat_deadline: SystemTime,
}

impl RestoreSession {
    pub fn new(profile: String) -> Self {
        let now = SystemTime::now();
        Self {
            id: uuid::Uuid::new_v4(),
            started_at: now,
            profile,
            suspended_processes: Vec::new(),
            changed_services: Vec::new(),
            heartbeat_deadline: now + Duration::from_secs(30),
        }
    }

    pub fn bump_heartbeat(&mut self, ttl: Duration) {
        self.heartbeat_deadline = SystemTime::now() + ttl;
    }

    pub fn heartbeat_expired(&self) -> bool {
        SystemTime::now() > self.heartbeat_deadline
    }
}

/// Persists the active session to a JSON file under ProgramData. The path is
/// injectable so tests can use a temp dir.
pub struct SessionStore {
    path: PathBuf,
}

impl SessionStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Default production location: `%ProgramData%\SystemBooster\session.json`.
    /// Falls back to the system temp dir if the env var is missing.
    pub fn default_location() -> Self {
        let base = std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        Self::new(base.join("SystemBooster").join("session.json"))
    }

    pub fn save(&self, session: &RestoreSession) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_vec_pretty(session)?;
        // Write to a temp file then rename for atomicity.
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, &json)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    pub fn load(&self) -> Result<Option<RestoreSession>> {
        match std::fs::read(&self.path) {
            Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn clear(&self) -> Result<()> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}
