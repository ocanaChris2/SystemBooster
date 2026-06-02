//! End-to-end engine tests using the in-memory mock backends. These exercise
//! the classification, boost/restore, write-ahead persistence and recovery
//! paths without requiring Windows or admin privileges.

use std::sync::Arc;

use booster_core::classify::{Classifier, Profile};
use booster_core::process::{MockProcessController, ProcessInfo};
use booster_core::service::{MockServiceController, ServiceInfo, ServiceState};
use booster_core::session::SessionStore;
use booster_core::BoosterEngine;

fn sample_processes() -> Vec<ProcessInfo> {
    vec![
        // Critical — must never be suspended.
        ProcessInfo {
            pid: 4,
            name: "System".into(),
            image_path: None,
            start_time: 1,
        },
        ProcessInfo {
            pid: 800,
            name: "lsass.exe".into(),
            image_path: None,
            start_time: 2,
        },
        ProcessInfo {
            pid: 900,
            name: "csrss.exe".into(),
            image_path: None,
            start_time: 3,
        },
        // Eligible user-space apps.
        ProcessInfo {
            pid: 1500,
            name: "Spotify.exe".into(),
            image_path: None,
            start_time: 4,
        },
        ProcessInfo {
            pid: 1600,
            name: "Slack.exe".into(),
            image_path: None,
            start_time: 5,
        },
    ]
}

fn sample_services() -> Vec<ServiceInfo> {
    vec![
        ServiceInfo {
            name: "RpcSs".into(),
            display_name: None,
            state: ServiceState::Running,
            accepts_pause: false,
        },
        ServiceInfo {
            name: "WSearch".into(),
            display_name: Some("Windows Search".into()),
            state: ServiceState::Running,
            accepts_pause: true,
        },
        ServiceInfo {
            name: "Spooler".into(),
            display_name: Some("Print Spooler".into()),
            state: ServiceState::Running,
            accepts_pause: false,
        },
        ServiceInfo {
            name: "AlreadyStopped".into(),
            display_name: None,
            state: ServiceState::Stopped,
            accepts_pause: false,
        },
    ]
}

fn make_engine(
    dir: &std::path::Path,
) -> (
    BoosterEngine,
    Arc<MockProcessController>,
    Arc<MockServiceController>,
) {
    let procs = Arc::new(MockProcessController::with_processes(sample_processes()));
    let svcs = Arc::new(MockServiceController::with_services(sample_services()));
    let store = SessionStore::new(dir.join("session.json"));
    let engine = BoosterEngine::new(procs.clone(), svcs.clone(), Classifier::default(), store);
    (engine, procs, svcs)
}

#[test]
fn scan_locks_critical_items() {
    let dir = tempdir();
    let (engine, _, _) = make_engine(&dir);
    let scan = engine.scan(&Profile::gaming()).unwrap();

    let lsass = scan
        .processes
        .iter()
        .find(|c| c.name == "lsass.exe")
        .unwrap();
    assert!(!lsass.eligible, "lsass must be locked");
    let spotify = scan
        .processes
        .iter()
        .find(|c| c.name == "Spotify.exe")
        .unwrap();
    assert!(spotify.eligible, "user app should be eligible");

    let rpcss = scan.services.iter().find(|c| c.key == "RpcSs").unwrap();
    assert!(!rpcss.eligible, "RpcSs must be locked");
}

#[test]
fn boost_then_restore_round_trips() {
    let dir = tempdir();
    let (mut engine, procs, svcs) = make_engine(&dir);

    let report = engine.start_boost(&Profile::gaming()).unwrap();
    assert_eq!(report.suspended_processes, 2, "Spotify + Slack");
    assert_eq!(
        report.changed_services, 2,
        "WSearch + Spooler (RpcSs critical, one stopped)"
    );

    // Critical items untouched, eligible ones suspended.
    assert!(procs.is_suspended(1500));
    assert!(procs.is_suspended(1600));
    assert!(!procs.is_suspended(800), "lsass must not be suspended");
    assert_eq!(svcs.state_of("RpcSs"), Some(ServiceState::Running));
    assert_eq!(svcs.state_of("WSearch"), Some(ServiceState::Paused));
    assert_eq!(svcs.state_of("Spooler"), Some(ServiceState::Stopped));
    assert!(engine.is_boosted());

    engine.end_boost().unwrap();
    assert!(!procs.is_suspended(1500));
    assert_eq!(svcs.state_of("WSearch"), Some(ServiceState::Running));
    assert_eq!(svcs.state_of("Spooler"), Some(ServiceState::Running));
    assert!(!engine.is_boosted());
}

#[test]
fn recover_restores_orphaned_session() {
    let dir = tempdir();

    // First engine applies a boost, then "crashes" (dropped without end_boost).
    let store_path = dir.join("session.json");
    {
        let procs = Arc::new(MockProcessController::with_processes(sample_processes()));
        let svcs = Arc::new(MockServiceController::with_services(sample_services()));
        let store = SessionStore::new(store_path.clone());
        let mut engine = BoosterEngine::new(procs, svcs, Classifier::default(), store);
        engine.start_boost(&Profile::gaming()).unwrap();
        std::mem::forget(engine); // simulate crash: no Drop-based restore
    }
    assert!(store_path.exists(), "session should be persisted on disk");

    // A fresh engine recovers on startup.
    let (mut engine, _procs, svcs) = make_engine(&dir);
    let recovered = engine.recover().unwrap();
    assert!(recovered);
    assert!(!store_path.exists(), "session cleared after recovery");
    assert_eq!(svcs.state_of("WSearch"), Some(ServiceState::Running));
}

#[test]
fn work_profile_leaves_services_alone() {
    let dir = tempdir();
    let (mut engine, _, svcs) = make_engine(&dir);
    let report = engine.start_boost(&Profile::work()).unwrap();
    assert_eq!(report.changed_services, 0);
    assert_eq!(svcs.state_of("WSearch"), Some(ServiceState::Running));
    engine.end_boost().unwrap();
}

/// Minimal unique temp dir without pulling in an external crate.
fn tempdir() -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    let nonce = format!(
        "systembooster-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    p.push(nonce);
    std::fs::create_dir_all(&p).unwrap();
    p
}
