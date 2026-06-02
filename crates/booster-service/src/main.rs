//! SystemBooster privileged host.
//!
//! On Windows this runs as a `LocalSystem` service: it acquires
//! `SeDebugPrivilege`, recovers any orphaned boost on startup, then serves the
//! UI over the named pipe while a watchdog auto-restores if heartbeats stop.
//!
//! On other platforms (dev containers, CI) it runs as a console host with the
//! in-memory mock backends so the wiring can be exercised end to end.

use std::sync::{Arc, Mutex};

use booster_core::classify::Classifier;
use booster_core::session::SessionStore;
use booster_core::BoosterEngine;

/// Shared, lock-guarded engine handle used by the IPC server and watchdog.
type SharedEngine = Arc<Mutex<BoosterEngine>>;

/// How long a boost survives without a heartbeat before the watchdog restores.
const HEARTBEAT_TTL: std::time::Duration = std::time::Duration::from_secs(15);

fn build_engine() -> BoosterEngine {
    let classifier = Classifier::default();
    let store = SessionStore::default_location();
    let (procs, svcs) = backend::controllers();
    BoosterEngine::new(procs, svcs, classifier, store)
}

fn main() {
    let mut engine = build_engine();

    // Safety net first: restore anything a previous run left suspended.
    match engine.recover() {
        Ok(true) => eprintln!("[booster] recovered and restored an orphaned boost session"),
        Ok(false) => {}
        Err(e) => eprintln!("[booster] recovery error: {e}"),
    }

    let engine: SharedEngine = Arc::new(Mutex::new(engine));
    backend::run(engine);
}

// --------------------------------------------------------------------------
// Windows: real backends, service host, named-pipe server, watchdog.
// --------------------------------------------------------------------------
#[cfg(windows)]
mod backend {
    use super::*;
    use booster_core::process::Win32ProcessController;
    use booster_core::service::Win32ServiceController;
    use booster_core::snapshot;
    use booster_ipc::transport::{PipeServer, PipeStream};
    use booster_ipc::{Request, Response, Status};

    pub fn controllers() -> (
        Arc<dyn booster_core::process::ProcessController>,
        Arc<dyn booster_core::service::ServiceController>,
    ) {
        (
            Arc::new(Win32ProcessController::new()),
            Arc::new(Win32ServiceController::new()),
        )
    }

    pub fn run(engine: SharedEngine) {
        // NOTE: a production build registers with the SCM via
        // `windows_service::service_dispatcher`. For the scaffold we run the
        // same serving loop directly so it is exercisable from a console too.
        acquire_se_debug();
        spawn_watchdog(engine.clone());
        serve(engine);
    }

    fn acquire_se_debug() {
        use windows::Win32::Foundation::{HANDLE, LUID};
        use windows::Win32::Security::*;
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        unsafe {
            let mut token = HANDLE::default();
            if OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &mut token,
            )
            .is_err()
            {
                return;
            }
            let mut luid = LUID::default();
            let name: Vec<u16> = "SeDebugPrivilege\0".encode_utf16().collect();
            if LookupPrivilegeValueW(
                windows::core::PCWSTR::null(),
                windows::core::PCWSTR(name.as_ptr()),
                &mut luid,
            )
            .is_ok()
            {
                let tp = TOKEN_PRIVILEGES {
                    PrivilegeCount: 1,
                    Privileges: [LUID_AND_ATTRIBUTES {
                        Luid: luid,
                        Attributes: SE_PRIVILEGE_ENABLED,
                    }],
                };
                let _ = AdjustTokenPrivileges(token, false, Some(&tp), 0, None, None);
            }
        }
    }

    fn spawn_watchdog(engine: SharedEngine) {
        std::thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_secs(2));
            let mut eng = engine.lock().unwrap();
            if eng.is_boosted() && eng.heartbeat_expired() {
                eprintln!("[booster] heartbeat expired — auto-restoring");
                let _ = eng.end_boost();
            }
        });
    }

    fn serve(engine: SharedEngine) {
        loop {
            match PipeServer::accept() {
                Ok(stream) => {
                    let engine = engine.clone();
                    std::thread::spawn(move || handle_client(stream, engine));
                }
                Err(e) => {
                    eprintln!("[booster] pipe accept failed: {e}");
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
            }
        }
    }

    fn handle_client(mut stream: PipeStream, engine: SharedEngine) {
        while let Ok(req) = stream.read_message::<Request>() {
            let resp = dispatch(req, &engine);
            if stream.write_message(&resp).is_err() {
                break;
            }
        }
    }

    fn dispatch(req: Request, engine: &SharedEngine) -> Response {
        let mut eng = engine.lock().unwrap();
        match req {
            Request::Scan { profile } => match eng.scan(&profile) {
                Ok(scan) => Response::Scan(scan),
                Err(e) => Response::Error {
                    message: e.to_string(),
                },
            },
            Request::StartBoost { profile } => {
                eng.heartbeat(HEARTBEAT_TTL);
                match eng.start_boost(&profile) {
                    Ok(report) => Response::Boosted(report),
                    Err(e) => Response::Error {
                        message: e.to_string(),
                    },
                }
            }
            Request::EndBoost => match eng.end_boost() {
                Ok(()) => Response::Ended,
                Err(e) => Response::Error {
                    message: e.to_string(),
                },
            },
            Request::Heartbeat => {
                eng.heartbeat(HEARTBEAT_TTL);
                Response::Ack
            }
            Request::GetStatus => Response::Status(Status {
                boosted: eng.is_boosted(),
                active_profile: None,
                metrics: snapshot::sample(),
            }),
        }
    }
}

// --------------------------------------------------------------------------
// Non-Windows: mock backends + a tiny console host for local verification.
// --------------------------------------------------------------------------
#[cfg(not(windows))]
mod backend {
    use super::*;
    use booster_core::classify::Profile;
    use booster_core::process::{MockProcessController, ProcessInfo};
    use booster_core::service::{MockServiceController, ServiceInfo, ServiceState};

    pub fn controllers() -> (
        Arc<dyn booster_core::process::ProcessController>,
        Arc<dyn booster_core::service::ServiceController>,
    ) {
        let procs = MockProcessController::with_processes(vec![
            ProcessInfo {
                pid: 4,
                name: "System".into(),
                image_path: None,
                start_time: 1,
            },
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
        ]);
        let svcs = MockServiceController::with_services(vec![
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
        ]);
        (Arc::new(procs), Arc::new(svcs))
    }

    pub fn run(engine: SharedEngine) {
        // Console smoke run: scan, boost, restore — proves the wiring works
        // without Windows. The real service serves the named pipe instead.
        let mut eng = engine.lock().unwrap();
        let profile = Profile::gaming();
        let scan = eng.scan(&profile).expect("scan");
        println!(
            "[console] scan: {} processes ({} eligible), {} services ({} eligible)",
            scan.processes.len(),
            scan.processes.iter().filter(|c| c.eligible).count(),
            scan.services.len(),
            scan.services.iter().filter(|c| c.eligible).count(),
        );
        let report = eng.start_boost(&profile).expect("boost");
        println!(
            "[console] boosted: suspended {} processes, changed {} services",
            report.suspended_processes, report.changed_services
        );
        eng.end_boost().expect("restore");
        println!("[console] restored — system back to normal");
        let _ = HEARTBEAT_TTL; // used by the Windows watchdog path
    }
}
