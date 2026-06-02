//! SystemBooster desktop UI backend (Tauri).
//!
//! The UI runs unprivileged. Every action is forwarded to the privileged
//! `booster-service` over the named pipe; this file is just a thin proxy that
//! exposes Tauri commands to the web front-end and translates them into
//! [`booster_ipc::Request`] / [`booster_ipc::Response`] round-trips.

#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use booster_core::classify::Profile;
use booster_ipc::{Request, Response};

/// Send one request to the service and await its response.
///
/// A new pipe connection is opened per call for simplicity; the service hosts
/// unlimited instances. On non-Windows dev machines (where the pipe does not
/// exist) this returns a mocked response so the UI can still be previewed.
fn call(req: Request) -> Result<Response, String> {
    #[cfg(windows)]
    {
        use booster_ipc::transport;
        let mut stream = transport::connect().map_err(|e| e.to_string())?;
        stream.write_message(&req).map_err(|e| e.to_string())?;
        stream.read_message::<Response>().map_err(|e| e.to_string())
    }
    #[cfg(not(windows))]
    {
        Ok(mock::respond(req))
    }
}

fn profile_from_name(name: &str) -> Profile {
    match name {
        "Work" => Profile::work(),
        _ => Profile::gaming(),
    }
}

#[tauri::command]
fn scan(profile: String) -> Result<Response, String> {
    call(Request::Scan {
        profile: profile_from_name(&profile),
    })
}

#[tauri::command]
fn start_boost(profile: String) -> Result<Response, String> {
    call(Request::StartBoost {
        profile: profile_from_name(&profile),
    })
}

#[tauri::command]
fn end_boost() -> Result<Response, String> {
    call(Request::EndBoost)
}

#[tauri::command]
fn get_status() -> Result<Response, String> {
    call(Request::GetStatus)
}

#[tauri::command]
fn heartbeat() -> Result<Response, String> {
    call(Request::Heartbeat)
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            scan,
            start_boost,
            end_boost,
            get_status,
            heartbeat
        ])
        .run(tauri::generate_context!())
        .expect("error while running SystemBooster");
}

#[cfg(not(windows))]
mod mock {
    //! Lets the UI be previewed on a dev machine without the Windows service.
    use super::*;
    use booster_core::snapshot::Metrics;
    use booster_core::{BoostReport, Candidate, ScanResult};
    use booster_ipc::Status;

    pub fn respond(req: Request) -> Response {
        match req {
            Request::Scan { .. } => Response::Scan(ScanResult {
                processes: vec![
                    Candidate { key: "1500".into(), name: "Spotify.exe".into(), eligible: true },
                    Candidate { key: "800".into(), name: "lsass.exe".into(), eligible: false },
                ],
                services: vec![Candidate {
                    key: "WSearch".into(),
                    name: "Windows Search".into(),
                    eligible: true,
                }],
            }),
            Request::StartBoost { .. } => Response::Boosted(BoostReport {
                session_id: uuid_zero(),
                suspended_processes: 23,
                changed_services: 11,
                skipped: vec![],
            }),
            Request::EndBoost => Response::Ended,
            Request::Heartbeat => Response::Ack,
            Request::GetStatus => Response::Status(Status {
                boosted: false,
                active_profile: None,
                metrics: Metrics {
                    memory_load_percent: 62,
                    total_physical_bytes: 16 * 1024 * 1024 * 1024,
                    available_physical_bytes: 6 * 1024 * 1024 * 1024,
                },
            }),
        }
    }

    fn uuid_zero() -> uuid::Uuid {
        uuid::Uuid::nil()
    }
}
