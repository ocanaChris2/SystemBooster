//! Service enumeration and pause/stop/restore, behind [`ServiceController`].
//! The Win32 backend uses the Service Control Manager and is Windows-only.

use crate::Result;

/// Coarse run state we care about for restore purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ServiceState {
    Running,
    Paused,
    Stopped,
    Other,
}

/// What we did to a service, so we know how to undo it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ServiceAction {
    Paused,
    Stopped,
}

/// A snapshot of one service.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub display_name: Option<String>,
    pub state: ServiceState,
    /// Whether the service accepts PAUSE/CONTINUE (vs. only STOP).
    pub accepts_pause: bool,
}

/// Abstraction over the Service Control Manager.
pub trait ServiceController: Send + Sync {
    fn enumerate(&self) -> Result<Vec<ServiceInfo>>;
    /// Pause the service if it supports it, otherwise stop it. Returns which.
    fn pause_or_stop(&self, name: &str) -> Result<ServiceAction>;
    /// Undo a previous pause/stop, returning the service to `original`.
    fn restore(&self, name: &str, original: &ServiceState, action: &ServiceAction) -> Result<()>;
}

/// In-memory backend for tests / non-Windows host.
#[derive(Default)]
pub struct MockServiceController {
    inner: std::sync::Mutex<Vec<ServiceInfo>>,
}

impl MockServiceController {
    pub fn with_services(services: Vec<ServiceInfo>) -> Self {
        Self {
            inner: std::sync::Mutex::new(services),
        }
    }

    pub fn state_of(&self, name: &str) -> Option<ServiceState> {
        self.inner
            .lock()
            .unwrap()
            .iter()
            .find(|s| s.name == name)
            .map(|s| s.state)
    }
}

impl ServiceController for MockServiceController {
    fn enumerate(&self) -> Result<Vec<ServiceInfo>> {
        Ok(self.inner.lock().unwrap().clone())
    }

    fn pause_or_stop(&self, name: &str) -> Result<ServiceAction> {
        let mut guard = self.inner.lock().unwrap();
        let svc = guard
            .iter_mut()
            .find(|s| s.name == name)
            .ok_or_else(|| crate::BoosterError::Os(format!("no such service {name}")))?;
        if svc.accepts_pause {
            svc.state = ServiceState::Paused;
            Ok(ServiceAction::Paused)
        } else {
            svc.state = ServiceState::Stopped;
            Ok(ServiceAction::Stopped)
        }
    }

    fn restore(&self, name: &str, original: &ServiceState, _action: &ServiceAction) -> Result<()> {
        let mut guard = self.inner.lock().unwrap();
        if let Some(svc) = guard.iter_mut().find(|s| s.name == name) {
            svc.state = *original;
        }
        Ok(())
    }
}

#[cfg(windows)]
pub use win32::Win32ServiceController;

#[cfg(windows)]
mod win32 {
    use super::*;
    use crate::BoosterError;
    use windows::core::PWSTR;
    use windows::Win32::Foundation::ERROR_MORE_DATA;
    use windows::Win32::System::Services::*;

    pub struct Win32ServiceController;

    impl Win32ServiceController {
        pub fn new() -> Self {
            Self
        }
    }

    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn map_state(current: SERVICE_STATUS_CURRENT_STATE) -> ServiceState {
        match current {
            SERVICE_RUNNING => ServiceState::Running,
            SERVICE_PAUSED => ServiceState::Paused,
            SERVICE_STOPPED => ServiceState::Stopped,
            _ => ServiceState::Other,
        }
    }

    impl ServiceController for Win32ServiceController {
        fn enumerate(&self) -> Result<Vec<ServiceInfo>> {
            unsafe {
                let scm = OpenSCManagerW(None, None, SC_MANAGER_ENUMERATE_SERVICE)
                    .map_err(|e| BoosterError::Os(format!("OpenSCManager: {e}")))?;

                let mut bytes_needed = 0u32;
                let mut count = 0u32;
                // First call sizes the buffer.
                let _ = EnumServicesStatusExW(
                    scm,
                    SC_ENUM_PROCESS_INFO,
                    SERVICE_WIN32,
                    SERVICE_STATE_ALL,
                    None,
                    &mut bytes_needed,
                    &mut count,
                    None,
                    None,
                );
                let mut buf = vec![0u8; bytes_needed as usize];
                let mut resume = 0u32;
                EnumServicesStatusExW(
                    scm,
                    SC_ENUM_PROCESS_INFO,
                    SERVICE_WIN32,
                    SERVICE_STATE_ALL,
                    Some(&mut buf),
                    &mut bytes_needed,
                    &mut count,
                    Some(&mut resume),
                    None,
                )
                .map_err(|e| BoosterError::Os(format!("EnumServicesStatusEx: {e}")))?;

                let entries = std::slice::from_raw_parts(
                    buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW,
                    count as usize,
                );
                let mut out = Vec::with_capacity(count as usize);
                for e in entries {
                    let name = e.lpServiceName.to_string().unwrap_or_default();
                    let display = e.lpDisplayName.to_string().ok();
                    let controls = e.ServiceStatusProcess.dwControlsAccepted;
                    out.push(ServiceInfo {
                        name,
                        display_name: display,
                        state: map_state(e.ServiceStatusProcess.dwCurrentState),
                        accepts_pause: controls & SERVICE_ACCEPT_PAUSE_CONTINUE != 0,
                    });
                }
                let _ = CloseServiceHandle(scm);
                let _ = ERROR_MORE_DATA; // documented possible status; handled by sizing call
                Ok(out)
            }
        }

        fn pause_or_stop(&self, name: &str) -> Result<ServiceAction> {
            unsafe {
                let scm = OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
                    .map_err(|e| BoosterError::Os(format!("OpenSCManager: {e}")))?;
                let wide = to_wide(name);
                let svc = OpenServiceW(
                    scm,
                    PWSTR(wide.as_ptr() as *mut u16),
                    SERVICE_PAUSE_CONTINUE | SERVICE_STOP | SERVICE_QUERY_STATUS,
                )
                .map_err(|e| BoosterError::Os(format!("OpenService({name}): {e}")))?;

                let mut status = SERVICE_STATUS::default();
                let accepts_pause = {
                    QueryServiceStatus(svc, &mut status).ok();
                    status.dwControlsAccepted & SERVICE_ACCEPT_PAUSE_CONTINUE != 0
                };

                let action = if accepts_pause {
                    ControlService(svc, SERVICE_CONTROL_PAUSE, &mut status)
                        .map_err(|e| BoosterError::Os(format!("pause {name}: {e}")))?;
                    ServiceAction::Paused
                } else {
                    ControlService(svc, SERVICE_CONTROL_STOP, &mut status)
                        .map_err(|e| BoosterError::Os(format!("stop {name}: {e}")))?;
                    ServiceAction::Stopped
                };
                let _ = CloseServiceHandle(svc);
                let _ = CloseServiceHandle(scm);
                Ok(action)
            }
        }

        fn restore(
            &self,
            name: &str,
            original: &ServiceState,
            action: &ServiceAction,
        ) -> Result<()> {
            // Only undo if the original state was Running; if it was already
            // paused/stopped we leave the system as the user had it.
            if *original != ServiceState::Running {
                return Ok(());
            }
            unsafe {
                let scm = OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
                    .map_err(|e| BoosterError::Os(format!("OpenSCManager: {e}")))?;
                let wide = to_wide(name);
                let svc = OpenServiceW(
                    scm,
                    PWSTR(wide.as_ptr() as *mut u16),
                    SERVICE_PAUSE_CONTINUE | SERVICE_START,
                )
                .map_err(|e| BoosterError::Os(format!("OpenService({name}): {e}")))?;

                match action {
                    ServiceAction::Paused => {
                        let mut status = SERVICE_STATUS::default();
                        let _ = ControlService(svc, SERVICE_CONTROL_CONTINUE, &mut status);
                    }
                    ServiceAction::Stopped => {
                        let _ = StartServiceW(svc, None);
                    }
                }
                let _ = CloseServiceHandle(svc);
                let _ = CloseServiceHandle(scm);
            }
            Ok(())
        }
    }
}
