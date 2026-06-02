//! Process enumeration and suspend/resume, behind the [`ProcessController`]
//! trait. The Win32 backend lives in [`win32`] and is compiled only on Windows.

use crate::Result;

/// A snapshot of one running process.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub image_path: Option<String>,
    /// Process creation time (FILETIME ticks). Used to detect PID recycling.
    pub start_time: u64,
}

/// Abstraction over the OS so the engine can be tested without privileges.
pub trait ProcessController: Send + Sync {
    fn enumerate(&self) -> Result<Vec<ProcessInfo>>;
    fn suspend(&self, pid: u32) -> Result<()>;
    fn resume(&self, pid: u32) -> Result<()>;
    /// True if a process with `pid` currently exists and was created at
    /// `start_time` — i.e. the PID was not recycled into a different process.
    fn matches(&self, pid: u32, start_time: u64) -> bool;
}

/// In-memory backend used by unit tests and by the non-Windows console host.
#[derive(Default)]
pub struct MockProcessController {
    inner: std::sync::Mutex<MockState>,
}

#[derive(Default)]
struct MockState {
    procs: Vec<ProcessInfo>,
    suspended: std::collections::HashSet<u32>,
}

impl MockProcessController {
    pub fn with_processes(procs: Vec<ProcessInfo>) -> Self {
        Self {
            inner: std::sync::Mutex::new(MockState {
                procs,
                suspended: Default::default(),
            }),
        }
    }

    /// Test helper: is the given pid currently suspended?
    pub fn is_suspended(&self, pid: u32) -> bool {
        self.inner.lock().unwrap().suspended.contains(&pid)
    }
}

impl ProcessController for MockProcessController {
    fn enumerate(&self) -> Result<Vec<ProcessInfo>> {
        Ok(self.inner.lock().unwrap().procs.clone())
    }

    fn suspend(&self, pid: u32) -> Result<()> {
        self.inner.lock().unwrap().suspended.insert(pid);
        Ok(())
    }

    fn resume(&self, pid: u32) -> Result<()> {
        self.inner.lock().unwrap().suspended.remove(&pid);
        Ok(())
    }

    fn matches(&self, pid: u32, start_time: u64) -> bool {
        self.inner
            .lock()
            .unwrap()
            .procs
            .iter()
            .any(|p| p.pid == pid && p.start_time == start_time)
    }
}

#[cfg(windows)]
pub use win32::Win32ProcessController;

#[cfg(windows)]
mod win32 {
    //! Real Win32 backend.
    //!
    //! Enumeration uses Toolhelp snapshots. Suspension prefers the undocumented
    //! `NtSuspendProcess`/`NtResumeProcess` (resolved from ntdll at runtime),
    //! falling back to enumerating and suspending each thread.

    use super::*;
    use crate::BoosterError;
    use std::ffi::c_void;
    use windows::core::PCSTR;
    use windows::Win32::Foundation::{CloseHandle, HANDLE, NTSTATUS};
    use windows::Win32::System::Diagnostics::ToolHelp::*;
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    use windows::Win32::System::Threading::*;

    type NtProcFn = unsafe extern "system" fn(HANDLE) -> NTSTATUS;

    pub struct Win32ProcessController {
        nt_suspend: Option<NtProcFn>,
        nt_resume: Option<NtProcFn>,
    }

    impl Win32ProcessController {
        pub fn new() -> Self {
            let (nt_suspend, nt_resume) = unsafe { resolve_ntdll() };
            Self {
                nt_suspend,
                nt_resume,
            }
        }

        fn open(&self, pid: u32, access: PROCESS_ACCESS_RIGHTS) -> Result<HANDLE> {
            unsafe { OpenProcess(access, false, pid) }
                .map_err(|e| BoosterError::Os(format!("OpenProcess({pid}): {e}")))
        }
    }

    unsafe fn resolve_ntdll() -> (Option<NtProcFn>, Option<NtProcFn>) {
        let Ok(ntdll) = GetModuleHandleA(PCSTR(b"ntdll.dll\0".as_ptr())) else {
            return (None, None);
        };
        let suspend = GetProcAddress(ntdll, PCSTR(b"NtSuspendProcess\0".as_ptr()))
            .map(|f| std::mem::transmute::<_, NtProcFn>(f));
        let resume = GetProcAddress(ntdll, PCSTR(b"NtResumeProcess\0".as_ptr()))
            .map(|f| std::mem::transmute::<_, NtProcFn>(f));
        (suspend, resume)
    }

    impl ProcessController for Win32ProcessController {
        fn enumerate(&self) -> Result<Vec<ProcessInfo>> {
            let mut out = Vec::new();
            unsafe {
                let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
                    .map_err(|e| BoosterError::Os(format!("snapshot: {e}")))?;
                let mut entry = PROCESSENTRY32W {
                    dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                    ..Default::default()
                };
                if Process32FirstW(snap, &mut entry).is_ok() {
                    loop {
                        let name = String::from_utf16_lossy(
                            &entry.szExeFile
                                [..entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(0)],
                        );
                        out.push(ProcessInfo {
                            pid: entry.th32ProcessID,
                            name,
                            image_path: None,
                            start_time: process_start_time(entry.th32ProcessID).unwrap_or(0),
                        });
                        if Process32NextW(snap, &mut entry).is_err() {
                            break;
                        }
                    }
                }
                let _ = CloseHandle(snap);
            }
            Ok(out)
        }

        fn suspend(&self, pid: u32) -> Result<()> {
            let handle = self.open(pid, PROCESS_SUSPEND_RESUME)?;
            let res = if let Some(f) = self.nt_suspend {
                unsafe { f(handle) }
                    .ok()
                    .map_err(|e| BoosterError::Os(format!("NtSuspendProcess({pid}): {e}")))
            } else {
                suspend_threads(pid, true)
            };
            unsafe {
                let _ = CloseHandle(handle);
            }
            res
        }

        fn resume(&self, pid: u32) -> Result<()> {
            let handle = self.open(pid, PROCESS_SUSPEND_RESUME)?;
            let res = if let Some(f) = self.nt_resume {
                unsafe { f(handle) }
                    .ok()
                    .map_err(|e| BoosterError::Os(format!("NtResumeProcess({pid}): {e}")))
            } else {
                suspend_threads(pid, false)
            };
            unsafe {
                let _ = CloseHandle(handle);
            }
            res
        }

        fn matches(&self, pid: u32, start_time: u64) -> bool {
            process_start_time(pid)
                .map(|t| t == start_time)
                .unwrap_or(false)
        }
    }

    /// Fallback path: suspend or resume every thread of a process.
    fn suspend_threads(pid: u32, suspend: bool) -> Result<()> {
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
                .map_err(|e| BoosterError::Os(format!("thread snapshot: {e}")))?;
            let mut entry = THREADENTRY32 {
                dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
                ..Default::default()
            };
            if Thread32First(snap, &mut entry).is_ok() {
                loop {
                    if entry.th32OwnerProcessID == pid {
                        if let Ok(th) = OpenThread(THREAD_SUSPEND_RESUME, false, entry.th32ThreadID)
                        {
                            if suspend {
                                SuspendThread(th);
                            } else {
                                ResumeThread(th);
                            }
                            let _ = CloseHandle(th);
                        }
                    }
                    if Thread32Next(snap, &mut entry).is_err() {
                        break;
                    }
                }
            }
            let _ = CloseHandle(snap);
        }
        Ok(())
    }

    /// Read the process creation time (low/high FILETIME packed into u64).
    fn process_start_time(pid: u32) -> Option<u64> {
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
            let mut creation = Default::default();
            let mut exit = Default::default();
            let mut kernel = Default::default();
            let mut user = Default::default();
            let ok =
                GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user).is_ok();
            let _ = CloseHandle(handle);
            if ok {
                Some(((creation.dwHighDateTime as u64) << 32) | creation.dwLowDateTime as u64)
            } else {
                None
            }
        }
    }

    // Silence unused import warning for c_void on some toolchains.
    const _: Option<*const c_void> = None;
}
