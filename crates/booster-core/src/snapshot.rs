//! System metrics sampling for the UI's before/during boost panel.
//! The Win32 backend reads global memory + CPU; other platforms return zeros.

/// A point-in-time sample of system load.
#[derive(Debug, Clone, Copy, Default, serde::Serialize, serde::Deserialize)]
pub struct Metrics {
    /// Percent of physical RAM in use (0-100).
    pub memory_load_percent: u32,
    pub total_physical_bytes: u64,
    pub available_physical_bytes: u64,
}

/// Sample current system metrics.
pub fn sample() -> Metrics {
    sample_impl()
}

#[cfg(windows)]
fn sample_impl() -> Metrics {
    use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
    let mut status = MEMORYSTATUSEX {
        dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
        ..Default::default()
    };
    unsafe {
        if GlobalMemoryStatusEx(&mut status).is_ok() {
            return Metrics {
                memory_load_percent: status.dwMemoryLoad,
                total_physical_bytes: status.ullTotalPhys,
                available_physical_bytes: status.ullAvailPhys,
            };
        }
    }
    Metrics::default()
}

#[cfg(not(windows))]
fn sample_impl() -> Metrics {
    Metrics::default()
}
