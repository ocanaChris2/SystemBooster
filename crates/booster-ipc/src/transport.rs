//! Windows named-pipe transport. The service hosts the pipe with a security
//! descriptor that grants access to the interactive user and administrators
//! only; the UI back-end connects as a client.
//!
//! Framing is the length-prefixed JSON from the parent module ([`crate::encode`]
//! / [`crate::decode`]).

use std::io::{self, Read, Write};

use serde::{Deserialize, Serialize};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_FLAG_OVERLAPPED, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    FILE_SHARE_NONE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
};
use windows::Win32::System::Pipes::*;

use crate::PIPE_NAME;

/// DACL: grant Administrators (BA) and the interactive logon group (IU) generic
/// all; deny everyone else by omission. Owner = SYSTEM (SY).
const PIPE_SDDL: &str = "O:SYG:SYD:(A;;GA;;;BA)(A;;GA;;;IU)";

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Build a SECURITY_ATTRIBUTES from [`PIPE_SDDL`]. The returned descriptor must
/// outlive the attributes; callers keep both on the stack for the create call.
unsafe fn pipe_security() -> io::Result<(SECURITY_ATTRIBUTES, PSECURITY_DESCRIPTOR)> {
    let mut psd = PSECURITY_DESCRIPTOR::default();
    let sddl = to_wide(PIPE_SDDL);
    ConvertStringSecurityDescriptorToSecurityDescriptorW(
        PCWSTR(sddl.as_ptr()),
        SDDL_REVISION_1,
        &mut psd,
        None,
    )
    .map_err(io::Error::other)?;
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: psd.0,
        bInheritHandle: false.into(),
    };
    Ok((sa, psd))
}

/// A connected pipe endpoint (either a server instance or a client).
pub struct PipeStream {
    handle: HANDLE,
}

// SAFETY: `PipeStream` uniquely owns its `HANDLE` (it is never cloned or
// aliased, and is closed exactly once on `Drop`). The service hands each
// accepted stream to a single worker thread, so the handle is only ever touched
// by one thread at a time. That makes it sound to move across threads. We do
// not implement `Sync`: concurrent use through a shared reference is not safe.
unsafe impl Send for PipeStream {}

impl PipeStream {
    /// Read one length-prefixed frame and decode it.
    pub fn read_message<T: for<'de> Deserialize<'de>>(&mut self) -> io::Result<T> {
        let mut len_buf = [0u8; 4];
        self.read_exact(&mut len_buf)?;
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; len];
        self.read_exact(&mut body)?;
        crate::decode(&body).map_err(io::Error::other)
    }

    /// Encode and write one length-prefixed frame.
    pub fn write_message<T: Serialize>(&mut self, msg: &T) -> io::Result<()> {
        let frame = crate::encode(msg).map_err(io::Error::other)?;
        self.write_all(&frame)?;
        Ok(())
    }
}

impl Read for PipeStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut read = 0u32;
        unsafe {
            ReadFile(self.handle, Some(buf), Some(&mut read), None).map_err(io::Error::other)?;
        }
        Ok(read as usize)
    }
}

impl Write for PipeStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut written = 0u32;
        unsafe {
            WriteFile(self.handle, Some(buf), Some(&mut written), None)
                .map_err(io::Error::other)?;
        }
        Ok(written as usize)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for PipeStream {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

/// Server side: creates a fresh pipe instance and blocks until a client
/// connects. Call in a loop (one instance per client) from the service.
pub struct PipeServer;

impl PipeServer {
    pub fn accept() -> io::Result<PipeStream> {
        unsafe {
            let (sa, _psd) = pipe_security()?;
            let name = to_wide(PIPE_NAME);
            let handle = CreateNamedPipeW(
                PCWSTR(name.as_ptr()),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                64 * 1024,
                64 * 1024,
                0,
                Some(&sa),
            );
            if handle == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }
            // Blocks until a client connects.
            ConnectNamedPipe(handle, None).map_err(io::Error::other)?;
            Ok(PipeStream { handle })
        }
    }
}

/// Client side: connect to the service's pipe.
pub fn connect() -> io::Result<PipeStream> {
    unsafe {
        let name = to_wide(PIPE_NAME);
        let handle = CreateFileW(
            PCWSTR(name.as_ptr()),
            (FILE_GENERIC_READ | FILE_GENERIC_WRITE).0,
            FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            Default::default(),
            None,
        )
        .map_err(io::Error::other)?;
        Ok(PipeStream { handle })
    }
}
