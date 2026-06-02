//! Wire protocol shared by the UI back-end (`booster-app`) and the privileged
//! service (`booster-service`). Keeping the types in one crate prevents the two
//! sides from drifting.
//!
//! Transport is a length-prefixed JSON message over a named pipe
//! (`\\.\pipe\SystemBooster`). The pipe and its framing helpers live in
//! [`transport`]; the request/response enums are platform-independent.

use booster_core::classify::Profile;
use booster_core::snapshot::Metrics;
use booster_core::{BoostReport, ScanResult};
use serde::{Deserialize, Serialize};

/// The well-known pipe name the service listens on.
pub const PIPE_NAME: &str = r"\\.\pipe\SystemBooster";

/// Requests sent UI → service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    /// Enumerate processes/services and mark eligibility for `profile`.
    Scan { profile: Profile },
    /// Apply a boost for `profile`.
    StartBoost { profile: Profile },
    /// Restore everything.
    EndBoost,
    /// Keep the boost alive; resets the service watchdog.
    Heartbeat,
    /// Current boost status + metrics.
    GetStatus,
}

/// Responses sent service → UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Response {
    Scan(ScanResult),
    Boosted(BoostReport),
    Ended,
    Ack,
    Status(Status),
    Error { message: String },
}

/// Snapshot of the service state for the dashboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Status {
    pub boosted: bool,
    pub active_profile: Option<String>,
    pub metrics: Metrics,
}

/// Encode a message as a length-prefixed JSON frame: 4-byte big-endian length
/// followed by the JSON body. Used by both the client and server transports.
pub fn encode<T: Serialize>(msg: &T) -> serde_json::Result<Vec<u8>> {
    let body = serde_json::to_vec(msg)?;
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Decode a JSON body (already de-framed) into a message.
pub fn decode<T: for<'de> Deserialize<'de>>(body: &[u8]) -> serde_json::Result<T> {
    serde_json::from_slice(body)
}

#[cfg(windows)]
pub mod transport;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        let req = Request::Heartbeat;
        let frame = encode(&req).unwrap();
        // First 4 bytes are the big-endian length.
        let len = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
        assert_eq!(len, frame.len() - 4);
        let decoded: Request = decode(&frame[4..]).unwrap();
        assert!(matches!(decoded, Request::Heartbeat));
    }
}
