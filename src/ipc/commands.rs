//! rkyv command/response types carried in the SHM rings (spec perf/008 §5–7).
//!
//! A length-prefixed frame holds an rkyv payload. The server validates
//! untrusted command bytes with `rkyv::access` before deserializing to an
//! owned value (spec §6 option a: copy into an `AlignedVec`, correctness over
//! zero-copy).

use rkyv::util::AlignedVec;
use rkyv::{rancor, Archive, Archived, Deserialize, Serialize};
use thiserror::Error;

/// Client → server command.
#[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
pub enum ShmCommand {
    Get { request_id: u64, domain: String, key: Vec<u8> },
    Put { request_id: u64, domain: String, key: Vec<u8>, value: Vec<u8>, ttl_secs: u64 },
    Delete { request_id: u64, domain: String, key: Vec<u8> },
    SetNull { request_id: u64, domain: String, key: Vec<u8> },
    ScanKeys { request_id: u64, domain: String, prefix: Vec<u8> },
    Ping { request_id: u64 },
}

/// Three-valued GET payload (spec kv/018): mirrors the engine's `GetResult`
/// on the wire — a key can be absent, explicitly NULL, or carry bytes.
#[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
pub enum ShmGetValue {
    Absent,
    Null,
    Present(Vec<u8>),
}

/// Server → client response. `code` is an HTTP-analog status (404, 429, …).
#[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
pub enum ShmResponse {
    GetOk { request_id: u64, value: ShmGetValue },
    Ok { request_id: u64 },
    ScanResult { request_id: u64, keys: Vec<Vec<u8>> },
    Pong { request_id: u64 },
    Error { request_id: u64, code: u32, message: String },
}

/// rkyv validation rejected an untrusted payload.
#[derive(Debug, Error)]
#[error("malformed shm payload: {0}")]
pub struct DecodeError(String);

impl ShmCommand {
    pub fn encode(&self) -> AlignedVec {
        rkyv::to_bytes::<rancor::Error>(self)
            .expect("rkyv serialization is infallible for in-memory values")
    }

    /// Validates untrusted bytes (`rkyv::access` is the security gate), then
    /// deserializes to an owned command.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut aligned: AlignedVec = AlignedVec::with_capacity(bytes.len());
        aligned.extend_from_slice(bytes);
        let archived = rkyv::access::<Archived<Self>, rancor::Error>(aligned.as_slice())
            .map_err(|e| DecodeError(e.to_string()))?;
        rkyv::deserialize::<Self, rancor::Error>(archived).map_err(|e| DecodeError(e.to_string()))
    }
}

impl ShmResponse {
    pub fn encode(&self) -> AlignedVec {
        rkyv::to_bytes::<rancor::Error>(self)
            .expect("rkyv serialization is infallible for in-memory values")
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut aligned: AlignedVec = AlignedVec::with_capacity(bytes.len());
        aligned.extend_from_slice(bytes);
        let archived = rkyv::access::<Archived<Self>, rancor::Error>(aligned.as_slice())
            .map_err(|e| DecodeError(e.to_string()))?;
        rkyv::deserialize::<Self, rancor::Error>(archived).map_err(|e| DecodeError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 7. ShmCommand serialize/deserialize roundtrip for every variant.
    #[test]
    fn test_command_roundtrip_all_variants() {
        let cmds = [
            ShmCommand::Get { request_id: 1, domain: "d".into(), key: b"k".to_vec() },
            ShmCommand::Put {
                request_id: 2,
                domain: "d".into(),
                key: b"k".to_vec(),
                value: b"v".to_vec(),
                ttl_secs: 60,
            },
            ShmCommand::Delete { request_id: 3, domain: "d".into(), key: b"k".to_vec() },
            ShmCommand::SetNull { request_id: 6, domain: "d".into(), key: b"k".to_vec() },
            ShmCommand::ScanKeys { request_id: 4, domain: "d".into(), prefix: b"p".to_vec() },
            ShmCommand::Ping { request_id: 5 },
        ];
        for cmd in cmds {
            let bytes = cmd.encode();
            assert_eq!(ShmCommand::decode(&bytes).unwrap(), cmd);
        }
    }

    #[test]
    fn test_response_roundtrip_all_variants() {
        let resps = [
            ShmResponse::GetOk { request_id: 1, value: ShmGetValue::Present(b"v".to_vec()) },
            ShmResponse::GetOk { request_id: 2, value: ShmGetValue::Absent },
            ShmResponse::GetOk { request_id: 7, value: ShmGetValue::Null },
            ShmResponse::Ok { request_id: 3 },
            ShmResponse::ScanResult { request_id: 4, keys: vec![b"a".to_vec(), b"bb".to_vec()] },
            ShmResponse::Pong { request_id: 5 },
            ShmResponse::Error { request_id: 6, code: 404, message: "not found".into() },
        ];
        for resp in resps {
            let bytes = resp.encode();
            assert_eq!(ShmResponse::decode(&bytes).unwrap(), resp);
        }
    }

    // Untrusted garbage must be rejected, not deserialized.
    #[test]
    fn test_decode_rejects_garbage() {
        assert!(ShmCommand::decode(&[0xff, 0x01, 0x02, 0x03, 0x04, 0x05]).is_err());
        assert!(ShmCommand::decode(&[]).is_err());
    }
}
