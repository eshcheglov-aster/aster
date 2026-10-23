//! Independent IP rendezvous/relay infrastructure and native command inputs.

#![forbid(unsafe_code)]

use crate::LabResult;
use aster_ip::{CipherRelayServer, RendezvousServer};
use aster_mesh::NodeId;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::net::SocketAddr;
use std::path::Path;
use std::thread::{self, JoinHandle};
use std::time::Instant;
use zeroize::Zeroize;

/// Configuration for the UDP rendezvous service and optional opaque TCP relay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RendezvousInfraConfig {
    pub rendezvous_bind: SocketAddr,
    pub relay: Option<RelayInfraConfig>,
}

/// Bounded relay listener configuration. A zero pair limit serves for the
/// lifetime of the infrastructure process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayInfraConfig {
    pub bind: SocketAddr,
    pub pair_limit: usize,
}

/// Snapshot from the nonblocking infrastructure helper.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InfraMetrics {
    pub rendezvous_address: SocketAddr,
    pub relay_address: Option<SocketAddr>,
    pub poll_calls: u64,
    pub processed_datagrams: u64,
    pub relay_finished: bool,
    pub elapsed_ms: u64,
}

impl InfraMetrics {
    pub fn to_record(self) -> String {
        format!(
            "ASTER_LAB_INFRA\tversion=1\trendezvous_address={}\trelay_address={}\tpoll_calls={}\tprocessed_datagrams={}\trelay_finished={}\telapsed_ms={}",
            self.rendezvous_address,
            display_endpoint(self.relay_address),
            self.poll_calls,
            self.processed_datagrams,
            self.relay_finished,
            self.elapsed_ms
        )
    }
}

/// Process-owned combined infrastructure. [`Self::poll`] never waits for a UDP
/// registration. The optional relay uses the adapter's bounded blocking server
/// on a background thread; dropping a still-running instance detaches that
/// process-lifetime thread rather than exposing an unsafe cancellation path.
pub struct RendezvousInfra {
    rendezvous: RendezvousServer,
    rendezvous_address: SocketAddr,
    relay_address: Option<SocketAddr>,
    relay_thread: Option<JoinHandle<io::Result<()>>>,
    relay_finished: bool,
    poll_calls: u64,
    processed_datagrams: u64,
    started: Instant,
}

impl fmt::Debug for RendezvousInfra {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RendezvousInfra")
            .field("rendezvous_address", &self.rendezvous_address)
            .field("relay_address", &self.relay_address)
            .field("relay_finished", &self.relay_finished)
            .field("poll_calls", &self.poll_calls)
            .field("processed_datagrams", &self.processed_datagrams)
            .finish()
    }
}

impl RendezvousInfra {
    pub fn bind(config: RendezvousInfraConfig) -> LabResult<Self> {
        let rendezvous = RendezvousServer::bind(config.rendezvous_bind)?;
        let rendezvous_address = rendezvous.local_addr()?;
        let (relay_address, relay_thread) = if let Some(relay_config) = config.relay {
            let relay = CipherRelayServer::bind(relay_config.bind)?;
            let address = relay.local_addr()?;
            let handle = thread::Builder::new()
                .name("aster-lab-relay-infra".into())
                .spawn(move || relay.serve(relay_config.pair_limit))?;
            (Some(address), Some(handle))
        } else {
            (None, None)
        };
        let relay_finished = relay_thread.is_none();
        Ok(Self {
            rendezvous,
            rendezvous_address,
            relay_address,
            relay_thread,
            relay_finished,
            poll_calls: 0,
            processed_datagrams: 0,
            started: Instant::now(),
        })
    }

    pub fn rendezvous_address(&self) -> SocketAddr {
        self.rendezvous_address
    }

    pub fn relay_address(&self) -> Option<SocketAddr> {
        self.relay_address
    }

    /// Processes all currently queued rendezvous datagrams and observes relay
    /// completion without blocking for new work.
    pub fn poll(&mut self) -> LabResult<InfraMetrics> {
        let processed = self.rendezvous.poll()?;
        self.poll_calls = self.poll_calls.saturating_add(1);
        self.processed_datagrams = self
            .processed_datagrams
            .saturating_add(u64::try_from(processed).unwrap_or(u64::MAX));
        if self
            .relay_thread
            .as_ref()
            .is_some_and(JoinHandle::is_finished)
        {
            let handle = self
                .relay_thread
                .take()
                .ok_or_else(|| invalid("relay completion state changed unexpectedly"))?;
            handle
                .join()
                .map_err(|_| invalid("relay infrastructure thread panicked"))??;
            self.relay_finished = true;
        }
        Ok(self.metrics())
    }

    pub fn metrics(&self) -> InfraMetrics {
        InfraMetrics {
            rendezvous_address: self.rendezvous_address,
            relay_address: self.relay_address,
            poll_calls: self.poll_calls,
            processed_datagrams: self.processed_datagrams,
            relay_finished: self.relay_finished,
            elapsed_ms: elapsed_ms(self.started),
        }
    }
}

/// Reads exactly `N` secret bytes from a mode-0600 hexadecimal file. The file
/// contents are never included in an error.
pub fn read_private_hex<const N: usize>(path: &Path) -> LabResult<[u8; N]> {
    let encoded_bound = N
        .checked_mul(2)
        .and_then(|value| value.checked_add(2))
        .ok_or_else(|| invalid("private hexadecimal size overflow"))?;
    let bytes = read_private_file(path, encoded_bound)?;
    let text = std::str::from_utf8(bytes.as_slice())
        .map_err(|_| invalid("private hexadecimal file is not UTF-8"))?
        .trim();
    if text.len() != N.saturating_mul(2) {
        return Err(invalid("private hexadecimal file has the wrong length"));
    }
    let mut decoded = [0_u8; N];
    decode_hex_into(text, &mut decoded)?;
    Ok(decoded)
}

/// Canonical lowercase NodeID representation used by manifests and metrics.
pub fn encode_node_id(identity: &NodeId) -> String {
    encode_hex(identity)
}

/// Parses exactly one 32-byte hexadecimal NodeID.
pub fn parse_node_id(value: &str) -> LabResult<NodeId> {
    if value.len() != 64 {
        return Err(invalid(
            "NodeID must contain exactly 64 hexadecimal characters",
        ));
    }
    let mut identity = [0_u8; 32];
    decode_hex_into(value, &mut identity)?;
    Ok(identity)
}

fn read_private_file(path: &Path, limit: usize) -> LabResult<SecretBytes> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(invalid("protected input is not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(invalid("protected input must have mode 0600 or stricter"));
        }
    }
    let file = OpenOptions::new().read(true).open(path)?;
    let read_limit = u64::try_from(limit)?
        .checked_add(1)
        .ok_or_else(|| invalid("protected input size limit overflow"))?;
    let mut bytes = Vec::new();
    file.take(read_limit).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        bytes.zeroize();
        return Err(invalid("protected input exceeds its size bound"));
    }
    Ok(SecretBytes(bytes))
}

struct SecretBytes(Vec<u8>);

impl SecretBytes {
    fn as_slice(&self) -> &[u8] {
        &self.0
    }

    fn erase(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.erase();
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(DIGITS[usize::from(byte >> 4)] as char);
        output.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    output
}

fn decode_hex_into(value: &str, output: &mut [u8]) -> LabResult<()> {
    if value.len() != output.len().saturating_mul(2) || !value.is_ascii() {
        return Err(invalid("hexadecimal value has the wrong length"));
    }
    for (index, byte) in output.iter_mut().enumerate() {
        let start = index * 2;
        *byte = u8::from_str_radix(&value[start..start + 2], 16)
            .map_err(|_| invalid("hexadecimal value contains an invalid character"))?;
    }
    Ok(())
}

fn display_endpoint(endpoint: Option<SocketAddr>) -> String {
    endpoint.map_or_else(|| "-".into(), |address| address.to_string())
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn invalid(message: impl Into<String>) -> Box<dyn std::error::Error + Send + Sync> {
    Box::new(io::Error::new(io::ErrorKind::InvalidInput, message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_id_round_trips_canonically() {
        assert_eq!(
            parse_node_id(&encode_node_id(&[0xab; 32])).unwrap(),
            [0xab; 32]
        );
        assert!(parse_node_id("00").is_err());
    }
}
