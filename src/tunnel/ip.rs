// CONNECT-IP tunnel implementation (RFC 9484).
//
// Each tunnel is assigned IP addresses from a shared pool and relays IP
// packets between the QUIC client and a shared TUN device.

use std::net::IpAddr;
use std::time::Instant;

/// State for a single CONNECT-IP tunnel.
pub struct IpTunnel {
    /// The HTTP/3 stream ID this tunnel is bound to.
    pub stream_id: u64,
    /// IP addresses assigned to this client.
    pub assigned_addrs: Vec<IpAddr>,
    /// Timestamp of last packet relayed (either direction).
    pub last_activity: Instant,
}

impl IpTunnel {
    pub fn new(stream_id: u64) -> Self {
        Self {
            stream_id,
            assigned_addrs: Vec::new(),
            last_activity: Instant::now(),
        }
    }

    /// Check whether a source IP is assigned to this tunnel.
    pub fn owns_address(&self, addr: &IpAddr) -> bool {
        self.assigned_addrs.contains(addr)
    }

    /// Check whether the tunnel has been idle longer than `timeout`.
    pub fn is_idle(&self, timeout: std::time::Duration) -> bool {
        self.last_activity.elapsed() > timeout
    }
}
