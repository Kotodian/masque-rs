// Per-client QUIC + HTTP/3 connection state.

use std::collections::HashMap;

use crate::tunnel::ip::IpTunnel;
use crate::tunnel::udp::UdpTunnel;

/// State for a single client connection.
pub struct ClientConnection {
    pub quic: quiche::Connection,
    pub h3: Option<quiche::h3::Connection>,
    /// Active UDP tunnels, keyed by stream ID.
    pub udp_tunnels: HashMap<u64, UdpTunnel>,
    /// Active IP tunnels, keyed by stream ID.
    pub ip_tunnels: HashMap<u64, IpTunnel>,
}

impl ClientConnection {
    pub fn new(quic: quiche::Connection) -> Self {
        Self {
            quic,
            h3: None,
            udp_tunnels: HashMap::new(),
            ip_tunnels: HashMap::new(),
        }
    }
}
