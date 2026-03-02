// TUN device management for CONNECT-IP tunnels.
//
// Creates and manages a shared TUN device. All IP tunnels share a single
// device; routing between tunnels is handled by the routing table.

use std::sync::Arc;

use tun_rs::AsyncDevice;
use tracing::info;

/// Wraps the async TUN device with server-specific configuration.
pub struct TunManager {
    device: Arc<AsyncDevice>,
    mtu: usize,
}

impl TunManager {
    /// Create and configure a new TUN device.
    ///
    /// Requires root/CAP_NET_ADMIN privileges. The device is created with the
    /// given name and MTU, and assigned the gateway addresses for the pool
    /// ranges (the network address + 1 offset is used as the device IP; clients
    /// get subsequent addresses from the pool).
    pub fn new(
        name: &str,
        mtu: u16,
        v4_gateway: Option<std::net::Ipv4Addr>,
        v4_prefix: u8,
        v6_gateway: Option<std::net::Ipv6Addr>,
        v6_prefix: u8,
    ) -> std::io::Result<Self> {
        let mut builder = tun_rs::DeviceBuilder::new()
            .name(name)
            .mtu(mtu);

        if let Some(v4) = v4_gateway {
            builder = builder.ipv4(v4, v4_prefix, None);
        }
        if let Some(v6) = v6_gateway {
            builder = builder.ipv6(v6, v6_prefix);
        }

        let device = builder.build_async()?;

        info!(
            name = name,
            mtu = mtu,
            "TUN device created"
        );

        Ok(Self {
            device: Arc::new(device),
            mtu: mtu as usize,
        })
    }

    /// Read an IP packet from the TUN device.
    pub async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.device.recv(buf).await
    }

    /// Write an IP packet to the TUN device.
    pub async fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.device.send(buf).await
    }

    /// Try to read without blocking (returns WouldBlock if no data).
    pub fn try_recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.device.try_recv(buf)
    }

    /// Try to write without blocking.
    pub fn try_send(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.device.try_send(buf)
    }

    /// The configured MTU.
    pub fn mtu(&self) -> usize {
        self.mtu
    }

    /// Get a clone of the underlying device Arc (for use in separate tasks).
    pub fn device(&self) -> Arc<AsyncDevice> {
        Arc::clone(&self.device)
    }
}
