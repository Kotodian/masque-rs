// QUIC listener and connection accept loop.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use quiche::h3::NameValue;
use tokio::net::UdpSocket;
use tracing::{debug, error, info, warn};

use crate::address_pool::AddressPool;
use crate::capsule;
use crate::capsule::{AssignedAddress, CapsuleFrame, IpAddress, IpAddressRange};
use crate::config::ServerConfig;
use crate::connection::ClientConnection;
use crate::datagram;
use crate::ip_packet;
use crate::policy::TargetPolicy;
use crate::routing::{RoutingTable, TunnelOwner};
use crate::tun::TunManager;
use crate::tunnel::ip::IpTunnel;
use crate::tunnel::udp::UdpTunnel;
use crate::uri;

/// Maximum UDP datagram size we read from the socket.
const MAX_DATAGRAM_SIZE: usize = 65535;

/// Unique connection ID length.
const CONN_ID_LEN: usize = 16;

/// Top-level MASQUE server.
pub struct Server {
    socket: UdpSocket,
    quic_config: quiche::Config,
    h3_config: quiche::h3::Config,
    connections: HashMap<quiche::ConnectionId<'static>, ClientConnection>,
    udp_policy: TargetPolicy,
    address_pool: AddressPool,
    routing_table: RoutingTable,
    config: ServerConfig,
    /// Monotonically increasing connection index used as the conn_id in
    /// TunnelOwner (since quiche ConnectionId is not easily hashable).
    next_conn_index: u64,
    /// Maps quiche ConnectionId to our internal conn_index for routing table
    /// lookups.
    conn_index_map: HashMap<quiche::ConnectionId<'static>, u64>,
    /// Shared TUN device for CONNECT-IP tunnels (None if IP proxy disabled).
    tun: Option<TunManager>,
}

impl Server {
    /// Create a new server bound to the configured address.
    pub async fn bind(config: ServerConfig) -> anyhow::Result<Self> {
        let socket = UdpSocket::bind(config.server.listen_addr).await?;
        info!(addr = %config.server.listen_addr, "listening");

        let mut quic_config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;

        // TLS
        quic_config.load_cert_chain_from_pem_file(
            config.tls.cert_path.to_str().unwrap_or(""),
        )?;
        quic_config.load_priv_key_from_pem_file(
            config.tls.key_path.to_str().unwrap_or(""),
        )?;

        quic_config
            .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)?;

        // Transport parameters
        quic_config.set_max_idle_timeout(
            (config.server.idle_timeout_secs * 1000) as u64,
        );
        quic_config
            .set_max_recv_udp_payload_size(config.quic.max_datagram_size);
        quic_config
            .set_max_send_udp_payload_size(config.quic.max_datagram_size);
        quic_config.set_initial_max_data(10_000_000);
        quic_config.set_initial_max_stream_data_bidi_local(1_000_000);
        quic_config.set_initial_max_stream_data_bidi_remote(1_000_000);
        quic_config.set_initial_max_streams_bidi(
            config.quic.initial_max_streams_bidi,
        );
        quic_config.set_initial_max_streams_uni(100);

        // DATAGRAM extension
        if config.quic.enable_dgram {
            quic_config.enable_dgram(true, 1000, 1000);
        }

        let mut h3_config = quiche::h3::Config::new()?;
        h3_config.set_max_field_section_size(8192);

        let udp_policy = TargetPolicy::new(
            &config.udp_proxy.allow_targets,
            &config.udp_proxy.deny_targets,
        );

        let address_pool = AddressPool::new(
            &config.ip_proxy.ipv4_pool,
            &config.ip_proxy.ipv6_pool,
        )
        .map_err(|e| anyhow::anyhow!("address pool: {e}"))?;

        // Create TUN device if IP proxy is enabled.
        let tun = if config.ip_proxy.enabled {
            // Parse pool CIDRs to get the gateway address (network + 1)
            // that we assign to the TUN device itself.
            let (v4_gw, v4_prefix) = if !config.ip_proxy.ipv4_pool.is_empty() {
                let net: ipnet::Ipv4Net = config
                    .ip_proxy
                    .ipv4_pool
                    .parse()
                    .map_err(|e| anyhow::anyhow!("bad v4 pool: {e}"))?;
                let gw_bits = u32::from(net.network()) | 1;
                (
                    Some(std::net::Ipv4Addr::from(gw_bits)),
                    net.prefix_len(),
                )
            } else {
                (None, 0)
            };

            let (v6_gw, v6_prefix) = if !config.ip_proxy.ipv6_pool.is_empty() {
                let net: ipnet::Ipv6Net = config
                    .ip_proxy
                    .ipv6_pool
                    .parse()
                    .map_err(|e| anyhow::anyhow!("bad v6 pool: {e}"))?;
                let gw_bits = u128::from(net.network()) | 1;
                (
                    Some(std::net::Ipv6Addr::from(gw_bits)),
                    net.prefix_len(),
                )
            } else {
                (None, 0)
            };

            match TunManager::new(
                &config.ip_proxy.tun_name,
                config.ip_proxy.tun_mtu as u16,
                v4_gw,
                v4_prefix,
                v6_gw,
                v6_prefix,
            ) {
                Ok(t) => Some(t),
                Err(e) => {
                    warn!(%e, "failed to create TUN device — CONNECT-IP will be unavailable");
                    None
                }
            }
        } else {
            None
        };

        Ok(Self {
            socket,
            quic_config,
            h3_config,
            connections: HashMap::new(),
            udp_policy,
            address_pool,
            routing_table: RoutingTable::new(),
            config,
            next_conn_index: 0,
            conn_index_map: HashMap::new(),
            tun,
        })
    }

    /// Run the server event loop.
    pub async fn run(&mut self) -> anyhow::Result<()> {
        let mut buf = vec![0u8; MAX_DATAGRAM_SIZE];
        let mut out = vec![0u8; MAX_DATAGRAM_SIZE];

        let local_addr = self.socket.local_addr()?;
        let idle_timeout =
            Duration::from_secs(self.config.server.idle_timeout_secs);

        let mut shutting_down = false;
        let mut drain_deadline: Option<tokio::time::Instant> = None;
        const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

        loop {
            // Calculate the earliest timer across all connections.
            let timeout = self
                .connections
                .values()
                .filter_map(|c| c.quic.timeout())
                .min()
                .map(|t| t.min(Duration::from_millis(50)))
                .or(Some(Duration::from_millis(50)));

            // Wait for a packet, signal, or timeout.
            enum Event {
                Packet(std::io::Result<(usize, SocketAddr)>),
                Shutdown,
                Timeout,
            }

            let event = if let Some(timeout) = timeout {
                tokio::select! {
                    biased;
                    _ = tokio::signal::ctrl_c(), if !shutting_down => {
                        Event::Shutdown
                    }
                    result = tokio::time::timeout(
                        timeout, self.socket.recv_from(&mut buf)
                    ) => match result {
                        Ok(r) => Event::Packet(r),
                        Err(_) => Event::Timeout,
                    },
                }
            } else {
                Event::Packet(self.socket.recv_from(&mut buf).await)
            };

            match event {
                Event::Shutdown => {
                    info!("shutdown signal received, draining connections...");
                    shutting_down = true;
                    drain_deadline =
                        Some(tokio::time::Instant::now() + DRAIN_TIMEOUT);

                    for client in self.connections.values_mut() {
                        if let Some(h3) = &mut client.h3 {
                            h3.send_goaway(&mut client.quic, 0).ok();
                        }
                        client
                            .quic
                            .close(true, 0x0, b"server shutting down")
                            .ok();
                    }
                }
                Event::Packet(Ok((len, from))) => {
                    if !shutting_down {
                        self.handle_packet(
                            &mut buf[..len],
                            from,
                            local_addr,
                        );
                    } else {
                        // During shutdown, still feed packets to quiche so
                        // it can send CONNECTION_CLOSE frames.
                        if let Ok(hdr) = quiche::Header::from_slice(
                            &mut buf[..len],
                            CONN_ID_LEN,
                        ) {
                            if let Some(client) =
                                self.connections.get_mut(&hdr.dcid)
                            {
                                let recv_info =
                                    quiche::RecvInfo { from, to: local_addr };
                                client.quic.recv(&mut buf[..len], recv_info).ok();
                            }
                        }
                    }
                }
                Event::Packet(Err(e)) => {
                    error!(%e, "socket recv error");
                }
                Event::Timeout => {}
            }

            // Process QUIC DATAGRAMs → forward to target UDP/TUN.
            if !shutting_down {
                self.relay_client_datagrams();
                self.relay_target_datagrams(&mut buf).await;
                self.relay_tun_inbound(&mut buf);
                self.cleanup_idle_tunnels(idle_timeout);
            }

            // Drive all connections: handle timers, send pending data.
            self.drive_connections(&mut out).await;

            // Remove closed connections and clean up their resources.
            let closed_ids: Vec<quiche::ConnectionId<'static>> = self
                .connections
                .iter()
                .filter(|(_, c)| c.quic.is_closed())
                .map(|(id, _)| id.clone())
                .collect();

            for id in closed_ids {
                if let Some(client) = self.connections.remove(&id) {
                    info!(?id, "connection closed");
                    for tunnel in client.ip_tunnels.values() {
                        self.address_pool.release_all(&tunnel.assigned_addrs);
                    }
                    if let Some(conn_idx) = self.conn_index_map.remove(&id) {
                        self.routing_table.remove_by_connection(conn_idx);
                    }
                }
            }

            // During shutdown, exit once all connections are drained or
            // the drain deadline is reached.
            if shutting_down {
                if self.connections.is_empty() {
                    info!("all connections drained, exiting");
                    return Ok(());
                }
                if let Some(deadline) = drain_deadline {
                    if tokio::time::Instant::now() >= deadline {
                        warn!(
                            remaining = self.connections.len(),
                            "drain timeout reached, forcing exit"
                        );
                        // Release all remaining IP tunnel resources.
                        for client in self.connections.values() {
                            for tunnel in client.ip_tunnels.values() {
                                self.address_pool
                                    .release_all(&tunnel.assigned_addrs);
                            }
                        }
                        return Ok(());
                    }
                }
            }
        }
    }

    /// Process an incoming UDP packet (QUIC).
    fn handle_packet(
        &mut self,
        buf: &mut [u8],
        from: SocketAddr,
        local: SocketAddr,
    ) {
        let hdr = match quiche::Header::from_slice(buf, CONN_ID_LEN) {
            Ok(v) => v,
            Err(e) => {
                debug!(%e, "failed to parse QUIC header");
                return;
            }
        };

        let conn_id = ring::hmac::sign(
            &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"masque"),
            &hdr.dcid,
        );
        let conn_id_vec = conn_id.as_ref()[..CONN_ID_LEN].to_vec();
        let conn_id = quiche::ConnectionId::from_vec(conn_id_vec);

        // Look up existing connection or accept a new one.
        if !self.connections.contains_key(&hdr.dcid)
            && !self.connections.contains_key(&conn_id)
        {
            if hdr.ty != quiche::Type::Initial {
                debug!("non-initial packet for unknown connection");
                return;
            }

            // Enforce max_connections limit.
            if self.connections.len() >= self.config.server.max_connections {
                warn!("max connections reached, rejecting new connection");
                return;
            }

            let scid = quiche::ConnectionId::from_vec(
                conn_id.as_ref().to_vec(),
            );

            let quic = match quiche::accept(
                &scid,
                None,
                local,
                from,
                &mut self.quic_config,
            ) {
                Ok(c) => c,
                Err(e) => {
                    error!(%e, "failed to accept connection");
                    return;
                }
            };

            info!(?scid, %from, "new connection");

            let conn_idx = self.next_conn_index;
            self.next_conn_index += 1;
            self.conn_index_map.insert(scid.clone(), conn_idx);

            let client = ClientConnection::new(quic);
            self.connections.insert(scid, client);
        }

        // Find the connection — try dcid first, then derived conn_id.
        let key = if self.connections.contains_key(&hdr.dcid) {
            hdr.dcid.into_owned()
        } else if self.connections.contains_key(&conn_id) {
            conn_id
        } else {
            debug!("packet for unknown connection");
            return;
        };

        let client = self.connections.get_mut(&key).unwrap();

        // Feed the packet to quiche.
        let recv_info = quiche::RecvInfo { from, to: local };

        if let Err(e) = client.quic.recv(buf, recv_info) {
            debug!(%e, "quiche recv error");
            return;
        }

        // Upgrade to HTTP/3 if not done yet.
        if client.h3.is_none() {
            match quiche::h3::Connection::with_transport(
                &mut client.quic,
                &self.h3_config,
            ) {
                Ok(h3) => {
                    client.h3 = Some(h3);
                    debug!("HTTP/3 connection established");
                }
                Err(e) => {
                    debug!(%e, "HTTP/3 handshake not ready yet");
                }
            }
        }

        // Collect pending tunnel setups so we can do async I/O outside
        // the borrow of h3.
        let mut pending_udp_setups: Vec<(u64, uri::UdpTarget)> = Vec::new();
        let mut pending_ip_setups: Vec<u64> = Vec::new();
        let mut closed_ip_streams: Vec<u64> = Vec::new();

        // Process HTTP/3 events.
        if let Some(h3) = &mut client.h3 {
            loop {
                match h3.poll(&mut client.quic) {
                    Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                        Self::handle_request(
                            h3,
                            &mut client.quic,
                            stream_id,
                            &list,
                            &self.config,
                            &self.udp_policy,
                            &mut pending_udp_setups,
                            &mut pending_ip_setups,
                        );
                    }
                    Ok((stream_id, quiche::h3::Event::Data)) => {
                        debug!(stream_id, "H3 data event");
                    }
                    Ok((stream_id, quiche::h3::Event::Finished)) => {
                        // Stream closed by client — remove tunnel if any.
                        if client.udp_tunnels.remove(&stream_id).is_some() {
                            info!(stream_id, "UDP tunnel closed by client");
                        }
                        if client.ip_tunnels.contains_key(&stream_id) {
                            closed_ip_streams.push(stream_id);
                        }
                    }
                    Ok((stream_id, quiche::h3::Event::Reset { .. })) => {
                        if client.udp_tunnels.remove(&stream_id).is_some() {
                            info!(stream_id, "UDP tunnel reset by client");
                        }
                        if client.ip_tunnels.contains_key(&stream_id) {
                            closed_ip_streams.push(stream_id);
                        }
                    }
                    Ok((_stream_id, quiche::h3::Event::PriorityUpdate)) => {}
                    Ok((_stream_id, quiche::h3::Event::GoAway)) => {}
                    Err(quiche::h3::Error::Done) => break,
                    Err(e) => {
                        error!(%e, "HTTP/3 error");
                        break;
                    }
                }
            }
        }

        // Now handle pending UDP tunnel setups (we deferred these so
        // we could drop the h3 borrow and do the sync part here).
        // The actual async socket creation will be handled in the next
        // event loop tick via a spawn or direct await.
        // For simplicity, we store them as pending and resolve them
        // in drive_connections.
        let max_tunnels = self.config.server.max_tunnels_per_connection;
        for (stream_id, target) in pending_udp_setups {
            let total_tunnels =
                client.udp_tunnels.len() + client.ip_tunnels.len();
            if total_tunnels >= max_tunnels {
                warn!(
                    stream_id,
                    total_tunnels,
                    "tunnel limit reached, rejecting"
                );
                if let Some(h3) = &mut client.h3 {
                    Self::send_error_response(
                        h3, &mut client.quic, stream_id, 503,
                    );
                }
                continue;
            }
            match target.resolve() {
                Ok(addrs) => {
                    // Use the first resolved address.
                    let addr = addrs[0];
                    // We can't await here (not async fn), so create the
                    // UdpTunnel synchronously using std::net, then convert.
                    match std::net::UdpSocket::bind(if addr.is_ipv4() {
                        "0.0.0.0:0"
                    } else {
                        "[::]:0"
                    }) {
                        Ok(std_sock) => {
                            if let Err(e) = std_sock.connect(addr) {
                                warn!(stream_id, %e, "UDP connect failed");
                                if let Some(h3) = &mut client.h3 {
                                    Self::send_error_response(
                                        h3, &mut client.quic, stream_id, 502,
                                    );
                                }
                                continue;
                            }
                            std_sock.set_nonblocking(true).ok();
                            match UdpSocket::from_std(std_sock) {
                                Ok(tok_sock) => {
                                    let tunnel = UdpTunnel {
                                        stream_id,
                                        socket: tok_sock,
                                        target_addr: addr,
                                        last_activity: std::time::Instant::now(),
                                    };
                                    info!(
                                        stream_id,
                                        target = %addr,
                                        "UDP tunnel established"
                                    );
                                    client.udp_tunnels.insert(stream_id, tunnel);
                                }
                                Err(e) => {
                                    warn!(stream_id, %e, "tokio socket convert failed");
                                    if let Some(h3) = &mut client.h3 {
                                        Self::send_error_response(
                                            h3, &mut client.quic, stream_id, 502,
                                        );
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            warn!(stream_id, %e, "UDP bind failed");
                            if let Some(h3) = &mut client.h3 {
                                Self::send_error_response(
                                    h3, &mut client.quic, stream_id, 502,
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!(stream_id, %e, "DNS resolution failed");
                    if let Some(h3) = &mut client.h3 {
                        Self::send_error_response(
                            h3, &mut client.quic, stream_id, 502,
                        );
                    }
                }
            }
        }

        // Handle pending CONNECT-IP tunnel setups: allocate addresses,
        // register routes, send capsules.
        let conn_idx = self.conn_index_map.get(&key).copied().unwrap_or(0);
        for stream_id in pending_ip_setups {
            let total_tunnels =
                client.udp_tunnels.len() + client.ip_tunnels.len();
            if total_tunnels >= max_tunnels {
                warn!(
                    stream_id,
                    total_tunnels,
                    "tunnel limit reached, rejecting IP tunnel"
                );
                if let Some(h3) = &mut client.h3 {
                    Self::send_error_response(
                        h3, &mut client.quic, stream_id, 503,
                    );
                }
                continue;
            }
            Self::setup_ip_tunnel(
                &mut self.address_pool,
                &mut self.routing_table,
                client,
                stream_id,
                conn_idx,
            );
        }

        // Clean up closed IP tunnels: release addresses, remove routes.
        for stream_id in closed_ip_streams {
            Self::teardown_ip_tunnel(
                &mut self.address_pool,
                &mut self.routing_table,
                client,
                stream_id,
                conn_idx,
            );
        }
    }

    /// Allocate addresses, register routes, send capsules for a new IP tunnel.
    fn setup_ip_tunnel(
        address_pool: &mut AddressPool,
        routing_table: &mut RoutingTable,
        client: &mut ClientConnection,
        stream_id: u64,
        conn_idx: u64,
    ) {
        let mut tunnel = IpTunnel::new(stream_id);

        // Allocate an IPv4 address if the pool has one.
        let v4_result = address_pool.allocate_v4();
        let v6_result = address_pool.allocate_v6();

        if v4_result.is_err() && v6_result.is_err() {
            warn!(stream_id, "address pool exhausted for IP tunnel");
            if let Some(h3) = &mut client.h3 {
                Self::send_error_response(h3, &mut client.quic, stream_id, 503);
            }
            return;
        }

        let mut assigned = Vec::new();

        if let Ok(v4_addr) = v4_result {
            let ip = IpAddr::V4(v4_addr);
            tunnel.assigned_addrs.push(ip);
            routing_table.insert(
                ip,
                TunnelOwner {
                    conn_id: conn_idx,
                    stream_id,
                },
            );
            assigned.push(AssignedAddress {
                request_id: 0,
                ip: IpAddress::V4(v4_addr),
                prefix_len: 32,
            });
            info!(stream_id, addr = %v4_addr, "assigned IPv4 to IP tunnel");
        }

        if let Ok(v6_addr) = v6_result {
            let ip = IpAddr::V6(v6_addr);
            tunnel.assigned_addrs.push(ip);
            routing_table.insert(
                ip,
                TunnelOwner {
                    conn_id: conn_idx,
                    stream_id,
                },
            );
            assigned.push(AssignedAddress {
                request_id: 0,
                ip: IpAddress::V6(v6_addr),
                prefix_len: 128,
            });
            info!(stream_id, addr = %v6_addr, "assigned IPv6 to IP tunnel");
        }

        // Send ADDRESS_ASSIGN capsule on the stream.
        let capsule_data = {
            let frame = CapsuleFrame::AddressAssign(assigned);
            let mut buf = Vec::new();
            capsule::encoder::encode(&frame, &mut buf);
            buf
        };
        if let Some(h3) = &mut client.h3 {
            if let Err(e) =
                h3.send_body(&mut client.quic, stream_id, &capsule_data, false)
            {
                warn!(stream_id, %e, "failed to send ADDRESS_ASSIGN capsule");
            }
        }

        // Send ROUTE_ADVERTISEMENT capsule: advertise a default route so
        // the client knows it can send all traffic through this tunnel.
        let route_capsule = {
            let frame = CapsuleFrame::RouteAdvertisement(vec![
                IpAddressRange {
                    start: IpAddress::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
                    end: IpAddress::V4(std::net::Ipv4Addr::new(255, 255, 255, 255)),
                    ip_protocol: 0, // all protocols
                },
                IpAddressRange {
                    start: IpAddress::V6(std::net::Ipv6Addr::UNSPECIFIED),
                    end: IpAddress::V6(std::net::Ipv6Addr::new(
                        0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
                    )),
                    ip_protocol: 0,
                },
            ]);
            let mut buf = Vec::new();
            capsule::encoder::encode(&frame, &mut buf);
            buf
        };
        if let Some(h3) = &mut client.h3 {
            if let Err(e) =
                h3.send_body(&mut client.quic, stream_id, &route_capsule, false)
            {
                warn!(stream_id, %e, "failed to send ROUTE_ADVERTISEMENT capsule");
            }
        }

        client.ip_tunnels.insert(stream_id, tunnel);
        info!(stream_id, "CONNECT-IP tunnel established");
    }

    /// Release addresses and remove routes for a closing IP tunnel.
    fn teardown_ip_tunnel(
        address_pool: &mut AddressPool,
        routing_table: &mut RoutingTable,
        client: &mut ClientConnection,
        stream_id: u64,
        conn_idx: u64,
    ) {
        if let Some(tunnel) = client.ip_tunnels.remove(&stream_id) {
            info!(stream_id, "IP tunnel closed");

            // Release addresses back to the pool.
            address_pool.release_all(&tunnel.assigned_addrs);

            // Remove routes for this tunnel.
            let owner = TunnelOwner {
                conn_id: conn_idx,
                stream_id,
            };
            routing_table.remove_by_owner(&owner);
        }
    }

    /// Handle an incoming HTTP/3 request.
    fn handle_request(
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        stream_id: u64,
        headers: &[quiche::h3::Header],
        config: &ServerConfig,
        udp_policy: &TargetPolicy,
        pending_udp_setups: &mut Vec<(u64, uri::UdpTarget)>,
        pending_ip_setups: &mut Vec<u64>,
    ) {
        let method = headers
            .iter()
            .find(|h| h.name() == b":method")
            .map(|h| h.value().to_vec());
        let path = headers
            .iter()
            .find(|h| h.name() == b":path")
            .map(|h| String::from_utf8_lossy(h.value()).to_string());
        let protocol = headers
            .iter()
            .find(|h| h.name() == b":protocol")
            .map(|h| String::from_utf8_lossy(h.value()).to_string());

        info!(
            stream_id,
            method = ?method.as_deref().map(|m| String::from_utf8_lossy(m).to_string()),
            path = ?path,
            protocol = ?protocol,
            "request received"
        );

        // Check for Extended CONNECT
        if method.as_deref() == Some(b"CONNECT") {
            match protocol.as_deref() {
                Some("connect-udp") if config.udp_proxy.enabled => {
                    Self::handle_connect_udp(
                        h3,
                        quic,
                        stream_id,
                        path.as_deref().unwrap_or(""),
                        config,
                        udp_policy,
                        pending_udp_setups,
                    );
                    return;
                }
                Some("connect-ip") if config.ip_proxy.enabled => {
                    Self::handle_connect_ip_response(
                        h3,
                        quic,
                        stream_id,
                        pending_ip_setups,
                    );
                    return;
                }
                _ => {}
            }
        }

        // Default: 404 for anything we don't handle.
        Self::send_error_response(h3, quic, stream_id, 404);
    }

    /// Send 200 OK for CONNECT-IP and defer address allocation.
    fn handle_connect_ip_response(
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        stream_id: u64,
        pending_ip_setups: &mut Vec<u64>,
    ) {
        info!(stream_id, "CONNECT-IP request accepted");

        // Send 200 OK with Capsule-Protocol header (stream stays open).
        let headers = vec![
            quiche::h3::Header::new(b":status", b"200"),
            quiche::h3::Header::new(b"capsule-protocol", b"?1"),
        ];

        if let Err(e) = h3.send_response(quic, stream_id, &headers, false) {
            warn!(stream_id, %e, "failed to send CONNECT-IP 200");
            return;
        }

        // Defer address allocation to after we release the h3 borrow.
        pending_ip_setups.push(stream_id);
    }

    /// Handle a CONNECT-UDP request: parse, validate, respond 200, defer
    /// socket creation.
    fn handle_connect_udp(
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        stream_id: u64,
        path: &str,
        config: &ServerConfig,
        udp_policy: &TargetPolicy,
        pending_udp_setups: &mut Vec<(u64, uri::UdpTarget)>,
    ) {
        // Parse URI template
        let target = match uri::parse_udp_path(path, &config.udp_proxy.uri_template) {
            Ok(t) => t,
            Err(e) => {
                warn!(stream_id, %e, "bad CONNECT-UDP URI");
                Self::send_error_response(h3, quic, stream_id, 400);
                return;
            }
        };

        info!(stream_id, host = %target.host, port = target.port, "CONNECT-UDP");

        // Policy check: resolve and check against allow/deny lists.
        // For hostnames, we need to resolve first. We do a quick sync
        // resolve here for the policy check.
        match target.resolved_ips() {
            Ok(ips) => {
                if !udp_policy.all_allowed(&ips) {
                    warn!(
                        stream_id,
                        host = %target.host,
                        "target denied by policy"
                    );
                    Self::send_error_response(h3, quic, stream_id, 403);
                    return;
                }
            }
            Err(e) => {
                warn!(stream_id, %e, "DNS resolution failed for policy check");
                Self::send_error_response(h3, quic, stream_id, 502);
                return;
            }
        }

        // Send 200 OK with Capsule-Protocol header (stream stays open).
        let headers = vec![
            quiche::h3::Header::new(b":status", b"200"),
            quiche::h3::Header::new(b"capsule-protocol", b"?1"),
        ];

        if let Err(e) = h3.send_response(quic, stream_id, &headers, false) {
            warn!(stream_id, %e, "failed to send CONNECT-UDP 200");
            return;
        }

        // Defer actual socket creation to after we release the h3 borrow.
        pending_udp_setups.push((stream_id, target));
    }

    /// Relay QUIC DATAGRAMs from clients to target UDP sockets and TUN device.
    fn relay_client_datagrams(&mut self) {
        for client in self.connections.values_mut() {
            let mut dgram_buf = vec![0u8; MAX_DATAGRAM_SIZE];

            loop {
                let len = match client.quic.dgram_recv(&mut dgram_buf) {
                    Ok(len) => len,
                    Err(quiche::Error::Done) => break,
                    Err(e) => {
                        debug!(%e, "dgram_recv error");
                        break;
                    }
                };

                let dgram = match datagram::decode(&dgram_buf[..len]) {
                    Ok(d) => d,
                    Err(e) => {
                        debug!(%e, "malformed datagram");
                        continue;
                    }
                };

                // Only handle context_id=0 (raw payload)
                if dgram.context_id != 0 {
                    debug!(
                        context_id = dgram.context_id,
                        "ignoring non-zero context_id"
                    );
                    continue;
                }

                // Check UDP tunnels first.
                if let Some(tunnel) = client.udp_tunnels.get_mut(&dgram.stream_id) {
                    match tunnel.socket.try_send(&dgram.payload) {
                        Ok(_) => {
                            tunnel.last_activity = std::time::Instant::now();
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(e) => {
                            debug!(
                                stream_id = dgram.stream_id,
                                %e,
                                "send to target failed"
                            );
                        }
                    }
                    continue;
                }

                // Check IP tunnels — validate source and forward to TUN.
                if let Some(tunnel) = client.ip_tunnels.get_mut(&dgram.stream_id) {
                    // Validate source address.
                    match ip_packet::src_addr(&dgram.payload) {
                        Ok(src) => {
                            if !tunnel.owns_address(&src) {
                                debug!(
                                    stream_id = dgram.stream_id,
                                    %src,
                                    "spoofed source address, dropping"
                                );
                                continue;
                            }
                        }
                        Err(e) => {
                            debug!(
                                stream_id = dgram.stream_id,
                                %e,
                                "invalid IP header in client packet"
                            );
                            continue;
                        }
                    }

                    tunnel.last_activity = std::time::Instant::now();

                    // Write to TUN device.
                    if let Some(tun) = &self.tun {
                        match tun.try_send(&dgram.payload) {
                            Ok(_) => {}
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                            Err(e) => {
                                debug!(
                                    stream_id = dgram.stream_id,
                                    %e,
                                    "TUN write failed"
                                );
                            }
                        }
                    }
                    continue;
                }

                debug!(
                    stream_id = dgram.stream_id,
                    "datagram for unknown tunnel"
                );
            }
        }
    }

    /// Read from target UDP sockets and send QUIC DATAGRAMs to clients.
    async fn relay_target_datagrams(&mut self, buf: &mut [u8]) {
        for client in self.connections.values_mut() {
            let streams: Vec<u64> = client.udp_tunnels.keys().copied().collect();

            for stream_id in streams {
                let tunnel = client.udp_tunnels.get_mut(&stream_id).unwrap();

                // Non-blocking read from target socket
                loop {
                    match tunnel.socket.try_recv(buf) {
                        Ok(len) => {
                            tunnel.last_activity = std::time::Instant::now();

                            // Encode as HTTP Datagram and send via QUIC DATAGRAM
                            match datagram::encode_payload(stream_id, &buf[..len]) {
                                Ok(encoded) => {
                                    if let Err(e) =
                                        client.quic.dgram_send(&encoded)
                                    {
                                        if e != quiche::Error::Done {
                                            debug!(
                                                stream_id,
                                                %e,
                                                "dgram_send failed"
                                            );
                                        }
                                        break;
                                    }
                                }
                                Err(e) => {
                                    debug!(stream_id, %e, "datagram encode failed");
                                    break;
                                }
                            }
                        }
                        Err(ref e)
                            if e.kind() == std::io::ErrorKind::WouldBlock =>
                        {
                            break;
                        }
                        Err(e) => {
                            debug!(stream_id, %e, "target recv failed");
                            break;
                        }
                    }
                }
            }
        }
    }

    /// Read IP packets from TUN device and route them to the correct client.
    fn relay_tun_inbound(&mut self, buf: &mut [u8]) {
        let tun = match &self.tun {
            Some(t) => t,
            None => return,
        };

        // Non-blocking reads from TUN.
        loop {
            let len = match tun.try_recv(buf) {
                Ok(len) => len,
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    debug!(%e, "TUN recv error");
                    break;
                }
            };

            let pkt = &buf[..len];

            // Extract destination IP from the packet header.
            let dst = match ip_packet::dst_addr(pkt) {
                Ok(addr) => addr,
                Err(e) => {
                    debug!(%e, "invalid IP header from TUN");
                    continue;
                }
            };

            // Look up the tunnel owner in the routing table.
            let owner = match self.routing_table.lookup(&dst) {
                Some(o) => *o,
                None => {
                    // No route — packet is for an address we don't manage.
                    continue;
                }
            };

            // Find the connection that owns this tunnel.
            let client = self
                .conn_index_map
                .iter()
                .find(|&(_, &idx)| idx == owner.conn_id)
                .and_then(|(cid, _)| self.connections.get_mut(cid));

            let client = match client {
                Some(c) => c,
                None => {
                    debug!(
                        conn_id = owner.conn_id,
                        "TUN packet for unknown connection"
                    );
                    continue;
                }
            };

            // Update tunnel activity and send DATAGRAM to client.
            if let Some(tunnel) = client.ip_tunnels.get_mut(&owner.stream_id) {
                tunnel.last_activity = std::time::Instant::now();

                match datagram::encode_payload(owner.stream_id, pkt) {
                    Ok(encoded) => {
                        if let Err(e) = client.quic.dgram_send(&encoded) {
                            if e != quiche::Error::Done {
                                debug!(
                                    stream_id = owner.stream_id,
                                    %e,
                                    "dgram_send for TUN packet failed"
                                );
                            }
                            break;
                        }
                    }
                    Err(e) => {
                        debug!(
                            stream_id = owner.stream_id,
                            %e,
                            "datagram encode for TUN packet failed"
                        );
                    }
                }
            }
        }
    }

    /// Close tunnels that have been idle too long.
    fn cleanup_idle_tunnels(&mut self, timeout: Duration) {
        // Collect idle IP tunnel info so we can clean up after the loop.
        let mut idle_ip_tunnels: Vec<(quiche::ConnectionId<'static>, u64, u64)> =
            Vec::new();

        for (conn_id, client) in &mut self.connections {
            // UDP tunnels
            let idle_udp: Vec<u64> = client
                .udp_tunnels
                .iter()
                .filter(|(_, t)| t.is_idle(timeout))
                .map(|(id, _)| *id)
                .collect();

            for stream_id in idle_udp {
                info!(stream_id, "closing idle UDP tunnel");
                client.udp_tunnels.remove(&stream_id);

                if let Some(h3) = &mut client.h3 {
                    h3.send_body(&mut client.quic, stream_id, b"", true)
                        .ok();
                }
            }

            // IP tunnels
            let idle_ip: Vec<u64> = client
                .ip_tunnels
                .iter()
                .filter(|(_, t)| t.is_idle(timeout))
                .map(|(id, _)| *id)
                .collect();

            for stream_id in &idle_ip {
                info!(stream_id, "closing idle IP tunnel");
                if let Some(h3) = &mut client.h3 {
                    h3.send_body(&mut client.quic, *stream_id, b"", true)
                        .ok();
                }
            }

            if !idle_ip.is_empty() {
                let conn_idx = self
                    .conn_index_map
                    .get(conn_id)
                    .copied()
                    .unwrap_or(0);
                for stream_id in idle_ip {
                    idle_ip_tunnels.push((conn_id.clone(), stream_id, conn_idx));
                }
            }
        }

        // Now tear down idle IP tunnels (needs &mut self fields).
        for (conn_id, stream_id, conn_idx) in idle_ip_tunnels {
            if let Some(client) = self.connections.get_mut(&conn_id) {
                Self::teardown_ip_tunnel(
                    &mut self.address_pool,
                    &mut self.routing_table,
                    client,
                    stream_id,
                    conn_idx,
                );
            }
        }
    }

    /// Send an HTTP error response.
    fn send_error_response(
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        stream_id: u64,
        status: u16,
    ) {
        let headers = vec![
            quiche::h3::Header::new(b":status", status.to_string().as_bytes()),
            quiche::h3::Header::new(b"content-length", b"0"),
        ];

        if let Err(e) = h3.send_response(quic, stream_id, &headers, true) {
            warn!(stream_id, %e, "failed to send response");
        }
    }

    /// Drive all connections: handle timers and flush outgoing packets.
    async fn drive_connections(&mut self, out: &mut [u8]) {
        for (_, client) in &mut self.connections {
            client.quic.on_timeout();

            // Flush outgoing QUIC packets.
            loop {
                let (write, send_info) = match client.quic.send(out) {
                    Ok(v) => v,
                    Err(quiche::Error::Done) => break,
                    Err(e) => {
                        error!(%e, "quiche send error");
                        client.quic.close(false, 0x1, b"send error").ok();
                        break;
                    }
                };

                if let Err(e) =
                    self.socket.send_to(&out[..write], send_info.to).await
                {
                    warn!(%e, "socket send error");
                }
            }
        }
    }
}
