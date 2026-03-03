use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use quiche::h3::NameValue;
use ring::rand::SecureRandom;
use tracing::{error, info, warn};

const MAX_DATAGRAM_SIZE: usize = 1350;
const BUF_SIZE: usize = 65535;

// ---------------------------------------------------------------------------
// QUIC + H3 test client
// ---------------------------------------------------------------------------

struct Client {
    socket: UdpSocket,
    quic: quiche::Connection,
    h3: Option<quiche::h3::Connection>,
    peer: SocketAddr,
    local: SocketAddr,
}

impl Client {
    fn connect(server_addr: &str) -> Result<Self> {
        let peer: SocketAddr = server_addr.parse().context("parse server addr")?;

        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.connect(peer)?;
        let local = socket.local_addr()?;

        let mut scid_buf = [0u8; quiche::MAX_CONN_ID_LEN];
        ring::rand::SystemRandom::new()
            .fill(&mut scid_buf)
            .map_err(|_| anyhow::anyhow!("RNG failed"))?;
        let scid = quiche::ConnectionId::from_ref(&scid_buf);

        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
        config.verify_peer(false);
        config.set_application_protos(quiche::h3::APPLICATION_PROTOCOL)?;
        config.set_max_idle_timeout(30_000);
        config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_initial_max_data(10_000_000);
        config.set_initial_max_stream_data_bidi_local(1_000_000);
        config.set_initial_max_stream_data_bidi_remote(1_000_000);
        config.set_initial_max_stream_data_uni(1_000_000);
        config.set_initial_max_streams_bidi(128);
        config.set_initial_max_streams_uni(100);
        config.enable_dgram(true, 1000, 1000);

        let quic = quiche::connect(Some("server"), &scid, local, peer, &mut config)?;

        Ok(Client { socket, quic, h3: None, peer, local })
    }

    /// Send all pending QUIC packets to the network.
    fn flush(&mut self) -> Result<()> {
        let mut out = [0u8; MAX_DATAGRAM_SIZE];
        loop {
            match self.quic.send(&mut out) {
                Ok((len, _)) => {
                    self.socket.send(&out[..len])?;
                }
                Err(quiche::Error::Done) => return Ok(()),
                Err(e) => bail!("QUIC send: {e}"),
            }
        }
    }

    /// Receive one packet from the network and feed it to QUIC.
    fn recv_once(&mut self) -> Result<bool> {
        let timeout = self
            .quic
            .timeout()
            .unwrap_or(Duration::from_millis(50))
            .max(Duration::from_millis(1));
        self.socket.set_read_timeout(Some(timeout))?;

        let mut buf = [0u8; BUF_SIZE];
        match self.socket.recv(&mut buf) {
            Ok(len) => {
                let info = quiche::RecvInfo { from: self.peer, to: self.local };
                match self.quic.recv(&mut buf[..len], info) {
                    Ok(_) | Err(quiche::Error::Done) => {}
                    Err(e) => bail!("QUIC recv: {e}"),
                }
                Ok(true)
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                self.quic.on_timeout();
                Ok(false)
            }
            Err(e) => bail!("socket recv: {e}"),
        }
    }

    /// One round of flush → recv → flush.
    fn drive(&mut self) -> Result<()> {
        self.flush()?;
        self.recv_once()?;
        self.flush()?;
        Ok(())
    }

    /// Complete the QUIC handshake.
    fn handshake(&mut self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            self.flush()?;
            if self.quic.is_established() {
                return Ok(());
            }
            if Instant::now() > deadline {
                bail!("handshake timeout");
            }
            self.recv_once()?;
        }
    }

    /// Create the HTTP/3 layer on top of the QUIC connection.
    fn init_h3(&mut self) -> Result<()> {
        let h3_config = quiche::h3::Config::new()?;
        let h3 =
            quiche::h3::Connection::with_transport(&mut self.quic, &h3_config)?;
        self.h3 = Some(h3);
        Ok(())
    }

    /// Send an HTTP/3 request; returns the stream ID.
    fn send_request(
        &mut self,
        headers: &[quiche::h3::Header],
        fin: bool,
    ) -> Result<u64> {
        let h3 = self.h3.as_mut().context("H3 not initialised")?;
        let stream_id = h3.send_request(&mut self.quic, headers, fin)?;
        self.flush()?;
        Ok(stream_id)
    }

    /// Poll until we get response headers for any stream, return (stream_id, status).
    fn poll_response(&mut self, timeout: Duration) -> Result<(u64, u16)> {
        let deadline = Instant::now() + timeout;
        loop {
            let h3 = self.h3.as_mut().context("H3 not initialised")?;
            loop {
                match h3.poll(&mut self.quic) {
                    Ok((sid, quiche::h3::Event::Headers { list, .. })) => {
                        let status = list
                            .iter()
                            .find(|h| h.name() == b":status")
                            .map(|h| {
                                String::from_utf8_lossy(h.value())
                                    .parse::<u16>()
                            })
                            .transpose()
                            .map_err(|e| anyhow::anyhow!("bad :status: {e}"))?
                            .context("missing :status")?;
                        return Ok((sid, status));
                    }
                    Ok(_) => continue,
                    Err(quiche::h3::Error::Done) => break,
                    Err(e) => bail!("H3 poll: {e}"),
                }
            }

            if Instant::now() > deadline {
                bail!("response timeout");
            }
            self.drive()?;
        }
    }

    /// Send a QUIC DATAGRAM carrying an HTTP Datagram for the given stream.
    fn send_dgram(&mut self, stream_id: u64, payload: &[u8]) -> Result<()> {
        let encoded = masque::datagram::encode_payload(stream_id, payload)
            .map_err(|e| anyhow::anyhow!("encode dgram: {e}"))?;
        self.quic.dgram_send(&encoded)?;
        self.flush()?;
        Ok(())
    }

    /// Wait for a QUIC DATAGRAM and decode it as an HTTP Datagram.
    fn recv_dgram(
        &mut self,
        timeout: Duration,
    ) -> Result<masque::datagram::HttpDatagram> {
        let deadline = Instant::now() + timeout;
        loop {
            let mut buf = [0u8; BUF_SIZE];
            match self.quic.dgram_recv(&mut buf) {
                Ok(len) => {
                    return masque::datagram::decode(&buf[..len])
                        .map_err(|e| anyhow::anyhow!("decode dgram: {e}"));
                }
                Err(quiche::Error::Done) => {}
                Err(e) => bail!("dgram recv: {e}"),
            }

            if Instant::now() > deadline {
                bail!("datagram timeout");
            }
            self.drive()?;
        }
    }
}

// ---------------------------------------------------------------------------
// Server readiness check
// ---------------------------------------------------------------------------

fn wait_for_server(server_addr: &str) -> Result<()> {
    let mut delay = Duration::from_millis(250);

    for attempt in 1..=20 {
        info!(attempt, "checking server readiness…");
        match Client::connect(server_addr).and_then(|mut c| {
            c.handshake()?;
            c.init_h3()?;
            Ok(())
        }) {
            Ok(()) => {
                info!("server ready");
                return Ok(());
            }
            Err(e) => {
                warn!(attempt, %e, "not ready, retrying");
                std::thread::sleep(delay);
                delay = (delay * 2).min(Duration::from_secs(5));
            }
        }
    }
    bail!("server not ready after 20 attempts")
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn connect_udp_headers(
    server_addr: &str,
    target_host: &str,
    target_port: &str,
) -> Vec<quiche::h3::Header> {
    let path = format!(
        "/.well-known/masque/udp/{target_host}/{target_port}/"
    );
    vec![
        quiche::h3::Header::new(b":method", b"CONNECT"),
        quiche::h3::Header::new(b":protocol", b"connect-udp"),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(b":authority", server_addr.as_bytes()),
        quiche::h3::Header::new(b":path", path.as_bytes()),
        quiche::h3::Header::new(b"capsule-protocol", b"?1"),
    ]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn test_connect_udp_happy_path(
    server_addr: &str,
    echo_addr: &str,
) -> Result<()> {
    let mut client = Client::connect(server_addr)?;
    client.handshake()?;
    client.init_h3()?;

    // Split echo address into host:port
    let (echo_host, echo_port) = echo_addr
        .rsplit_once(':')
        .context("bad ECHO_SERVER_ADDR")?;

    let headers = connect_udp_headers(server_addr, echo_host, echo_port);
    let stream_id = client.send_request(&headers, false)?;

    let (_sid, status) = client.poll_response(Duration::from_secs(5))?;
    if status != 200 {
        bail!("expected 200, got {status}");
    }

    // Give the server a moment to set up the UDP tunnel socket.
    std::thread::sleep(Duration::from_millis(100));

    // Send a datagram through the tunnel and verify echo.
    let payload = b"hello masque e2e";
    client.send_dgram(stream_id, payload)?;

    let dgram = client.recv_dgram(Duration::from_secs(5))?;
    if dgram.payload != payload {
        bail!(
            "payload mismatch: {:?} vs {:?}",
            dgram.payload,
            payload.to_vec()
        );
    }

    info!("datagram round-trip OK");
    Ok(())
}

fn test_connect_udp_policy_deny(
    server_addr: &str,
    _echo_addr: &str,
) -> Result<()> {
    let mut client = Client::connect(server_addr)?;
    client.handshake()?;
    client.init_h3()?;

    let headers = connect_udp_headers(server_addr, "127.0.0.1", "53");
    let _stream_id = client.send_request(&headers, false)?;

    let (_sid, status) = client.poll_response(Duration::from_secs(5))?;
    if status != 403 {
        bail!("expected 403, got {status}");
    }
    Ok(())
}

fn test_connect_udp_bad_uri(
    server_addr: &str,
    _echo_addr: &str,
) -> Result<()> {
    let mut client = Client::connect(server_addr)?;
    client.handshake()?;
    client.init_h3()?;

    let headers = vec![
        quiche::h3::Header::new(b":method", b"CONNECT"),
        quiche::h3::Header::new(b":protocol", b"connect-udp"),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(b":authority", server_addr.as_bytes()),
        quiche::h3::Header::new(b":path", b"/bad/path"),
        quiche::h3::Header::new(b"capsule-protocol", b"?1"),
    ];
    let _stream_id = client.send_request(&headers, false)?;

    let (_sid, status) = client.poll_response(Duration::from_secs(5))?;
    if status != 400 {
        bail!("expected 400, got {status}");
    }
    Ok(())
}

fn test_non_connect_404(
    server_addr: &str,
    _echo_addr: &str,
) -> Result<()> {
    let mut client = Client::connect(server_addr)?;
    client.handshake()?;
    client.init_h3()?;

    let headers = vec![
        quiche::h3::Header::new(b":method", b"GET"),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(b":authority", server_addr.as_bytes()),
        quiche::h3::Header::new(b":path", b"/"),
    ];
    let _stream_id = client.send_request(&headers, true)?;

    let (_sid, status) = client.poll_response(Duration::from_secs(5))?;
    if status != 404 {
        bail!("expected 404, got {status}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "masque_e2e=info".parse().unwrap()),
        )
        .init();

    let server_addr = std::env::var("MASQUE_SERVER_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:4433".into());
    let echo_addr = std::env::var("ECHO_SERVER_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:9999".into());

    info!(%server_addr, %echo_addr, "MASQUE E2E test suite");

    if let Err(e) = wait_for_server(&server_addr) {
        error!(%e, "server not ready");
        std::process::exit(1);
    }

    let tests: &[(&str, fn(&str, &str) -> Result<()>)] = &[
        ("connect_udp_happy_path", test_connect_udp_happy_path),
        ("connect_udp_policy_deny", test_connect_udp_policy_deny),
        ("connect_udp_bad_uri", test_connect_udp_bad_uri),
        ("non_connect_404", test_non_connect_404),
    ];

    let mut passed = 0u32;
    let mut failed = 0u32;

    for (name, test_fn) in tests {
        info!("--- {name} ---");
        match test_fn(&server_addr, &echo_addr) {
            Ok(()) => {
                info!("{name}: PASS");
                passed += 1;
            }
            Err(e) => {
                error!("{name}: FAIL — {e:#}");
                failed += 1;
            }
        }
    }

    info!("{passed} passed, {failed} failed");
    if failed > 0 {
        std::process::exit(1);
    }
}
