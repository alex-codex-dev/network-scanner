//! Multiplexed ICMP echo engine used by the explicit `--engine icmp` CLI option.

use std::{
    collections::BTreeMap,
    io,
    net::Ipv4Addr,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

const PAYLOAD_TAG: &[u8] = b"network-scanner-v3:";
static SCAN_NONCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostState {
    Reachable,
    TimedOut,
}

#[derive(Debug)]
pub enum ScanError {
    InvalidConcurrency,
    TooManyHosts,
    Socket(io::Error),
}

/// Transport boundary permits deterministic scheduler tests without network access.
pub trait Transport {
    fn send(&mut self, target: Ipv4Addr, sequence: u16, payload: &[u8]) -> io::Result<()>;
    fn receive(&mut self, wait: Duration) -> io::Result<Option<Reply>>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub source: Ipv4Addr,
    pub sequence: u16,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostResult {
    pub address: Ipv4Addr,
    pub state: HostState,
}

/// Runs requests with at most `concurrency` outstanding. Socket failures abort the scan;
/// unanswered hosts are ordinary per-host timeouts. Results retain input order.
pub fn scan<T: Transport>(
    transport: &mut T,
    hosts: &[Ipv4Addr],
    timeout: Duration,
    concurrency: usize,
) -> Result<Vec<HostResult>, ScanError> {
    if concurrency == 0 {
        return Err(ScanError::InvalidConcurrency);
    }
    if hosts.len() > u16::MAX as usize {
        return Err(ScanError::TooManyHosts);
    }
    let mut results: Vec<Option<HostState>> = vec![None; hosts.len()];
    let mut pending: BTreeMap<u16, (usize, Instant, Vec<u8>)> = BTreeMap::new();
    let mut next = 0usize;
    let mut sequence = 1u16;
    let nonce = SCAN_NONCE.fetch_add(1, Ordering::Relaxed);
    while next < hosts.len() || !pending.is_empty() {
        while next < hosts.len() && pending.len() < concurrency {
            let seq = sequence;
            sequence = sequence.wrapping_add(1);
            let mut payload = PAYLOAD_TAG.to_vec();
            payload.extend_from_slice(&nonce.to_be_bytes());
            payload.extend_from_slice(&(next as u16).to_be_bytes());
            if let Err(error) = transport.send(hosts[next], seq, &payload) {
                return Err(ScanError::Socket(error));
            }
            pending.insert(seq, (next, Instant::now() + timeout, payload));
            next += 1;
        }
        let now = Instant::now();
        for (idx, deadline, _) in pending.values() {
            if *deadline <= now {
                results[*idx] = Some(HostState::TimedOut);
            }
        }
        pending.retain(|_, (_, deadline, _)| *deadline > now);
        if pending.is_empty() {
            continue;
        }
        let wait = pending
            .values()
            .map(|(_, deadline, _)| deadline.saturating_duration_since(Instant::now()))
            .min()
            .unwrap_or(Duration::ZERO);
        let reply = match transport.receive(wait) {
            Ok(reply) => reply,
            Err(error)
                if error.kind() == io::ErrorKind::TimedOut
                    || error.kind() == io::ErrorKind::WouldBlock =>
            {
                None
            }
            Err(error) => return Err(ScanError::Socket(error)),
        };
        if let Some(reply) = reply
            && let Some((idx, deadline, expected)) = pending.get(&reply.sequence)
            && *deadline > Instant::now()
            && hosts[*idx] == reply.source
            && *expected == reply.payload
        {
            results[*idx] = Some(HostState::Reachable);
            pending.remove(&reply.sequence);
        }
    }
    Ok(hosts
        .iter()
        .copied()
        .zip(
            results
                .into_iter()
                .map(|r| r.unwrap_or(HostState::TimedOut)),
        )
        .map(|(address, state)| HostResult { address, state })
        .collect())
}

#[cfg(target_os = "linux")]
pub mod linux {
    use super::*;
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    use std::{mem::MaybeUninit, net::SocketAddrV4};

    /// Linux ping sockets own the ICMP identifier; the kernel may rewrite the request's
    /// identifier and return it in replies. Correlation therefore deliberately uses source,
    /// sequence and unpredictable-per-request payload data.
    pub struct PingSocket {
        socket: Socket,
    }
    impl PingSocket {
        pub fn open() -> io::Result<Self> {
            Ok(Self {
                socket: Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))?,
            })
        }
    }
    impl Transport for PingSocket {
        fn send(&mut self, target: Ipv4Addr, sequence: u16, payload: &[u8]) -> io::Result<()> {
            let packet = crate::icmp_linux::build_echo_request(0, sequence, payload);
            self.socket
                .send_to(&packet, &SockAddr::from(SocketAddrV4::new(target, 0)))
                .map(|_| ())
        }
        fn receive(&mut self, wait: Duration) -> io::Result<Option<Reply>> {
            self.socket
                .set_read_timeout(Some(wait.max(Duration::from_micros(1))))?;
            let mut buffer = [MaybeUninit::uninit(); 4096];
            let (length, source) = self.socket.recv_from(&mut buffer)?;
            let Some(source) = source.as_socket_ipv4() else {
                return Ok(None);
            };
            // recv_from initializes exactly the reported bytes.
            let bytes = unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), length) };
            let message = match crate::icmp_linux::parse_echo_message(bytes) {
                Ok(message) => message,
                Err(_) => return Ok(None),
            };
            if message.kind != 0 || message.code != 0 {
                return Ok(None);
            }
            let _kernel_socket_identifier = message.identifier;
            Ok(Some(Reply {
                source: *source.ip(),
                sequence: message.sequence,
                payload: message.payload,
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    struct Mock {
        sends: Vec<(Ipv4Addr, u16, Vec<u8>)>,
        replies: VecDeque<io::Result<Option<Reply>>>,
        max_in_flight: usize,
    }
    impl Transport for Mock {
        fn send(&mut self, ip: Ipv4Addr, seq: u16, payload: &[u8]) -> io::Result<()> {
            self.sends.push((ip, seq, payload.to_vec()));
            self.max_in_flight = self.max_in_flight.max(self.sends.len());
            Ok(())
        }
        fn receive(&mut self, _: Duration) -> io::Result<Option<Reply>> {
            let mut reply = self.replies.pop_front().unwrap_or(Ok(None))?;
            if let Some(reply) = &mut reply
                && reply.payload == b"VALID"
            {
                reply.payload = self
                    .sends
                    .iter()
                    .find(|(_, sequence, _)| *sequence == reply.sequence)
                    .unwrap()
                    .2
                    .clone();
            }
            Ok(reply)
        }
    }
    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn correlates_out_of_order_and_ignores_duplicate_wrong_source_and_payload() {
        let ips = [ip("127.0.0.1"), ip("127.0.0.2")];
        let payload = [PAYLOAD_TAG, &[0, 1]].concat();
        let mut m = Mock {
            sends: vec![],
            max_in_flight: 0,
            replies: VecDeque::from([
                Ok(Some(Reply {
                    source: ips[0],
                    sequence: 2,
                    payload: payload.clone(),
                })),
                Ok(Some(Reply {
                    source: ips[1],
                    sequence: 2,
                    payload: b"VALID".to_vec(),
                })),
                Ok(Some(Reply {
                    source: ips[1],
                    sequence: 2,
                    payload: b"wrong-payload".to_vec(),
                })),
                Ok(Some(Reply {
                    source: ips[1],
                    sequence: 2,
                    payload: b"VALID".to_vec(),
                })),
                Ok(None),
            ]),
        };
        let result = scan(&mut m, &ips, Duration::from_millis(20), 2).unwrap();
        assert_eq!(
            result.iter().map(|r| r.state).collect::<Vec<_>>(),
            [HostState::TimedOut, HostState::Reachable]
        );
        assert_eq!(m.sends.len(), 2);
    }
    #[test]
    fn bounds_pending_requests_and_propagates_socket_errors() {
        let ips = [ip("127.0.0.1"), ip("127.0.0.2"), ip("127.0.0.3")];
        let mut m = Mock {
            sends: vec![],
            replies: VecDeque::from([Ok(None), Ok(None), Ok(None)]),
            max_in_flight: 0,
        };
        assert!(scan(&mut m, &ips, Duration::from_nanos(1), 2).is_ok());
        assert_eq!(m.sends.len(), 3);
        let mut bad = Mock {
            sends: vec![],
            replies: VecDeque::from([Err(io::ErrorKind::BrokenPipe.into())]),
            max_in_flight: 0,
        };
        assert!(matches!(
            scan(&mut bad, &ips[..1], Duration::from_secs(1), 1),
            Err(ScanError::Socket(_))
        ));
        assert!(matches!(
            scan(&mut bad, &ips, Duration::from_secs(1), 0),
            Err(ScanError::InvalidConcurrency)
        ));
    }
}

#[cfg(all(test, target_os = "linux"))]
mod integration_tests {
    use super::{HostState, linux::PingSocket, scan};
    use std::{net::Ipv4Addr, time::Duration};

    #[test]
    #[ignore = "requires Linux ping sockets and reachable loopback aliases; run manually outside the sandbox"]
    fn scans_two_loopback_addresses_with_one_ping_socket() {
        let hosts = [Ipv4Addr::LOCALHOST, Ipv4Addr::new(127, 0, 0, 2)];
        let mut socket = PingSocket::open().unwrap();
        let results = scan(&mut socket, &hosts, Duration::from_secs(1), 2).unwrap();

        assert_eq!(
            results
                .iter()
                .map(|result| result.address)
                .collect::<Vec<_>>(),
            hosts
        );
        assert!(
            results
                .iter()
                .all(|result| result.state == HostState::Reachable)
        );
    }
}
