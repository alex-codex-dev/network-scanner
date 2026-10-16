//! Linux ICMP Echo over ping sockets.

use std::io;

#[cfg(test)]
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
#[cfg(test)]
use std::{mem::MaybeUninit, net::Ipv4Addr, time::Duration};

const ECHO_REQUEST: u8 = 8;
#[cfg(test)]
const ECHO_REPLY: u8 = 0;

#[derive(Debug, PartialEq, Eq)]
pub(super) struct EchoMessage {
    pub(super) kind: u8,
    pub(super) code: u8,
    pub(super) identifier: u16,
    pub(super) sequence: u16,
    pub(super) payload: Vec<u8>,
}

pub(super) fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for chunk in bytes.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from(chunk[0]) << 8
        };
        sum += u32::from(word);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub(super) fn build_echo_request(identifier: u16, sequence: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(8 + payload.len());
    packet.extend_from_slice(&[ECHO_REQUEST, 0, 0, 0]);
    packet.extend_from_slice(&identifier.to_be_bytes());
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(payload);
    let value = checksum(&packet).to_be_bytes();
    packet[2..4].copy_from_slice(&value);
    packet
}

pub(super) fn parse_echo_message(packet: &[u8]) -> io::Result<EchoMessage> {
    if packet.len() < 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "short ICMP message",
        ));
    }
    if checksum(packet) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid ICMP checksum",
        ));
    }
    Ok(EchoMessage {
        kind: packet[0],
        code: packet[1],
        identifier: u16::from_be_bytes([packet[4], packet[5]]),
        sequence: u16::from_be_bytes([packet[6], packet[7]]),
        payload: packet[8..].to_vec(),
    })
}

#[cfg(test)]
fn open_ping_socket() -> io::Result<Socket> {
    Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))
}

#[cfg(test)]
fn echo_once(
    target: Ipv4Addr,
    identifier: u16,
    sequence: u16,
    timeout: Duration,
) -> io::Result<EchoMessage> {
    let socket = open_ping_socket()?;
    socket.set_read_timeout(Some(timeout))?;
    let payload = b"rust-scanner-v3";
    let request = build_echo_request(identifier, sequence, payload);
    let destination = SockAddr::from(std::net::SocketAddrV4::new(target, 0));
    socket.send_to(&request, &destination)?;

    let mut response = [MaybeUninit::uninit(); 4096];
    loop {
        let (length, source) = socket.recv_from(&mut response)?;
        if source
            .as_socket_ipv4()
            .is_some_and(|addr| *addr.ip() == target)
        {
            // `recv_from` initializes exactly the first `length` bytes.
            let bytes =
                unsafe { std::slice::from_raw_parts(response.as_ptr().cast::<u8>(), length) };
            let message = parse_echo_message(bytes)?;
            if message.kind == ECHO_REPLY && message.code == 0 && message.sequence == sequence {
                return Ok(message);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_echo_request_with_valid_checksum_and_fields() {
        let packet = build_echo_request(0x1234, 7, b"abc");
        assert_eq!(packet[0..2], [ECHO_REQUEST, 0]);
        assert_eq!(checksum(&packet), 0);
        assert_eq!(
            parse_echo_message(&packet).unwrap(),
            EchoMessage {
                kind: ECHO_REQUEST,
                code: 0,
                identifier: 0x1234,
                sequence: 7,
                payload: b"abc".to_vec(),
            }
        );
    }

    #[test]
    fn parses_echo_reply_and_rejects_malformed_messages() {
        let reply = build_echo_request(4, 9, b"payload");
        let mut reply = reply;
        reply[0] = ECHO_REPLY;
        reply[2..4].fill(0);
        let checksum_bytes = checksum(&reply).to_be_bytes();
        reply[2..4].copy_from_slice(&checksum_bytes);
        let parsed = parse_echo_message(&reply).unwrap();
        assert_eq!(
            (parsed.kind, parsed.code, parsed.sequence),
            (ECHO_REPLY, 0, 9)
        );
        assert!(parse_echo_message(&[0; 7]).is_err());
        reply[8] ^= 1;
        assert_eq!(
            parse_echo_message(&reply).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires a Linux ICMP ping socket; this sandbox denies socket creation"]
    fn one_echo_round_trip_to_localhost() {
        let reply = echo_once(Ipv4Addr::LOCALHOST, 0x5153, 1, Duration::from_secs(2)).unwrap();
        assert_eq!((reply.kind, reply.code, reply.sequence), (ECHO_REPLY, 0, 1));
        assert_eq!(reply.payload, b"rust-scanner-v3");
    }
}
