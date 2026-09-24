use std::{
    io,
    net::{Ipv4Addr, SocketAddrV4},
    rc::Rc,
};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use super::{Method, ProbeId, Replies, Reply, ReplyKind, ReplyQueue, Unreachable};
use crate::net::{MIN_IPV4_HEADER_LEN, internet_checksum};

const ECHO_HEADER_LEN: usize = 8;

const ECHO_REQUEST: u8 = 8;
const DEST_UNREACH: u8 = 3;
const TIME_EXCEEDED: u8 = 11;

/// The sequence number, which sits at the same offset in an echo reply as in
/// the request a router quotes back.
fn sequence(quoted: &[u8]) -> Option<ProbeId> {
    let sequence = quoted.get(6..8)?.try_into().ok()?;
    Some(ProbeId(u16::from_be_bytes(sequence)))
}

struct EchoReplies;

impl Replies for EchoReplies {
    fn identify(&self, reply: &Reply<'_>) -> Option<ProbeId> {
        sequence(reply.quoted)
    }

    fn classify(&self, _reply: &Reply<'_>) -> ReplyKind {
        // Only the target answers an echo request.
        ReplyKind::Destination
    }

    fn ignores_read_error(&self, error: i32) -> bool {
        error == -libc::EHOSTUNREACH
    }
}

struct ErrorReplies;

impl Replies for ErrorReplies {
    fn identify(&self, reply: &Reply<'_>) -> Option<ProbeId> {
        sequence(reply.quoted)
    }

    fn classify(&self, reply: &Reply<'_>) -> ReplyKind {
        let Some(error) = reply.error else {
            return ReplyKind::Unreachable(Unreachable::Marker("!?"));
        };

        let unreachable = match (error.icmp_type, error.icmp_code) {
            (TIME_EXCEEDED, 0) => return ReplyKind::Hop,
            // "Port Unreachable" should only come from the destination.
            (DEST_UNREACH, 3) => return ReplyKind::Destination,
            (DEST_UNREACH, 0 | 6 | 8 | 11) => Unreachable::Marker("!N"),
            (DEST_UNREACH, 1 | 7 | 12) => Unreachable::Marker("!H"),
            (DEST_UNREACH, 9 | 10 | 13) => Unreachable::Marker("!X"),
            (DEST_UNREACH, 2) => Unreachable::Marker("!P"),
            (DEST_UNREACH, 4) => Unreachable::TooBig { mtu: error.info },
            (DEST_UNREACH, 5) => Unreachable::Marker("!S"),
            (DEST_UNREACH, 14) => Unreachable::Marker("!V"),
            (DEST_UNREACH, 15) => Unreachable::Marker("!C"),
            (DEST_UNREACH, code) => Unreachable::Code(code),
            (icmp_type, code) => Unreachable::Other { icmp_type, code },
        };

        ReplyKind::Unreachable(unreachable)
    }
}

pub struct Icmp {
    target: Ipv4Addr,
    payload_len: usize,
}

impl Icmp {
    /// This method is IPv4-only.
    const MIN_PACKET_LEN: usize = MIN_IPV4_HEADER_LEN + ECHO_HEADER_LEN;

    /// `packet_len` counts the whole IP packet, and must be large enough to
    /// hold the headers.
    pub fn try_new(target: Ipv4Addr, packet_len: usize) -> anyhow::Result<Self> {
        let Some(payload_len) = packet_len.checked_sub(Self::MIN_PACKET_LEN) else {
            anyhow::bail!(
                "packet size must be at least {} bytes for method icmp",
                Self::MIN_PACKET_LEN
            );
        };

        Ok(Self {
            target,
            payload_len,
        })
    }
}

impl Method for Icmp {
    fn open(&self) -> io::Result<(Rc<Socket>, Vec<ReplyQueue>)> {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))?;
        socket.bind(&SockAddr::from(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)))?;
        let socket = Rc::new(socket);

        Ok((
            socket.clone(),
            vec![
                ReplyQueue {
                    socket: socket.clone(),
                    err_queue: false,
                    replies: Box::new(EchoReplies),
                },
                ReplyQueue {
                    socket,
                    err_queue: true,
                    replies: Box::new(ErrorReplies),
                },
            ],
        ))
    }

    fn probe(&self, id: ProbeId) -> (Vec<u8>, SockAddr) {
        // Let the kernel assign the ICMP identifier.
        let mut packet = vec![0; ECHO_HEADER_LEN + self.payload_len];
        packet[0] = ECHO_REQUEST;
        // We use the sequence number to store the probe's identifier.
        packet[6..8].copy_from_slice(&id.0.to_be_bytes());

        let checksum = internet_checksum(&packet).to_be_bytes();
        packet[2..4].copy_from_slice(&checksum);

        (packet, SockAddr::from(SocketAddrV4::new(self.target, 0)))
    }

    fn max_reply_len(&self) -> usize {
        // An echo reply echoes our payload back with the same header length.
        ECHO_HEADER_LEN + self.payload_len
    }
}

#[cfg(test)]
mod test {
    use std::net::{Ipv4Addr, SocketAddrV4};

    use socket2::SockAddr;

    use crate::{
        method::{
            Icmp, Method, ProbeId, Replies, Reply, ReplyKind, Unreachable,
            icmp::{DEST_UNREACH, ECHO_REQUEST, EchoReplies, ErrorReplies, TIME_EXCEEDED},
        },
        net::{IcmpError, MIN_IPV4_HEADER_LEN, internet_checksum},
    };

    const TARGET: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
    const PACKET_LENGTH: usize = 60;
    const PROBE_ID: ProbeId = ProbeId(1234);

    const ECHO_REPLY: u8 = 0;
    /// An ICMP type this method does not handle.
    const SOURCE_QUENCH: u8 = 4;

    fn icmp_error(icmp_type: u8, icmp_code: u8) -> Option<IcmpError> {
        Some(IcmpError {
            icmp_type,
            icmp_code,
            info: 0,
        })
    }

    fn reply(quoted: &[u8], error: Option<IcmpError>) -> Reply<'_> {
        Reply {
            source: None,
            quoted,
            error,
        }
    }

    fn probe() -> Vec<u8> {
        let (packet, _) = Icmp::try_new(TARGET, PACKET_LENGTH)
            .unwrap()
            .probe(PROBE_ID);
        packet
    }

    /// Probes are addressed to the provided target.
    #[test]
    fn test_probe_addresses_target() {
        let icmp = Icmp::try_new(TARGET, PACKET_LENGTH).unwrap();
        let (_, address) = icmp.probe(PROBE_ID);
        assert_eq!(address, SockAddr::from(SocketAddrV4::new(TARGET, 0)));
    }

    /// Packets that are below the minimum length are rejected.
    #[test]
    fn test_rejects_too_small_packet() {
        assert!(Icmp::try_new(TARGET, 0).is_err());
        assert!(Icmp::try_new(TARGET, Icmp::MIN_PACKET_LEN - 1).is_err());
    }

    /// Probes use the provided length.
    #[test]
    fn test_probe_length() {
        for packet_len in [Icmp::MIN_PACKET_LEN, PACKET_LENGTH, 1500] {
            let icmp = Icmp::try_new(TARGET, packet_len).unwrap();
            let (packet, _) = icmp.probe(PROBE_ID);

            assert_eq!(packet.len(), packet_len - MIN_IPV4_HEADER_LEN);
            assert_eq!(packet.len(), icmp.max_reply_len());
        }
    }

    /// Probes set a valid checksum.
    #[test]
    fn test_probe_sets_checksum() {
        for packet_len in [Icmp::MIN_PACKET_LEN, PACKET_LENGTH, 1500] {
            let (packet, _) = Icmp::try_new(TARGET, packet_len).unwrap().probe(PROBE_ID);

            assert_eq!(packet[0], ECHO_REQUEST);
            assert_eq!(packet[1], 0);
            // A packet carrying a correct checksum sums to zero.
            assert_eq!(internet_checksum(&packet), 0, "packet length {packet_len}");
        }
    }

    /// Probes are identified correctly from their quoted replies.
    #[test]
    fn test_identify_quoted_probe() {
        let packet = probe();
        assert_eq!(
            ErrorReplies.identify(&reply(&packet, icmp_error(TIME_EXCEEDED, 0))),
            Some(PROBE_ID)
        );
    }

    /// Probe replies are identified correctly with the corresponding probe ID.
    #[test]
    fn test_identify_echo_reply() {
        let mut packet = probe();
        packet[0] = ECHO_REPLY;
        assert_eq!(EchoReplies.identify(&reply(&packet, None)), Some(PROBE_ID));
    }

    /// Quoted packets that are below 8 bytes are rejected.
    #[test]
    fn test_identify_rejects_truncated_quote() {
        let packet = probe();
        let truncated = reply(&packet[..7], None);
        assert_eq!(ErrorReplies.identify(&truncated), None);
        assert_eq!(EchoReplies.identify(&truncated), None);
    }

    /// Echo replies are classified as belonging to the destination.
    #[test]
    fn test_classify_echo_replies() {
        assert_eq!(
            EchoReplies.classify(&reply(&probe(), None)),
            ReplyKind::Destination
        );
    }

    /// "Host Unreachable" messages are ignored by the [`EchoReplies`] reader.
    #[test]
    fn test_echo_replies_ignore_host_unreachable() {
        assert!(EchoReplies.ignores_read_error(-libc::EHOSTUNREACH));
        assert!(!EchoReplies.ignores_read_error(-libc::ECONNREFUSED));
    }

    /// ICMP errors are classified correctly.
    #[test]
    fn test_classify_errors() {
        let unreachable = |marker| ReplyKind::Unreachable(Unreachable::Marker(marker));
        let too_big = Some(IcmpError {
            icmp_type: DEST_UNREACH,
            icmp_code: 4,
            info: 1400,
        });
        let cases = [
            (icmp_error(TIME_EXCEEDED, 0), ReplyKind::Hop),
            (
                icmp_error(TIME_EXCEEDED, 1),
                ReplyKind::Unreachable(Unreachable::Other {
                    icmp_type: TIME_EXCEEDED,
                    code: 1,
                }),
            ),
            (icmp_error(DEST_UNREACH, 3), ReplyKind::Destination),
            (icmp_error(DEST_UNREACH, 0), unreachable("!N")),
            (icmp_error(DEST_UNREACH, 6), unreachable("!N")),
            (icmp_error(DEST_UNREACH, 8), unreachable("!N")),
            (icmp_error(DEST_UNREACH, 11), unreachable("!N")),
            (icmp_error(DEST_UNREACH, 1), unreachable("!H")),
            (icmp_error(DEST_UNREACH, 7), unreachable("!H")),
            (icmp_error(DEST_UNREACH, 12), unreachable("!H")),
            (icmp_error(DEST_UNREACH, 9), unreachable("!X")),
            (icmp_error(DEST_UNREACH, 10), unreachable("!X")),
            (icmp_error(DEST_UNREACH, 13), unreachable("!X")),
            (icmp_error(DEST_UNREACH, 2), unreachable("!P")),
            (
                too_big,
                ReplyKind::Unreachable(Unreachable::TooBig { mtu: 1400 }),
            ),
            (icmp_error(DEST_UNREACH, 5), unreachable("!S")),
            (icmp_error(DEST_UNREACH, 14), unreachable("!V")),
            (icmp_error(DEST_UNREACH, 15), unreachable("!C")),
            (
                icmp_error(DEST_UNREACH, 99),
                ReplyKind::Unreachable(Unreachable::Code(99)),
            ),
            (
                icmp_error(SOURCE_QUENCH, 0),
                ReplyKind::Unreachable(Unreachable::Other {
                    icmp_type: SOURCE_QUENCH,
                    code: 0,
                }),
            ),
            (None, unreachable("!?")),
        ];

        for (error, expected) in cases {
            assert_eq!(
                ErrorReplies.classify(&reply(&[], error)),
                expected,
                "{error:?}"
            );
        }
    }
}
