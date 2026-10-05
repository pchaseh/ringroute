use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    rc::Rc,
};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use super::{Method, ProbeId, Replies, Reply, ReplyKind, ReplyQueue};
use crate::net::{IPV6_HEADER_LENGTH, MIN_IPV4_HEADER_LEN};
use crate::{
    icmp::{v4, v6},
    method::Unreachable,
};

const ECHO_HEADER_LEN: usize = 8;

/// The sequence number, which sits at the same offset in an echo reply as in
/// the request a router quotes back.
fn sequence(quoted: &[u8]) -> Option<ProbeId> {
    let sequence = quoted.get(6..8)?.try_into().ok()?;
    Some(ProbeId(u16::from_be_bytes(sequence)))
}

pub(crate) struct EchoReplies;

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

pub(crate) struct ErrorReplies;

impl Replies for ErrorReplies {
    fn identify(&self, reply: &Reply<'_>) -> Option<ProbeId> {
        sequence(reply.quoted)
    }

    fn classify(&self, reply: &Reply<'_>) -> ReplyKind {
        reply
            .error
            .map_or(ReplyKind::Unreachable(Unreachable::Marker("!?")), |error| {
                error.kind()
            })
    }
}

pub struct Icmp {
    target: IpAddr,
    payload_len: usize,
}

impl Icmp {
    pub const fn min_packet_len(target: IpAddr) -> usize {
        (match target {
            IpAddr::V4(_) => MIN_IPV4_HEADER_LEN,
            IpAddr::V6(_) => IPV6_HEADER_LENGTH,
        }) + ECHO_HEADER_LEN
    }

    /// `packet_len` counts the whole IP packet, and must be large enough to
    /// hold the headers.
    pub fn try_new(target: IpAddr, packet_len: usize) -> anyhow::Result<Self> {
        let want_packet_len = Self::min_packet_len(target);

        let Some(payload_len) = packet_len.checked_sub(want_packet_len) else {
            anyhow::bail!(
                "packet size must be at least {} bytes for method icmp",
                want_packet_len
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
        let socket = match self.target {
            IpAddr::V4(_) => {
                let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))?;
                socket.bind(&SockAddr::from(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)))?;
                socket
            }
            IpAddr::V6(_) => {
                let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::ICMPV6))?;
                socket.bind(&SockAddr::from(SocketAddrV6::new(
                    Ipv6Addr::UNSPECIFIED,
                    0,
                    0,
                    0,
                )))?;
                socket
            }
        };

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
        let mut packet = vec![0; ECHO_HEADER_LEN + self.payload_len];
        packet[0] = match self.target {
            IpAddr::V4(_) => v4::ECHO_REQUEST,
            IpAddr::V6(_) => v6::ECHO_REQUEST,
        };
        // 2..4: Checksum, which we let the kernel compute for us...
        // 4..6: Identifier, which we let the kernel pick for us...
        // 6..8: Sequence number, which we use to store the probe's identifier.
        packet[6..8].copy_from_slice(&id.0.to_be_bytes());

        (packet, SockAddr::from(SocketAddr::new(self.target, 0)))
    }

    fn max_reply_len(&self) -> usize {
        // An echo reply echoes our payload back with the same header length.
        ECHO_HEADER_LEN + self.payload_len
    }
}

#[cfg(test)]
mod test {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use crate::method::{
        Icmp, Method, ProbeId, Replies, Reply, ReplyKind, Unreachable,
        icmp::{EchoReplies, ErrorReplies},
    };

    const TARGETS: [IpAddr; 2] = [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ];
    const PACKET_LENGTH: usize = 60;
    const PROBE_ID: ProbeId = ProbeId(1234);

    fn reply(quoted: &[u8]) -> Reply<'_> {
        Reply {
            source: None,
            destination: None,
            quoted,
            error: None,
        }
    }

    fn probe(target: IpAddr) -> Vec<u8> {
        let (packet, _) = Icmp::try_new(target, PACKET_LENGTH)
            .unwrap()
            .probe(PROBE_ID);
        packet
    }

    /// Probes are identified correctly from their quoted replies.
    #[test]
    fn test_identify_quoted_probe() {
        for target in TARGETS {
            assert_eq!(
                ErrorReplies.identify(&reply(&probe(target))),
                Some(PROBE_ID),
                "{target}"
            );
        }
    }

    /// Probe replies are identified correctly with the corresponding probe ID.
    #[test]
    fn test_identify_echo_reply() {
        for target in TARGETS {
            // An echo reply carries the request's sequence number back.
            assert_eq!(
                EchoReplies.identify(&reply(&probe(target))),
                Some(PROBE_ID),
                "{target}"
            );
        }
    }

    /// Replies that are below 8 bytes are rejected.
    #[test]
    fn test_identify_rejects_truncated_reply() {
        for target in TARGETS {
            let packet = probe(target);
            let truncated = reply(&packet[..7]);
            assert_eq!(ErrorReplies.identify(&truncated), None, "{target}");
            assert_eq!(EchoReplies.identify(&truncated), None, "{target}");
        }
    }

    /// Echo replies are classified as belonging to the destination.
    #[test]
    fn test_classify_echo_replies() {
        for target in TARGETS {
            assert_eq!(
                EchoReplies.classify(&reply(&probe(target))),
                ReplyKind::Destination,
                "{target}"
            );
        }
    }

    /// Error queue replies without an ICMP error are marked unknown.
    #[test]
    fn test_classify_without_error() {
        assert_eq!(
            ErrorReplies.classify(&reply(&[])),
            ReplyKind::Unreachable(Unreachable::Marker("!?"))
        );
    }

    /// "Host Unreachable" messages are ignored by the [`EchoReplies`] reader.
    #[test]
    fn test_echo_replies_ignore_host_unreachable() {
        assert!(EchoReplies.ignores_read_error(-libc::EHOSTUNREACH));
        assert!(!EchoReplies.ignores_read_error(-libc::ECONNREFUSED));
    }

    mod v4 {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        use socket2::SockAddr;

        use crate::{
            icmp::v4::ECHO_REQUEST,
            method::{Icmp, Method, ProbeId},
            net::MIN_IPV4_HEADER_LEN,
        };

        const TARGET: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        const PACKET_LENGTH: usize = 60;
        const PROBE_ID: ProbeId = ProbeId(1234);

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
            assert_eq!(address, SockAddr::from(SocketAddr::new(TARGET, 0)));
        }

        /// Packets that are below the minimum length are rejected.
        #[test]
        fn test_rejects_too_small_packet() {
            assert!(Icmp::try_new(TARGET, 0).is_err());
            assert!(Icmp::try_new(TARGET, Icmp::min_packet_len(TARGET) - 1).is_err());
        }

        /// Probes use the provided length.
        #[test]
        fn test_probe_length() {
            for packet_len in [Icmp::min_packet_len(TARGET), PACKET_LENGTH, 1500] {
                let icmp = Icmp::try_new(TARGET, packet_len).unwrap();
                let (packet, _) = icmp.probe(PROBE_ID);

                assert_eq!(packet.len(), packet_len - MIN_IPV4_HEADER_LEN);
                assert_eq!(packet.len(), icmp.max_reply_len());
            }
        }

        /// Probes are echo requests.
        #[test]
        fn test_probe_is_echo_request() {
            let packet = probe();
            assert_eq!(packet[0], ECHO_REQUEST);
            assert_eq!(packet[1], 0);
        }
    }

    mod v6 {
        use std::net::{IpAddr, Ipv6Addr, SocketAddr};

        use socket2::SockAddr;

        use crate::{
            icmp::v6::ECHO_REQUEST,
            method::{Icmp, Method, ProbeId},
            net::IPV6_HEADER_LENGTH,
        };

        const TARGET: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);
        const PACKET_LENGTH: usize = 60;
        const PROBE_ID: ProbeId = ProbeId(1234);

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
            assert_eq!(address, SockAddr::from(SocketAddr::new(TARGET, 0)));
        }

        /// Packets that are below the minimum length are rejected.
        #[test]
        fn test_rejects_too_small_packet() {
            assert!(Icmp::try_new(TARGET, 0).is_err());
            assert!(Icmp::try_new(TARGET, Icmp::min_packet_len(TARGET) - 1).is_err());
        }

        /// Probes use the provided length.
        #[test]
        fn test_probe_length() {
            for packet_len in [Icmp::min_packet_len(TARGET), PACKET_LENGTH, 1500] {
                let icmp = Icmp::try_new(TARGET, packet_len).unwrap();
                let (packet, _) = icmp.probe(PROBE_ID);

                assert_eq!(packet.len(), packet_len - IPV6_HEADER_LENGTH);
                assert_eq!(packet.len(), icmp.max_reply_len());
            }
        }

        /// Probes are echo requests.
        #[test]
        fn test_probe_is_echo_request() {
            let packet = probe();
            assert_eq!(packet[0], ECHO_REQUEST);
            assert_eq!(packet[1], 0);
        }
    }
}
