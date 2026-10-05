use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    rc::Rc,
};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::{
    method::{Method, ProbeId, Replies, Reply, ReplyKind, ReplyQueue, Unreachable},
    net::{IPV6_HEADER_LENGTH, MIN_IPV4_HEADER_LEN},
};

const UDP_HEADER_LEN: usize = 8;
const START_PORT: u16 = 33434;

pub struct Udp {
    target: IpAddr,
    payload_len: usize,
}

/// Represents a UDP reply from the socket's read queue.
///
/// Note that, unless we happened to send out a probe matching the port of an active service that
/// also elicits a reply, we're unlikely to ever see any replies outside of [`ErrorReplies`].
struct UdpReplies {
    target: IpAddr,
}

impl Replies for UdpReplies {
    fn identify(&self, reply: &Reply<'_>) -> Option<ProbeId> {
        let source = reply.source.as_ref()?.as_socket()?;

        if source.ip() != self.target {
            return None;
        }

        Some(ProbeId(source.port().checked_sub(START_PORT)?))
    }

    fn classify(&self, _reply: &Reply<'_>) -> ReplyKind {
        ReplyKind::Destination
    }

    fn ignores_read_error(&self, error: i32) -> bool {
        error == -libc::EHOSTUNREACH
    }
}

struct ErrorReplies;

impl Replies for ErrorReplies {
    fn identify(&self, reply: &Reply<'_>) -> Option<ProbeId> {
        // The port must be read from `msg_name` because `quoted` only includes the
        // quoted UDP payload and not its header.
        let port = reply.destination.as_ref()?.as_socket()?.port();
        port.checked_sub(START_PORT).map(ProbeId)
    }

    fn classify(&self, reply: &Reply<'_>) -> ReplyKind {
        reply
            .error
            .map_or(ReplyKind::Unreachable(Unreachable::Marker("!?")), |error| {
                error.kind()
            })
    }
}

impl Udp {
    /// `packet_len` counts the whole IP packet, and must be large enough to
    /// hold the headers.
    pub fn try_new(target: IpAddr, packet_len: usize) -> anyhow::Result<Self> {
        let want_packet_len = (match target {
            IpAddr::V4(_) => MIN_IPV4_HEADER_LEN,
            IpAddr::V6(_) => IPV6_HEADER_LENGTH,
        }) + UDP_HEADER_LEN;

        let Some(payload_len) = packet_len.checked_sub(want_packet_len) else {
            anyhow::bail!(
                "packet size must be at least {} bytes for method udp",
                want_packet_len
            );
        };

        Ok(Self {
            target,
            payload_len,
        })
    }
}

impl Method for Udp {
    fn open(&self) -> io::Result<(Rc<Socket>, Vec<ReplyQueue>)> {
        let socket = match self.target {
            IpAddr::V4(_) => {
                let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
                socket.bind(&SockAddr::from(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)))?;
                socket
            }
            IpAddr::V6(_) => {
                let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
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
                    replies: Box::new(UdpReplies {
                        target: self.target,
                    }),
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
        let packet = vec![0; self.payload_len];
        (
            packet,
            SockAddr::from(SocketAddr::new(self.target, START_PORT + id.0)),
        )
    }

    fn max_reply_len(&self) -> usize {
        self.payload_len
    }
}

#[cfg(test)]
mod test {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use socket2::SockAddr;

    use crate::{
        icmp::{IcmpError, v4},
        method::{
            Method, ProbeId, Replies, Reply, ReplyKind, Udp, Unreachable,
            udp::{ErrorReplies, START_PORT, UDP_HEADER_LEN, UdpReplies},
        },
        net::{IPV6_HEADER_LENGTH, MIN_IPV4_HEADER_LEN},
    };

    const TARGETS: [IpAddr; 2] = [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ];
    const PACKET_LENGTH: usize = 60;
    const PROBE_ID: ProbeId = ProbeId(1234);

    fn min_packet_len(target: IpAddr) -> usize {
        (match target {
            IpAddr::V4(_) => MIN_IPV4_HEADER_LEN,
            IpAddr::V6(_) => IPV6_HEADER_LENGTH,
        }) + UDP_HEADER_LEN
    }

    fn reply(destination: Option<SockAddr>, error: Option<IcmpError>) -> Reply<'static> {
        Reply {
            source: None,
            destination,
            quoted: &[],
            error,
        }
    }

    fn received(source: Option<SockAddr>) -> Reply<'static> {
        Reply {
            source,
            destination: None,
            quoted: &[],
            error: None,
        }
    }

    fn sockaddr(target: IpAddr, port: u16) -> Option<SockAddr> {
        Some(SockAddr::from(SocketAddr::new(target, port)))
    }

    fn udp_replies(target: IpAddr) -> UdpReplies {
        UdpReplies { target }
    }

    /// Probes are addressed to the provided target.
    #[test]
    fn test_probe_addresses_target() {
        for target in TARGETS {
            let (_, address) = Udp::try_new(target, PACKET_LENGTH).unwrap().probe(PROBE_ID);
            assert_eq!(address, sockaddr(target, START_PORT + PROBE_ID.0).unwrap());
        }
    }

    /// Packets that are below the minimum length are rejected.
    #[test]
    fn test_rejects_too_small_packet() {
        for target in TARGETS {
            assert!(Udp::try_new(target, 0).is_err(), "{target}");
            assert!(
                Udp::try_new(target, min_packet_len(target) - 1).is_err(),
                "{target}"
            );
        }
    }

    /// Probes use the provided length.
    #[test]
    fn test_probe_length() {
        for target in TARGETS {
            for packet_len in [min_packet_len(target), PACKET_LENGTH, 1500] {
                let udp = Udp::try_new(target, packet_len).unwrap();
                let (packet, _) = udp.probe(PROBE_ID);

                assert_eq!(packet.len(), packet_len - min_packet_len(target));
                assert_eq!(packet.len(), udp.max_reply_len());
            }
        }
    }

    /// Error replies are identified by the dropped probe's destination port.
    #[test]
    fn test_identify_error_reply() {
        for target in TARGETS {
            assert_eq!(
                ErrorReplies.identify(&reply(sockaddr(target, START_PORT + PROBE_ID.0), None)),
                Some(PROBE_ID),
                "{target}"
            );
        }
    }

    /// Error replies without a destination port belonging to a probe are rejected.
    #[test]
    fn test_identify_rejects_unknown_destination() {
        for target in TARGETS {
            assert_eq!(
                ErrorReplies.identify(&reply(sockaddr(target, START_PORT - 1), None)),
                None,
                "{target}"
            );
        }
        assert_eq!(ErrorReplies.identify(&reply(None, None)), None);
    }

    /// Received replies are identified by the port they were sent from.
    #[test]
    fn test_identify_received_reply() {
        for target in TARGETS {
            assert_eq!(
                udp_replies(target).identify(&received(sockaddr(target, START_PORT + PROBE_ID.0))),
                Some(PROBE_ID),
                "{target}"
            );
        }
    }

    /// Received replies that are not from a probe's port on the target are rejected.
    #[test]
    fn test_identify_rejects_unknown_source() {
        for target in TARGETS {
            assert_eq!(
                udp_replies(target).identify(&received(sockaddr(target, 7))),
                None,
                "{target}"
            );

            let other = match target {
                IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            };
            assert_eq!(
                udp_replies(target).identify(&received(sockaddr(other, START_PORT + PROBE_ID.0))),
                None,
                "{target}"
            );

            assert_eq!(udp_replies(target).identify(&received(None)), None);
        }
    }

    /// Error replies are classified by their ICMP error.
    #[test]
    fn test_classify_error_reply() {
        let error = IcmpError::V4 {
            icmp_type: v4::TIME_EXCEEDED,
            code: 0,
            info: 0,
        };
        assert_eq!(
            ErrorReplies.classify(&reply(None, Some(error))),
            ReplyKind::Hop
        );
    }

    /// Error queue replies without an ICMP error are marked unknown.
    #[test]
    fn test_classify_without_error() {
        assert_eq!(
            ErrorReplies.classify(&reply(None, None)),
            ReplyKind::Unreachable(Unreachable::Marker("!?"))
        );
    }
}
