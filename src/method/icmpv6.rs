use std::{
    io,
    net::{Ipv6Addr, SocketAddrV6},
    rc::Rc,
};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use super::{Method, ProbeId, Replies, Reply, ReplyKind, ReplyQueue, Unreachable};
use crate::net::IPV6_HEADER_LENGTH;

const ECHO_HEADER_LEN: usize = 8;

const ECHO_REQUEST: u8 = 128;

const DEST_UNREACH: u8 = 1;
const PACKET_TOO_BIG: u8 = 2;
const TIME_EXCEEDED: u8 = 3;

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
            (DEST_UNREACH, 4) => return ReplyKind::Destination,
            (DEST_UNREACH, 0) => Unreachable::Marker("!N"),
            (DEST_UNREACH, 1) => Unreachable::Marker("!X"),
            (DEST_UNREACH, 2 | 3) => Unreachable::Marker("!H"),
            (DEST_UNREACH, code) => Unreachable::Code(code),
            (PACKET_TOO_BIG, _) => Unreachable::TooBig { mtu: error.info },
            (icmp_type, code) => Unreachable::Other { icmp_type, code },
        };

        ReplyKind::Unreachable(unreachable)
    }
}

pub struct Icmpv6 {
    target: Ipv6Addr,
    payload_len: usize,
}

impl Icmpv6 {
    /// This method is IPv6-only.
    const MIN_PACKET_LEN: usize = IPV6_HEADER_LENGTH + ECHO_HEADER_LEN;

    /// `packet_len` counts the whole IP packet, and must be large enough to
    /// hold the headers.
    pub fn try_new(target: Ipv6Addr, packet_len: usize) -> anyhow::Result<Self> {
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

impl Method for Icmpv6 {
    fn open(&self) -> io::Result<(Rc<Socket>, Vec<ReplyQueue>)> {
        let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::ICMPV6))?;
        socket.bind(&SockAddr::from(SocketAddrV6::new(
            Ipv6Addr::UNSPECIFIED,
            0,
            0,
            0,
        )))?;
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
        packet[0] = ECHO_REQUEST;
        // 3..5: Let the kernel assign the ICMP identifier.
        // We use the sequence number to store the probe's identifier.
        packet[6..8].copy_from_slice(&id.0.to_be_bytes());
        // 2..4: The kernel computes the checksum, which covers a pseudo header
        // including the source address it picks, and the identifier it assigns.

        (
            packet,
            SockAddr::from(SocketAddrV6::new(self.target, 0, 0, 0)),
        )
    }

    fn max_reply_len(&self) -> usize {
        // An echo reply echoes our payload back with the same header length.
        ECHO_HEADER_LEN + self.payload_len
    }
}

#[cfg(test)]
mod test {
    use crate::{
        method::{
            Replies, Reply, ReplyKind, Unreachable,
            icmpv6::{DEST_UNREACH, ErrorReplies, PACKET_TOO_BIG, TIME_EXCEEDED},
        },
        net::IcmpError,
    };

    const PARAMETER_PROBLEM: u8 = 4;

    fn classify(error: Option<IcmpError>) -> ReplyKind {
        ErrorReplies.classify(&Reply {
            source: None,
            quoted: &[],
            error,
        })
    }

    fn icmp_error(icmp_type: u8, icmp_code: u8, info: u32) -> Option<IcmpError> {
        Some(IcmpError {
            icmp_type,
            icmp_code,
            info,
        })
    }

    /// ICMPv6 errors are classified correctly.
    #[test]
    fn test_classify_errors() {
        let unreachable = |marker| ReplyKind::Unreachable(Unreachable::Marker(marker));
        let cases = [
            (icmp_error(TIME_EXCEEDED, 0, 0), ReplyKind::Hop),
            (
                icmp_error(TIME_EXCEEDED, 1, 0),
                ReplyKind::Unreachable(Unreachable::Other {
                    icmp_type: TIME_EXCEEDED,
                    code: 1,
                }),
            ),
            (icmp_error(DEST_UNREACH, 0, 0), unreachable("!N")),
            (icmp_error(DEST_UNREACH, 1, 0), unreachable("!X")),
            (icmp_error(DEST_UNREACH, 2, 0), unreachable("!H")),
            (icmp_error(DEST_UNREACH, 3, 0), unreachable("!H")),
            (icmp_error(DEST_UNREACH, 4, 0), ReplyKind::Destination),
            (
                icmp_error(DEST_UNREACH, 5, 0),
                ReplyKind::Unreachable(Unreachable::Code(5)),
            ),
            (
                icmp_error(PACKET_TOO_BIG, 0, 1280),
                ReplyKind::Unreachable(Unreachable::TooBig { mtu: 1280 }),
            ),
            (
                icmp_error(PARAMETER_PROBLEM, 1, 0),
                ReplyKind::Unreachable(Unreachable::Other {
                    icmp_type: PARAMETER_PROBLEM,
                    code: 1,
                }),
            ),
            (None, unreachable("!?")),
        ];

        for (error, expected) in cases {
            assert_eq!(classify(error), expected, "{error:?}");
        }
    }

    #[test]
    fn test_display_unreachable() {
        assert_eq!(Unreachable::Marker("!N").to_string(), "!N");
        assert_eq!(Unreachable::Code(5).to_string(), "!<5>");
        assert_eq!(
            Unreachable::Other {
                icmp_type: 4,
                code: 1
            }
            .to_string(),
            "!<4-1>"
        );
        assert_eq!(Unreachable::TooBig { mtu: 1280 }.to_string(), "!F-1280");
    }
}
