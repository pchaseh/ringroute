use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    rc::Rc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use pnet::packet::{
    Packet,
    ipv4::Ipv4Packet,
    tcp::{MutableTcpPacket, TcpFlags, TcpOption, TcpPacket},
};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::{
    method::{ErrorReplies, Method, ProbeId, Replies, Reply, ReplyKind, ReplyQueue},
    net::MIN_IPV4_HEADER_LEN,
};

const TCP_MIN_HEADER_LEN: usize = 20;
const TCP_SYN_OPTIONS_LEN: usize = 20;
const DEST_PORT: u16 = 80;

pub struct Tcp {
    target: IpAddr,
    source: SocketAddr,
    // Dummy TCP socket. We use this to get a free port from the system and hold it for as long as it might be needed.
    _dummy_sock: Socket,
}

struct TcpReplies {
    target: IpAddr,
    source: SocketAddr,
}

impl Replies for TcpReplies {
    fn identify(&self, reply: &Reply<'_>) -> Option<ProbeId> {
        if reply.source.as_ref()?.as_socket()?.ip() != self.target {
            return None;
        }

        let ip_packet = match self.target {
            IpAddr::V4(_) => Some(Ipv4Packet::new(reply.quoted)?),
            IpAddr::V6(_) => None,
        };

        let tcp_payload = match &ip_packet {
            Some(ip) => ip.payload(),
            None => reply.quoted,
        };

        let tcp_packet = TcpPacket::new(tcp_payload)?;

        // The source address for raw sockets will always be port 0, so verify that the ports match
        // on our own.
        if (tcp_packet.get_source(), tcp_packet.get_destination())
            != (DEST_PORT, self.source.port())
        {
            return None;
        }
        // We don't currently permit probing with data, but if ever we did the below translation
        // would have to take into account responses acknowledging our data (eg. RFC 9293,
        // § 3.10.7.1).
        let sequence = tcp_packet.get_acknowledgement().checked_sub(1)?;
        let sequence = u16::try_from(sequence).ok()?;
        Some(ProbeId(sequence))
    }

    fn classify(&self, _reply: &Reply<'_>) -> ReplyKind {
        ReplyKind::Destination
    }

    fn ignores_read_error(&self, error: i32) -> bool {
        error == -libc::EHOSTUNREACH
    }
}

pub(crate) fn identify_from_error(reply: &Reply<'_>, want_source_port: u16) -> Option<ProbeId> {
    let source_port = u16::from_be_bytes(reply.quoted.get(0..2)?.try_into().ok()?);
    if source_port != want_source_port {
        return None;
    }
    // No [`TcpPacket::new`] here because only the first 8 bytes are quoted, and a
    // valid TCP header must be at least 20 bytes.
    let sequence = u32::from_be_bytes(reply.quoted.get(4..8)?.try_into().ok()?);
    let sequence = u16::try_from(sequence).ok()?;
    Some(ProbeId(sequence))
}

impl Tcp {
    pub fn try_new(target: IpAddr) -> anyhow::Result<Self> {
        let dummy_sock = match target {
            IpAddr::V4(_) => {
                let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
                socket.bind(&SockAddr::from(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)))?;
                socket
            }
            IpAddr::V6(_) => {
                let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
                socket.bind(&SockAddr::from(SocketAddrV6::new(
                    Ipv6Addr::UNSPECIFIED,
                    0,
                    0,
                    0,
                )))?;
                socket
            }
        };

        let source_port = dummy_sock
            .local_addr()?
            .as_socket()
            .context("not a socket address")?
            .port();

        let source_ip = {
            // Create a UDP socket and call `connect()` to trigger a route lookup so we know what
            // source IP to probe from.
            let socket = match target {
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

            socket.connect(&SockAddr::from(SocketAddr::new(target, DEST_PORT)))?;
            socket
                .local_addr()?
                .as_socket()
                .context("not a socket address")?
                .ip()
        };

        let source = SocketAddr::new(source_ip, source_port);

        Ok(Self {
            target,
            _dummy_sock: dummy_sock,
            source,
        })
    }
}

impl Method for Tcp {
    fn open(&self) -> std::io::Result<(std::rc::Rc<socket2::Socket>, Vec<super::ReplyQueue>)> {
        let socket = match self.target {
            IpAddr::V4(_) => {
                let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP))?;
                socket.bind(&SockAddr::from(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)))?;
                socket
            }
            IpAddr::V6(_) => {
                let socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::TCP))?;
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
        let source_port = self.source.port();

        Ok((
            socket.clone(),
            vec![
                ReplyQueue {
                    socket: socket.clone(),
                    err_queue: false,
                    replies: Box::new(TcpReplies {
                        target: self.target,
                        source: self.source,
                    }),
                },
                ReplyQueue {
                    socket,
                    err_queue: true,
                    replies: Box::new(ErrorReplies {
                        identify: move |reply: &Reply<'_>| identify_from_error(reply, source_port),
                    }),
                },
            ],
        ))
    }

    fn probe(&self, id: ProbeId) -> (Vec<u8>, socket2::SockAddr) {
        let total_len = TCP_MIN_HEADER_LEN + TCP_SYN_OPTIONS_LEN;
        let mut packet = vec![0; total_len];

        {
            let mut tcp_packet = MutableTcpPacket::new(&mut packet).unwrap();
            tcp_packet.set_source(self.source.port());
            tcp_packet.set_destination(DEST_PORT);
            tcp_packet.set_sequence(id.0 as u32);
            tcp_packet.set_flags(TcpFlags::SYN);
            tcp_packet.set_data_offset(total_len as u8 / 4);
            let mss = match self.target {
                IpAddr::V4(_) => 1460,
                IpAddr::V6(_) => 1440,
            };
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u32;
            // Set the same options that a TCP SYN would carry by default on Linux based systems.
            tcp_packet.set_options(&[
                TcpOption::mss(mss),
                TcpOption::sack_perm(),
                TcpOption::timestamp(timestamp, 0),
                TcpOption::nop(),
                TcpOption::wscale(7),
            ]);
            let checksum = match (self.source.ip(), self.target) {
                (IpAddr::V4(source), IpAddr::V4(target)) => {
                    pnet::packet::tcp::ipv4_checksum(&tcp_packet.to_immutable(), &source, &target)
                }
                (IpAddr::V6(source), IpAddr::V6(target)) => {
                    pnet::packet::tcp::ipv6_checksum(&tcp_packet.to_immutable(), &source, &target)
                }
                _ => unreachable!(),
            };
            tcp_packet.set_checksum(checksum);
        }
        (
            packet,
            SockAddr::from(SocketAddr::new(self.target, DEST_PORT)),
        )
    }

    fn max_reply_len(&self) -> usize {
        // Using a raw socket means we'll also see the IPv4 header for normal reads. IPv6 doesn't
        // include it.
        (match self.target {
            IpAddr::V4(_) => MIN_IPV4_HEADER_LEN,
            IpAddr::V6(_) => 0,
        } + TCP_MIN_HEADER_LEN)
    }
}

#[cfg(test)]
mod test {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use pnet::packet::{
        ip::IpNextHeaderProtocols,
        ipv4::MutableIpv4Packet,
        tcp::{self, MutableTcpPacket, TcpFlags, TcpOptionNumbers, TcpPacket},
    };
    use socket2::SockAddr;

    use crate::{
        method::{
            ErrorReplies, Method, ProbeId, Replies, Reply, ReplyKind, Tcp,
            tcp::{
                DEST_PORT, TCP_MIN_HEADER_LEN, TCP_SYN_OPTIONS_LEN, TcpReplies, identify_from_error,
            },
        },
        net::MIN_IPV4_HEADER_LEN,
    };

    const TARGETS: [IpAddr; 2] = [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ];
    const PROBE_ID: ProbeId = ProbeId(1234);
    /// The port our probes are sent from.
    const SOURCE_PORT: u16 = 40000;

    fn reply(quoted: &[u8]) -> Reply<'_> {
        Reply {
            source: None,
            destination: None,
            quoted,
            error: None,
        }
    }

    fn received(source: Option<SockAddr>, quoted: &[u8]) -> Reply<'_> {
        Reply {
            source,
            destination: None,
            quoted,
            error: None,
        }
    }

    fn sockaddr(target: IpAddr, port: u16) -> Option<SockAddr> {
        Some(SockAddr::from(SocketAddr::new(target, port)))
    }

    fn tcp_replies(target: IpAddr) -> TcpReplies {
        TcpReplies {
            target,
            source: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), SOURCE_PORT),
        }
    }

    fn probe(target: IpAddr) -> Vec<u8> {
        let (packet, _) = Tcp::try_new(target).unwrap().probe(PROBE_ID);
        packet
    }

    /// A reset from the target answering one of our probes.
    fn segment(target: IpAddr, acknowledgement: u32) -> Vec<u8> {
        segment_between(target, DEST_PORT, SOURCE_PORT, acknowledgement)
    }

    /// A reset from the target as a raw socket reads it, which only includes the IP header for
    /// IPv4.
    fn segment_between(
        target: IpAddr,
        source_port: u16,
        destination_port: u16,
        acknowledgement: u32,
    ) -> Vec<u8> {
        let mut segment = vec![0; TCP_MIN_HEADER_LEN];
        {
            let mut tcp_packet = MutableTcpPacket::new(&mut segment).unwrap();
            tcp_packet.set_source(source_port);
            tcp_packet.set_destination(destination_port);
            tcp_packet.set_acknowledgement(acknowledgement);
            tcp_packet.set_flags(TcpFlags::RST | TcpFlags::ACK);
            tcp_packet.set_data_offset((TCP_MIN_HEADER_LEN / 4) as u8);
        }

        let IpAddr::V4(source) = target else {
            return segment;
        };

        let total_len = MIN_IPV4_HEADER_LEN + TCP_MIN_HEADER_LEN;
        let mut packet = vec![0; total_len];
        {
            let mut ip_packet = MutableIpv4Packet::new(&mut packet).unwrap();
            ip_packet.set_version(4);
            ip_packet.set_header_length((MIN_IPV4_HEADER_LEN / 4) as u8);
            ip_packet.set_total_length(total_len as u16);
            ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
            ip_packet.set_source(source);
            ip_packet.set_payload(&segment);
        }
        packet
    }

    /// The error queue reader for a trace whose probes are sent from `source_port`.
    fn error_replies(source_port: u16) -> ErrorReplies<impl Fn(&Reply<'_>) -> Option<ProbeId>> {
        ErrorReplies {
            identify: move |reply: &Reply<'_>| identify_from_error(reply, source_port),
        }
    }

    /// A probe, and the error queue reader of the trace that sent it.
    fn traced_probe(
        target: IpAddr,
    ) -> (
        Vec<u8>,
        ErrorReplies<impl Fn(&Reply<'_>) -> Option<ProbeId>>,
    ) {
        let tcp = Tcp::try_new(target).unwrap();
        let (packet, _) = tcp.probe(PROBE_ID);
        (packet, error_replies(tcp.source.port()))
    }

    /// Probes are addressed to the provided target.
    #[test]
    fn test_probe_addresses_target() {
        for target in TARGETS {
            let (_, address) = Tcp::try_new(target).unwrap().probe(PROBE_ID);
            assert_eq!(address, sockaddr(target, DEST_PORT).unwrap(), "{target}");
        }
    }

    /// Probes are SYNs carrying the probe ID as their sequence number.
    #[test]
    fn test_probe_is_syn() {
        for target in TARGETS {
            let packet = probe(target);
            let tcp_packet = TcpPacket::new(&packet).unwrap();

            assert_eq!(tcp_packet.get_flags(), TcpFlags::SYN, "{target}");
            assert_eq!(tcp_packet.get_destination(), DEST_PORT, "{target}");
            assert_eq!(tcp_packet.get_sequence(), u32::from(PROBE_ID.0), "{target}");
        }
    }

    /// Probes are sent from the port held by the dummy socket.
    #[test]
    fn test_probe_source_port() {
        for target in TARGETS {
            let tcp = Tcp::try_new(target).unwrap();
            let (packet, _) = tcp.probe(PROBE_ID);
            let port = tcp
                ._dummy_sock
                .local_addr()
                .unwrap()
                .as_socket()
                .unwrap()
                .port();

            assert_eq!(
                TcpPacket::new(&packet).unwrap().get_source(),
                port,
                "{target}"
            );
        }
    }

    /// Probes carry a valid checksum.
    #[test]
    fn test_probe_checksum() {
        for target in TARGETS {
            let tcp = Tcp::try_new(target).unwrap();
            let (packet, _) = tcp.probe(PROBE_ID);
            let tcp_packet = TcpPacket::new(&packet).unwrap();

            let checksum = match (tcp.source.ip(), target) {
                (IpAddr::V4(source), IpAddr::V4(target)) => {
                    tcp::ipv4_checksum(&tcp_packet, &source, &target)
                }
                (IpAddr::V6(source), IpAddr::V6(target)) => {
                    tcp::ipv6_checksum(&tcp_packet, &source, &target)
                }
                _ => unreachable!(),
            };
            assert_eq!(tcp_packet.get_checksum(), checksum, "{target}");
        }
    }

    /// Probes carry no payload.
    #[test]
    fn test_probe_carries_no_payload() {
        for target in TARGETS {
            let packet = probe(target);
            let tcp_packet = TcpPacket::new(&packet).unwrap();

            assert_eq!(
                packet.len(),
                TCP_MIN_HEADER_LEN + TCP_SYN_OPTIONS_LEN,
                "{target}"
            );
            assert_eq!(
                usize::from(tcp_packet.get_data_offset()) * 4,
                TCP_MIN_HEADER_LEN + TCP_SYN_OPTIONS_LEN,
                "{target}"
            );
        }
    }

    /// Probes carry the expected options.
    #[test]
    fn test_probe_options() {
        for target in TARGETS {
            let packet = probe(target);
            let tcp_packet = TcpPacket::new(&packet).unwrap();
            let numbers = tcp_packet
                .get_options_iter()
                .map(|option| option.get_number())
                .collect::<Vec<_>>();

            assert_eq!(
                numbers,
                [
                    TcpOptionNumbers::MSS,
                    TcpOptionNumbers::SACK_PERMITTED,
                    TcpOptionNumbers::TIMESTAMPS,
                    TcpOptionNumbers::NOP,
                    TcpOptionNumbers::WSCALE,
                ],
                "{target}"
            );
        }
    }

    /// Probes are identified correctly from the first 8 bytes quoted back.
    #[test]
    fn test_identify_quoted_probe() {
        for target in TARGETS {
            let (probe, error_replies) = traced_probe(target);
            assert_eq!(
                error_replies.identify(&reply(&probe[..8])),
                Some(PROBE_ID),
                "{target}"
            );
        }
    }

    /// Replies that are too short to hold their identifier are rejected.
    #[test]
    fn test_identify_rejects_truncated_reply() {
        for target in TARGETS {
            let (probe, error_replies) = traced_probe(target);
            assert_eq!(
                error_replies.identify(&reply(&probe[..7])),
                None,
                "{target}"
            );

            let segment = segment(target, u32::from(PROBE_ID.0) + 1);
            assert_eq!(
                tcp_replies(target).identify(&received(
                    sockaddr(target, DEST_PORT),
                    &segment[..segment.len() - 1]
                )),
                None,
                "{target}"
            );
        }
    }

    /// Received replies are identified by the sequence number they acknowledge.
    #[test]
    fn test_identify_received_reply() {
        for target in TARGETS {
            assert_eq!(
                tcp_replies(target).identify(&received(
                    sockaddr(target, DEST_PORT),
                    &segment(target, u32::from(PROBE_ID.0) + 1)
                )),
                Some(PROBE_ID),
                "{target}"
            );
        }
    }

    /// Received replies that are not from the target are rejected.
    #[test]
    fn test_identify_rejects_unknown_source() {
        for target in TARGETS {
            let segment = segment(target, u32::from(PROBE_ID.0) + 1);
            let other = match target {
                IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            };
            assert_eq!(
                tcp_replies(target).identify(&received(sockaddr(other, DEST_PORT), &segment)),
                None,
                "{target}"
            );

            assert_eq!(
                tcp_replies(target).identify(&received(None, &segment)),
                None,
                "{target}"
            );

            // A raw socket sees every segment the target sends us, so the ports must be checked
            // too to verify the response belongs to us.
            let acknowledgement = u32::from(PROBE_ID.0) + 1;
            for (source_port, destination_port) in
                [(443, SOURCE_PORT), (DEST_PORT, SOURCE_PORT + 1)]
            {
                assert_eq!(
                    tcp_replies(target).identify(&received(
                        sockaddr(target, DEST_PORT),
                        &segment_between(target, source_port, destination_port, acknowledgement)
                    )),
                    None,
                    "{target} {source_port} -> {destination_port}"
                );
            }

            // Likewise, the error queue sees errors for every TCP segment the host sends us, but
            // errors quoting packets not belonging to us shouldn't be acted upon.
            let (probe, _) = traced_probe(target);
            let (_, other_trace) = traced_probe(target);
            assert_eq!(other_trace.identify(&reply(&probe[..8])), None, "{target}");
        }
    }

    /// Received replies that cannot acknowledge a probe are rejected.
    #[test]
    fn test_identify_rejects_zero_acknowledgement() {
        for target in TARGETS {
            assert_eq!(
                tcp_replies(target)
                    .identify(&received(sockaddr(target, DEST_PORT), &segment(target, 0))),
                None,
                "{target}"
            );
        }
    }

    /// Received replies are classified as belonging to the destination.
    #[test]
    fn test_classify_received_replies() {
        for target in TARGETS {
            assert_eq!(
                tcp_replies(target).classify(&received(
                    sockaddr(target, DEST_PORT),
                    &segment(target, u32::from(PROBE_ID.0) + 1)
                )),
                ReplyKind::Destination,
                "{target}"
            );
        }
    }

    /// "Host Unreachable" messages are ignored by the [`TcpReplies`] reader.
    #[test]
    fn test_tcp_replies_ignore_host_unreachable() {
        for target in TARGETS {
            assert!(tcp_replies(target).ignores_read_error(-libc::EHOSTUNREACH));
            assert!(!tcp_replies(target).ignores_read_error(-libc::ECONNREFUSED));
        }
    }
}
