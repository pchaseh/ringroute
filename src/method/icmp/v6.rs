use crate::method::{Reply, ReplyKind, Unreachable};

pub(crate) const ECHO_REQUEST: u8 = 128;

const DEST_UNREACH: u8 = 1;
const PACKET_TOO_BIG: u8 = 2;
const TIME_EXCEEDED: u8 = 3;

pub(crate) fn classify(reply: &Reply<'_>) -> ReplyKind {
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

#[cfg(test)]
mod test {
    use std::net::{IpAddr, Ipv6Addr, SocketAddr};

    use socket2::SockAddr;

    use crate::{
        method::{
            Icmp, Method, ProbeId, Reply, ReplyKind, Unreachable,
            icmp::v6::{DEST_UNREACH, ECHO_REQUEST, PACKET_TOO_BIG, TIME_EXCEEDED, classify},
        },
        net::{IPV6_HEADER_LENGTH, IcmpError},
    };

    const TARGET: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);
    const PACKET_LENGTH: usize = 60;
    const PROBE_ID: ProbeId = ProbeId(1234);

    const PARAMETER_PROBLEM: u8 = 4;

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

    fn icmp_error(icmp_type: u8, icmp_code: u8, info: u32) -> Option<IcmpError> {
        Some(IcmpError {
            icmp_type,
            icmp_code,
            info,
        })
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
            assert_eq!(classify(&reply(&[], error)), expected, "{error:?}");
        }
    }
}
