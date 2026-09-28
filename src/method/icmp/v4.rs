use crate::method::{Reply, ReplyKind, Unreachable};

pub(crate) const ECHO_REQUEST: u8 = 8;

const DEST_UNREACH: u8 = 3;
const TIME_EXCEEDED: u8 = 11;

pub(crate) fn classify(reply: &Reply<'_>) -> ReplyKind {
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

#[cfg(test)]
mod test {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use socket2::SockAddr;

    use crate::{
        method::{
            Icmp, Method, ProbeId, Reply, ReplyKind, Unreachable,
            icmp::v4::{DEST_UNREACH, ECHO_REQUEST, TIME_EXCEEDED, classify},
        },
        net::{IcmpError, MIN_IPV4_HEADER_LEN},
    };

    const TARGET: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    const PACKET_LENGTH: usize = 60;
    const PROBE_ID: ProbeId = ProbeId(1234);

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
            assert_eq!(classify(&reply(&[], error)), expected, "{error:?}");
        }
    }
}
