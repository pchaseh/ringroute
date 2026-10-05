use crate::method::{ReplyKind, Unreachable};

pub mod v4 {
    pub const ECHO_REQUEST: u8 = 8;

    pub const DEST_UNREACH: u8 = 3;
    pub const TIME_EXCEEDED: u8 = 11;
}

pub mod v6 {
    pub const ECHO_REQUEST: u8 = 128;

    pub const DEST_UNREACH: u8 = 1;
    pub const PACKET_TOO_BIG: u8 = 2;
    pub const TIME_EXCEEDED: u8 = 3;
}

/// An ICMP error reported through the socket error queue.
#[derive(Copy, Clone, Debug)]
pub enum IcmpError {
    V4 { icmp_type: u8, code: u8, info: u32 },
    V6 { icmp_type: u8, code: u8, info: u32 },
}

impl IcmpError {
    pub fn kind(&self) -> ReplyKind {
        let unreachable = match self {
            Self::V4 {
                icmp_type,
                code,
                info,
            } => match (*icmp_type, *code) {
                (v4::TIME_EXCEEDED, 0) => return ReplyKind::Hop,
                // "Port Unreachable" should only come from the destination.
                (v4::DEST_UNREACH, 3) => return ReplyKind::Destination,
                (v4::DEST_UNREACH, 0 | 6 | 8 | 11) => Unreachable::Marker("!N"),
                (v4::DEST_UNREACH, 1 | 7 | 12) => Unreachable::Marker("!H"),
                (v4::DEST_UNREACH, 9 | 10 | 13) => Unreachable::Marker("!X"),
                (v4::DEST_UNREACH, 2) => Unreachable::Marker("!P"),
                (v4::DEST_UNREACH, 4) => Unreachable::TooBig { mtu: *info },
                (v4::DEST_UNREACH, 5) => Unreachable::Marker("!S"),
                (v4::DEST_UNREACH, 14) => Unreachable::Marker("!V"),
                (v4::DEST_UNREACH, 15) => Unreachable::Marker("!C"),
                (v4::DEST_UNREACH, code) => Unreachable::Code(code),
                (icmp_type, code) => Unreachable::Other { icmp_type, code },
            },
            Self::V6 {
                icmp_type,
                code,
                info,
            } => match (*icmp_type, *code) {
                (v6::TIME_EXCEEDED, 0) => return ReplyKind::Hop,
                // "Port Unreachable" should only come from the destination.
                (v6::DEST_UNREACH, 4) => return ReplyKind::Destination,
                (v6::DEST_UNREACH, 0) => Unreachable::Marker("!N"),
                (v6::DEST_UNREACH, 1) => Unreachable::Marker("!X"),
                (v6::DEST_UNREACH, 2 | 3) => Unreachable::Marker("!H"),
                (v6::DEST_UNREACH, code) => Unreachable::Code(code),
                (v6::PACKET_TOO_BIG, _) => Unreachable::TooBig { mtu: *info },
                (icmp_type, code) => Unreachable::Other { icmp_type, code },
            },
        };

        ReplyKind::Unreachable(unreachable)
    }
}

#[cfg(test)]
mod test {
    use super::IcmpError;
    use crate::method::{ReplyKind, Unreachable};

    fn v4_error(icmp_type: u8, code: u8) -> IcmpError {
        IcmpError::V4 {
            icmp_type,
            code,
            info: 0,
        }
    }

    fn v6_error(icmp_type: u8, code: u8) -> IcmpError {
        IcmpError::V6 {
            icmp_type,
            code,
            info: 0,
        }
    }

    fn marker(marker: &'static str) -> ReplyKind {
        ReplyKind::Unreachable(Unreachable::Marker(marker))
    }

    fn other(icmp_type: u8, code: u8) -> ReplyKind {
        ReplyKind::Unreachable(Unreachable::Other { icmp_type, code })
    }

    mod v4 {
        use super::{marker, other, v4_error};
        use crate::{
            icmp::{IcmpError, v4::*},
            method::{ReplyKind, Unreachable},
        };

        /// An ICMP type `kind` does not handle.
        const SOURCE_QUENCH: u8 = 4;

        /// TTL expiry comes from an intermediate hop.
        #[test]
        fn test_ttl_exceeded_is_hop() {
            assert_eq!(v4_error(TIME_EXCEEDED, 0).kind(), ReplyKind::Hop);
        }

        /// Fragment reassembly timeouts are not treated as hops.
        #[test]
        fn test_reassembly_exceeded_is_other() {
            assert_eq!(v4_error(TIME_EXCEEDED, 1).kind(), other(TIME_EXCEEDED, 1));
        }

        /// Port Unreachable comes from the destination.
        #[test]
        fn test_port_unreachable_is_destination() {
            assert_eq!(v4_error(DEST_UNREACH, 3).kind(), ReplyKind::Destination);
        }

        /// Destination Unreachable codes map to traceroute's markers.
        #[test]
        fn test_dest_unreach_markers() {
            let cases = [
                (0, "!N"),
                (6, "!N"),
                (8, "!N"),
                (11, "!N"),
                (1, "!H"),
                (7, "!H"),
                (12, "!H"),
                (9, "!X"),
                (10, "!X"),
                (13, "!X"),
                (2, "!P"),
                (5, "!S"),
                (14, "!V"),
                (15, "!C"),
            ];

            for (code, expected) in cases {
                assert_eq!(
                    v4_error(DEST_UNREACH, code).kind(),
                    marker(expected),
                    "code {code}"
                );
            }
        }

        /// Fragmentation Needed reports the next hop's MTU.
        #[test]
        fn test_fragmentation_needed_reports_mtu() {
            let error = IcmpError::V4 {
                icmp_type: DEST_UNREACH,
                code: 4,
                info: 1400,
            };
            assert_eq!(
                error.kind(),
                ReplyKind::Unreachable(Unreachable::TooBig { mtu: 1400 })
            );
        }

        /// Destination Unreachable codes without a marker keep their code.
        #[test]
        fn test_unnamed_dest_unreach_code() {
            assert_eq!(
                v4_error(DEST_UNREACH, 99).kind(),
                ReplyKind::Unreachable(Unreachable::Code(99))
            );
        }

        /// Unhandled types keep their type and code.
        #[test]
        fn test_unhandled_type_is_other() {
            assert_eq!(v4_error(SOURCE_QUENCH, 0).kind(), other(SOURCE_QUENCH, 0));
        }
    }

    mod v6 {
        use super::{marker, other, v6_error};
        use crate::{
            icmp::{IcmpError, v6::*},
            method::{ReplyKind, Unreachable},
        };

        /// An ICMPv6 type `kind` does not handle.
        const PARAMETER_PROBLEM: u8 = 4;

        /// Hop limit expiry comes from an intermediate hop.
        #[test]
        fn test_hop_limit_exceeded_is_hop() {
            assert_eq!(v6_error(TIME_EXCEEDED, 0).kind(), ReplyKind::Hop);
        }

        /// Fragment reassembly timeouts are not treated as hops.
        #[test]
        fn test_reassembly_exceeded_is_other() {
            assert_eq!(v6_error(TIME_EXCEEDED, 1).kind(), other(TIME_EXCEEDED, 1));
        }

        /// Port Unreachable comes from the destination.
        #[test]
        fn test_port_unreachable_is_destination() {
            assert_eq!(v6_error(DEST_UNREACH, 4).kind(), ReplyKind::Destination);
        }

        /// Destination Unreachable codes map to traceroute's markers.
        #[test]
        fn test_dest_unreach_markers() {
            let cases = [(0, "!N"), (1, "!X"), (2, "!H"), (3, "!H")];

            for (code, expected) in cases {
                assert_eq!(
                    v6_error(DEST_UNREACH, code).kind(),
                    marker(expected),
                    "code {code}"
                );
            }
        }

        /// Packet Too Big reports the next hop's MTU.
        #[test]
        fn test_packet_too_big_reports_mtu() {
            let error = IcmpError::V6 {
                icmp_type: PACKET_TOO_BIG,
                code: 0,
                info: 1280,
            };
            assert_eq!(
                error.kind(),
                ReplyKind::Unreachable(Unreachable::TooBig { mtu: 1280 })
            );
        }

        /// Destination Unreachable codes without a marker keep their code.
        #[test]
        fn test_unnamed_dest_unreach_code() {
            assert_eq!(
                v6_error(DEST_UNREACH, 5).kind(),
                ReplyKind::Unreachable(Unreachable::Code(5))
            );
        }

        /// Unhandled types keep their type and code.
        #[test]
        fn test_unhandled_type_is_other() {
            assert_eq!(
                v6_error(PARAMETER_PROBLEM, 1).kind(),
                other(PARAMETER_PROBLEM, 1)
            );
        }
    }
}
