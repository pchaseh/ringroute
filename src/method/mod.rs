mod icmp;

use std::{io, net::IpAddr, rc::Rc};

use socket2::{SockAddr, Socket};

pub use icmp::Icmp;

use crate::net::IcmpError;

/// One queue the trace reads from.
pub struct ReplyQueue {
    pub socket: Rc<Socket>,
    /// Read the socket's error queue rather than its receive queue.
    pub err_queue: bool,
    pub replies: Box<dyn Replies>,
}

/// Interprets the replies arriving on one queue.
pub trait Replies {
    /// Identify which probe a reply answers. A router only has to quote back
    /// the first eight bytes of the datagram it dropped, so any information
    /// needed must be encoded within them.
    fn identify(&self, reply: &Reply<'_>) -> Option<ProbeId>;

    /// Classify a reply.
    fn classify(&self, reply: &Reply<'_>) -> ReplyKind;

    /// Read errors that should be ignored because they indicate a queued error
    /// rather than a failure.
    fn ignores_read_error(&self, _error: i32) -> bool {
        false
    }
}

/// Identifies one probe in flight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeId(pub u16);

impl ProbeId {
    pub fn index(self) -> usize {
        usize::from(self.0)
    }
}

/// A response read from one of our queues.
pub struct Reply<'a> {
    pub source: Option<IpAddr>,
    /// Either the reply or the datagram an intermediate node quoted back.
    pub quoted: &'a [u8],
    /// Set when the reply arrived on the socket error queue.
    pub error: Option<IcmpError>,
}

/// Indicates what a reply means for the trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyKind {
    /// An intermediate hop.
    Hop,
    /// The target answered.
    Destination,
    /// Delivery failed.
    Unreachable(Unreachable),
}

/// Provides information about a failed probe delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unreachable {
    /// A named marker, such as `!N`.
    Marker(&'static str),
    /// A Destination Unreachable code with no named marker, shown as `!<code>`.
    Code(u8),
    /// Any other error, shown as `!<type-code>`.
    Other { icmp_type: u8, code: u8 },
    /// The probe exceeded the next hop's MTU, shown as `!F-<mtu>`.
    TooBig { mtu: u32 },
}

impl std::fmt::Display for Unreachable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Marker(marker) => formatter.write_str(marker),
            Self::Code(code) => write!(formatter, "!<{code}>"),
            Self::Other { icmp_type, code } => write!(formatter, "!<{icmp_type}-{code}>"),
            Self::TooBig { mtu } => write!(formatter, "!F-{mtu}"),
        }
    }
}

impl ReplyKind {
    /// Whether or not this kind of reply signals the completion of the trace.
    pub fn terminates_trace(self) -> bool {
        matches!(self, Self::Destination)
    }
}

/// Describes a probing method
pub trait Method {
    /// Open the socket probes are sent on and the queues replies come back on.
    fn open(&self) -> io::Result<(Rc<Socket>, Vec<ReplyQueue>)>;

    /// The datagram to send for `id`, and where to send it.
    fn probe(&self, id: ProbeId) -> (Vec<u8>, SockAddr);

    /// The largest reply this method can receive including the protocol's
    /// headers.
    fn max_reply_len(&self) -> usize;
}

#[cfg(test)]
mod test {
    use super::Unreachable;

    /// Markers render the way traceroute prints them.
    #[test]
    fn test_unreachable_display() {
        assert_eq!(Unreachable::Marker("!N").to_string(), "!N");
        assert_eq!(Unreachable::Code(99).to_string(), "!<99>");
        assert_eq!(
            Unreachable::Other {
                icmp_type: 11,
                code: 1
            }
            .to_string(),
            "!<11-1>"
        );
        assert_eq!(Unreachable::TooBig { mtu: 1400 }.to_string(), "!F-1400");
    }
}
