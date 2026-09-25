use std::{
    io, mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::AsRawFd,
};

use socket2::{Domain, Socket};

/// Minimum IPv4 header length.
pub const MIN_IPV4_HEADER_LEN: usize = 20;

/// Enable `IP_RECVERR`/`IPV6_RECVERR` on the socket so ICMP errors can be
/// read from the socket error queue.
pub fn enable_recverr(socket: &Socket) -> io::Result<()> {
    let (level, name) = if socket.domain()? == Domain::IPV6 {
        (libc::IPPROTO_IPV6, libc::IPV6_RECVERR)
    } else {
        (libc::IPPROTO_IP, libc::IP_RECVERR)
    };

    let enabled: libc::c_int = 1;
    // SAFETY: `setsockopt` completes immediately, so `enabled` cannot be
    // use before freed
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            name,
            (&raw const enabled).cast(),
            mem::size_of_val(&enabled) as libc::socklen_t,
        )
    };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

/// An ICMP error reported through the socket error queue.
#[derive(Debug, Clone, Copy)]
pub struct IcmpError {
    pub icmp_type: u8,
    pub icmp_code: u8,
    /// Type-specific data, such as the next hop's MTU when fragmentation is
    /// needed.
    pub info: u32,
}

/// Contains a subset of the `sock_extended_err` fields that are of interest.
pub struct ExtendedError<'a> {
    pub error: IcmpError,
    pub source_bytes: &'a [u8],
}

/// Equivalent of Linux's `CMSG_ALIGN` macro.
const fn cmsg_align(length: usize) -> usize {
    let align = mem::size_of::<usize>();
    (length + align - 1) & !(align - 1)
}

/// The aligned size of a `cmsghdr`, which is where a cmsg's data begins.
const CMSG_HEADER_LEN: usize = cmsg_align(mem::size_of::<libc::cmsghdr>());

/// Room for the cmsgs an error queue read produces: `IP_RECVERR`'s
/// `sock_extended_err` plus the address of whoever sent the error, sized for
/// the widest family we can open. Enabling more IP options appends more cmsgs.
// SAFETY: `CMSG_SPACE` only performs arithmetic on its argument.
pub const RECVERR_CONTROL_LEN: usize = unsafe {
    libc::CMSG_SPACE(
        (mem::size_of::<libc::sock_extended_err>() + mem::size_of::<libc::sockaddr_in6>()) as u32,
    )
} as usize;

/// Parse a `sockaddr_in` or `sockaddr_in6` if `bytes` contains one, or else return `None`
pub fn parse_sockaddr(bytes: &[u8]) -> Option<IpAddr> {
    let family = u16::from_ne_bytes(bytes.get(..2)?.try_into().ok()?);

    match i32::from(family) {
        libc::AF_INET => {
            let address = bytes
                .get(..mem::size_of::<libc::sockaddr_in>())?
                .as_ptr()
                .cast::<libc::sockaddr_in>();
            // SAFETY: `get` checked the length, and an unaligned read needs no more.
            let address = unsafe { address.read_unaligned() };

            Some(IpAddr::V4(Ipv4Addr::from(
                address.sin_addr.s_addr.to_ne_bytes(),
            )))
        }
        libc::AF_INET6 => {
            let address = bytes
                .get(..mem::size_of::<libc::sockaddr_in6>())?
                .as_ptr()
                .cast::<libc::sockaddr_in6>();
            // SAFETY: `get` checked the length, and an unaligned read needs no more.
            let address = unsafe { address.read_unaligned() };

            Some(IpAddr::V6(Ipv6Addr::from(address.sin6_addr.s6_addr)))
        }
        _ => None,
    }
}

pub fn parse_ip_recverr(control: &[u8]) -> Option<ExtendedError<'_>> {
    let mut offset = 0;

    while offset + mem::size_of::<libc::cmsghdr>() <= control.len() {
        // SAFETY: The loop condition leaves a whole `cmsghdr` in bounds.
        let header = unsafe {
            control
                .as_ptr()
                .add(offset)
                .cast::<libc::cmsghdr>()
                .read_unaligned()
        };

        let cmsg_len = header.cmsg_len;
        let cmsg_end = offset.checked_add(cmsg_len)?;
        if cmsg_len < CMSG_HEADER_LEN || cmsg_end > control.len() {
            return None;
        }

        if matches!(
            (header.cmsg_level, header.cmsg_type),
            (libc::IPPROTO_IP, libc::IP_RECVERR) | (libc::IPPROTO_IPV6, libc::IPV6_RECVERR)
        ) {
            let data_offset = offset + CMSG_HEADER_LEN;
            let error_end = data_offset + mem::size_of::<libc::sock_extended_err>();
            if error_end > cmsg_end {
                return None;
            }

            // SAFETY: `error_end` was checked against the end of this cmsg.
            let error = unsafe {
                control
                    .as_ptr()
                    .add(data_offset)
                    .cast::<libc::sock_extended_err>()
                    .read_unaligned()
            };

            if !matches!(
                error.ee_origin,
                libc::SO_EE_ORIGIN_ICMP | libc::SO_EE_ORIGIN_ICMP6
            ) {
                return None;
            }

            return Some(ExtendedError {
                error: IcmpError {
                    icmp_type: error.ee_type,
                    icmp_code: error.ee_code,
                    info: error.ee_info,
                },
                source_bytes: &control[error_end..cmsg_end],
            });
        }

        offset += cmsg_align(cmsg_len);
    }

    None
}

#[expect(dead_code, reason = "kept for future methods that send on raw sockets")]
pub fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0_u32;

    for chunk in bytes.chunks(2) {
        sum += u32::from(u16::from_be_bytes([
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
        ]));
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !(sum as u16)
}
