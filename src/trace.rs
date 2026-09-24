use std::{
    io,
    marker::PhantomPinned,
    mem,
    net::IpAddr,
    ops::RangeInclusive,
    os::fd::{AsFd, AsRawFd, BorrowedFd},
    pin::Pin,
    time::{Duration, Instant},
};

use anyhow::{Context, bail};
use bitfield_struct::bitfield;
use io_uring::{
    IoUring, cqueue, opcode, squeue,
    types::{self, RecvMsgOut},
};
use io_uring_buf_ring::IoUringBufRing;
use log::error;
use slab::Slab;
use socket2::{Domain, SockAddr};

use crate::{
    method::{Method, ProbeId, Reply, ReplyKind, ReplyQueue},
    net::{RECVERR_CONTROL_LEN, enable_recverr, parse_ip_recverr, parse_sockaddr},
};

/// The maximum space needed for the address a reply came from, which is
/// the size of `sockaddr_in6`.
const NAME_LEN: usize = mem::size_of::<libc::sockaddr_in6>();

/// `io_recvmsg_out` (four `u32`s) plus the `NAME_LEN` bytes of name data and
/// `RECVERR_CONTROL_LEN` bytes of control data we reserve.
const RECVMSG_OVERHEAD: usize = 4 * mem::size_of::<u32>() + NAME_LEN + RECVERR_CONTROL_LEN;

/// Possible states an io_uring event can represent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub(crate) enum State {
    Write = 0,
    Read,
    Timeout,
}

impl State {
    const fn into_bits(self) -> u64 {
        self as _
    }

    pub(crate) const fn from_bits(value: u64) -> Self {
        match value {
            0 => Self::Write,
            1 => Self::Read,
            2 => Self::Timeout,
            _ => panic!("unexpected value"),
        }
    }
}

#[bitfield(u64)]
pub struct UserData {
    /// The slab key of a write, or the index of a reader.
    pub slot: u16,
    #[bits(48)]
    pub state: State,
}

pub struct Probe {
    pub ttl: u8,
    sent_at: Option<Instant>,
    pub result: Option<HopResult>,
}

pub struct HopResult {
    pub source: Option<IpAddr>,
    pub rtt: Duration,
    pub kind: ReplyKind,
}

impl std::fmt::Display for HopResult {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let source = self
            .source
            .map_or(String::from("?"), |source| source.to_string());

        write!(
            formatter,
            "{source}  {:.3} ms",
            self.rtt.as_secs_f64() * 1_000.0
        )?;
        if let ReplyKind::Unreachable(annotation) = self.kind {
            write!(formatter, "  {annotation}")?;
        }

        Ok(())
    }
}

/// A probe's send buffers, which must outlive the send completion.
///
/// `msg` points into the other fields, so this is only ever handed out pinned.
struct Outgoing {
    packet: Vec<u8>,
    destination: SockAddr,
    iov: libc::iovec,
    control: HopLimitControl,
    msg: libc::msghdr,
    probe: ProbeId,
    _pin: PhantomPinned,
}

#[repr(C)]
struct HopLimitControl {
    header: libc::cmsghdr,
    hop_limit: libc::c_int,
}

impl HopLimitControl {
    fn new(domain: Domain, hop_limit: u8) -> Self {
        let (level, option) = if domain == Domain::IPV6 {
            (libc::IPPROTO_IPV6, libc::IPV6_HOPLIMIT)
        } else {
            (libc::IPPROTO_IP, libc::IP_TTL)
        };

        Self {
            header: libc::cmsghdr {
                // SAFETY: `CMSG_LEN` only performs arithmetic on its argument.
                cmsg_len: unsafe { libc::CMSG_LEN(mem::size_of::<libc::c_int>() as u32) } as usize,
                cmsg_level: level,
                cmsg_type: option,
            },
            hop_limit: hop_limit.into(),
        }
    }
}

impl Outgoing {
    fn new(packet: Vec<u8>, destination: SockAddr, ttl: u8, probe: ProbeId) -> Pin<Box<Self>> {
        let control = HopLimitControl::new(destination.domain(), ttl);
        let mut outgoing = Box::new(Self {
            packet,
            destination,
            iov: libc::iovec {
                iov_base: std::ptr::null_mut(),
                iov_len: 0,
            },
            control,
            // SAFETY: A zeroed `msghdr` is valid before its fields are populated.
            msg: unsafe { mem::zeroed() },
            probe,
            _pin: PhantomPinned,
        });

        outgoing.iov = libc::iovec {
            iov_base: outgoing.packet.as_mut_ptr().cast(),
            iov_len: outgoing.packet.len(),
        };
        outgoing.msg = libc::msghdr {
            msg_name: outgoing.destination.as_ptr().cast_mut().cast(),
            msg_namelen: outgoing.destination.len(),
            msg_iov: &raw mut outgoing.iov,
            msg_iovlen: 1,
            msg_control: (&raw mut outgoing.control).cast(),
            msg_controllen: mem::size_of::<HopLimitControl>(),
            msg_flags: 0,
        };

        Box::into_pin(outgoing)
    }
}

/// Schedule a probe to be written to `fd` and record the outgoing probe
/// details in `sending`.
fn schedule_write(
    fd: BorrowedFd<'_>,
    sending: &mut Slab<Pin<Box<Outgoing>>>,
    method: &dyn Method,
    id: ProbeId,
    ttl: u8,
    sq: &mut squeue::SubmissionQueue,
) -> anyhow::Result<()> {
    let (packet, destination) = method.probe(id);
    let slot = sending.insert(Outgoing::new(packet, destination, ttl, id));

    let entry = opcode::SendMsg::new(types::Fd(fd.as_raw_fd()), &sending[slot].msg)
        .build()
        .user_data(
            UserData::new()
                .with_slot(slot as u16)
                .with_state(State::Write)
                .into_bits(),
        );

    // SAFETY: Caller must ensure that the `sending` entry will survive until
    // the corresponding write completion arrives.
    if let Err(error) = unsafe { sq.push(&entry) } {
        sending.remove(slot);
        return Err(error.into());
    }

    Ok(())
}

/// A multishot read kept outstanding for the whole trace.
struct Multishot<'a> {
    queue: &'a ReplyQueue,
    slot: u16,
    msghdr: libc::msghdr,
}

impl<'a> Multishot<'a> {
    fn try_new(queue: &'a ReplyQueue, slot: u16) -> io::Result<Self> {
        if queue.err_queue {
            enable_recverr(&queue.socket)?;
        }

        // SAFETY: A zeroed `msghdr` is valid, and multishot recvmsg only reads
        // `msg_namelen` and `msg_controllen` from this template.
        let mut msghdr: libc::msghdr = unsafe { mem::zeroed() };
        msghdr.msg_namelen = NAME_LEN as libc::socklen_t;
        msghdr.msg_controllen = if queue.err_queue {
            RECVERR_CONTROL_LEN
        } else {
            0
        };

        Ok(Self {
            queue,
            slot,
            msghdr,
        })
    }

    /// Schedule a multishot `recvmsg` request.
    ///
    /// This request will repeatedly post a completion. Callers must check
    /// whether or not the `IORING_CQE_F_MORE` flag is set on the resulting
    /// completions and reschedule the request if not.
    fn schedule(&self, sq: &mut squeue::SubmissionQueue) -> Result<(), squeue::PushError> {
        let fd = types::Fd(self.queue.socket.as_raw_fd());
        let entry = opcode::RecvMsgMulti::new(fd, &self.msghdr, 0)
            .flags(if self.queue.err_queue {
                libc::MSG_ERRQUEUE as u32
            } else {
                0
            })
            .build()
            .user_data(
                UserData::new()
                    .with_slot(self.slot)
                    .with_state(State::Read)
                    .into_bits(),
            );

        // SAFETY: `self` is pointed at by every read it schedules, and neither
        // moves nor drops before they complete.
        unsafe { sq.push(&entry) }
    }
}

/// Given a completion representing a successful receive, process the response.
///
/// Records a [`HopResult`] for the probe the reply answers, unless that probe
/// already has one.
fn handle_read(
    cqe: &cqueue::Entry,
    buf_ring: &IoUringBufRing<Vec<u8>>,
    reader: &Multishot<'_>,
    probes: &mut [Probe],
) {
    let buffer_id = cqueue::buffer_select(cqe.flags()).expect("read has a buffer ID");

    let len = cqe.result() as usize;
    // recvmsg takes up space even if we in theory read zero data.
    assert!(len > 0);

    // SAFETY: The completion names the buffer it filled and how much it wrote.
    let buffer =
        unsafe { buf_ring.get_buf(buffer_id, len) }.expect("buffer ring contains buffer ID");
    let message = RecvMsgOut::parse(&buffer, &reader.msghdr).expect("parsing msghdr");

    let (source, error) = if reader.queue.err_queue {
        if message.is_control_data_truncated() {
            error!("error queue cmsg did not fit in {RECVERR_CONTROL_LEN} bytes");
            return;
        }

        let Some(extended) = parse_ip_recverr(message.control_data()) else {
            return;
        };
        (parse_sockaddr(extended.source_bytes), Some(extended.error))
    } else {
        (parse_sockaddr(message.name_data()), None)
    };
    let reply = Reply {
        source,
        quoted: message.payload_data(),
        error,
    };

    let Some(probe) = reader
        .queue
        .replies
        .identify(&reply)
        .and_then(|probe| probes.get_mut(probe.index()))
    else {
        return;
    };
    if probe.result.is_some() {
        return;
    }
    let Some(sent_at) = probe.sent_at else {
        return;
    };

    probe.result = Some(HopResult {
        source: reply.source,
        rtt: sent_at.elapsed(),
        kind: reader.queue.replies.classify(&reply),
    });
}

/// Check that all io_uring features in use are supported on this system.
fn check_features_supported() -> anyhow::Result<()> {
    {
        let ring: &IoUring<squeue::Entry, cqueue::Entry> =
            &mut IoUring::builder().setup_r_disabled().build(1)?;
        let mut probe = io_uring::Probe::new();
        ring.submitter()
            .register_probe(&mut probe)
            .context("registering probe")?;

        // Multishot recvmsg was introduced in Linux 6.0
        if !probe.is_supported(opcode::RecvMsgMulti::CODE) {
            bail!("recvmsg_multishot is unsupported");
        }
    }

    Ok(())
}

pub fn run(
    method: &dyn Method,
    hops: RangeInclusive<u8>,
    timeout: Duration,
) -> anyhow::Result<Vec<Probe>> {
    check_features_supported()?;

    let (socket, queues) = method.open()?;
    let fd = socket.as_fd();

    let mut probes = hops
        .map(|ttl| Probe {
            ttl,
            sent_at: None,
            result: None,
        })
        .collect::<Vec<_>>();

    // One send per probe, one read per reader, plus our timeout.
    let ring_size = queues.len() + probes.len() + 1;
    let mut ring = IoUring::new(u32::try_from(ring_size)?)?;

    let buf_ring = IoUringBufRing::new_with_flags(
        &ring,
        // One buffer per probe in theory, but in reality we can require more if
        // buffers can't be recycled before getting queued.
        2 * u16::try_from(probes.len())?,
        0,
        RECVMSG_OVERHEAD + method.max_reply_len(),
        0,
    )?;

    let (submitter, mut sq, mut cq) = ring.split();

    // The kernel keeps a pointer into each `msghdr` for the life of its
    // multishot read, so the readers must not move again.
    let readers = queues
        .iter()
        .enumerate()
        .map(|(index, queue)| Multishot::try_new(queue, index as u16))
        .collect::<io::Result<Box<[_]>>>()?;

    for reader in &readers {
        reader.schedule(&mut sq)?;
    }

    let mut sending = Slab::new();

    for (index, probe) in probes.iter().enumerate() {
        schedule_write(
            fd,
            &mut sending,
            method,
            ProbeId(index as u16),
            probe.ttl,
            &mut sq,
        )?;
    }

    let timeout_ts: types::Timespec = timeout.into();
    let timeout_entry = opcode::Timeout::new(&timeout_ts)
        .build()
        .user_data(UserData::new().with_state(State::Timeout).into_bits());
    // SAFETY: `timeout_ts` has the same lifetime as the ring.
    unsafe { sq.push(&timeout_entry)? };

    sq.sync();

    loop {
        match submitter.submit_and_wait(1) {
            Ok(_) => (),
            Err(ref err) if err.raw_os_error() == Some(libc::EBUSY) => (),
            Err(err) => return Err(err.into()),
        }
        cq.sync();

        for cqe in &mut cq {
            let ret = cqe.result();
            let user_data: UserData = cqe.user_data().into();
            let state = user_data.state();

            let failed = match state {
                // A successful timeout results in `-libc::ETIME`
                State::Timeout => ret != -libc::ETIME,
                State::Write => {
                    let outgoing = sending.remove(usize::from(user_data.slot()));
                    if ret >= 0 {
                        probes[outgoing.probe.index()].sent_at = Some(Instant::now());
                    }
                    ret < 0
                }
                State::Read => {
                    let reader = &readers[usize::from(user_data.slot())];

                    if ret >= 0 {
                        handle_read(&cqe, &buf_ring, reader, &mut probes);
                    }

                    if !cqueue::more(cqe.flags()) {
                        reader.schedule(&mut sq)?;
                    }

                    // Ignore errors on the receive queue that we expect to see on the
                    // error queue. We can observe these if there are queued socket errors
                    // we have yet to read from the error queue
                    ret < 0 && !reader.queue.replies.ignores_read_error(ret)
                }
            };

            if failed {
                let error = io::Error::from_raw_os_error(-ret);
                error!("error completing {state:?}: {error:?}");
            }
            if state == State::Timeout {
                return Ok(probes);
            }
        }

        sq.sync();
    }
}
