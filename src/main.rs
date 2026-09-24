mod method;
mod net;
mod trace;

use std::{
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    time::Duration,
};

use anyhow::{Context, bail};
use clap::{Parser, ValueEnum};

use method::Icmp;
use trace::Probe;

#[derive(Copy, Clone, Debug, ValueEnum)]
enum MethodArg {
    Icmp,
}

impl MethodArg {
    fn build(self, target: IpAddr, packet_len: usize) -> anyhow::Result<Box<dyn method::Method>> {
        match (self, target) {
            (Self::Icmp, IpAddr::V4(target)) => Ok(Box::new(Icmp::try_new(target, packet_len)?)),
            (Self::Icmp, IpAddr::V6(_)) => bail!("method icmp unsupported for IPv6"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum IpVersionArg {
    /// Use the IP version of --target if it is an IP address, or the resolver's first answer for a hostname.
    Auto,
    /// Use IPv4. --target must either be an IPv4 address or a hostname that resolves to at least one IPv4 address.
    V4,
    /// Use IPv6. --target must either be an IPv6 address or a hostname that resolves to at least one IPv6 address.
    V6,
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub(crate) struct Args {
    /// Target IP address or hostname to traceroute to. When a hostname, the first answer returned is used.
    #[arg(long)]
    target: String,

    /// Hop to start the trace at.
    #[arg(short, long, default_value_t = 1, value_parser = clap::value_parser!(u8).range(1..))]
    first_hop: u8,

    /// Max number of hops.
    #[arg(short = 'H', long, default_value_t = 30, value_parser = clap::value_parser!(u8).range(1..))]
    max_hops: u8,

    /// Max number of seconds to wait for responses.
    #[arg(short, long = "timeout-secs", value_name = "TIMEOUT_SECS", default_value = "5", value_parser = |s: &str| s.parse().map(Duration::from_secs))]
    timeout: Duration,

    /// Packet size to use for probes, including IP headers.
    #[arg(short, long, default_value_t = 60)]
    size: usize,

    /// Method to use for probes.
    #[arg(short, long, value_enum, default_value_t = MethodArg::Icmp)]
    method: MethodArg,

    /// IP version to use.
    #[arg(short, long, value_enum, default_value_t = IpVersionArg::Auto)]
    ip_version: IpVersionArg,
}

/// Print the results of a trace to standard output.
fn print_results(probes: &[Probe]) {
    for probe in probes {
        match &probe.result {
            Some(result) => {
                println!("{:>2}  {result}", probe.ttl);
                // Because we submitted every probe at once, we'll observe
                // multiple replies if the maximum TTL exceeded the final hop.
                if result.kind.terminates_trace() {
                    break;
                }
            }
            None => println!("{:>2}  *", probe.ttl),
        }
    }
}

const fn ip_version_matches(addr: &IpAddr, want: IpVersionArg) -> bool {
    match want {
        IpVersionArg::Auto => true,
        IpVersionArg::V4 => addr.is_ipv4(),
        IpVersionArg::V6 => addr.is_ipv6(),
    }
}

/// Returns [`Some`] if `addr` is an IP address, or [`None`] otherwise
fn maybe_ip(addr: &str) -> Option<IpAddr> {
    if let Ok(addr) = addr.parse::<SocketAddr>() {
        return Some(addr.ip());
    }

    if let Ok(addr) = addr.parse::<IpAddr>() {
        return Some(addr);
    }

    None
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    env_logger::init();

    if args.first_hop >= args.max_hops {
        bail!("--first-hop must be less than --max-hops")
    }

    let target = if let Some(addr) = maybe_ip(&args.target) {
        if !ip_version_matches(&addr, args.ip_version) {
            bail!("--target IP version does not match --ip-version ")
        }

        addr
    } else {
        // Even if an AAAA query was also issued on an IPv4-only system,
        // RFC 6724 destination address selection should yield an IPv4 address
        // as the first answer so [`IpVersionArg::Auto`] shouldn't yield an
        // unreachable address family.
        format!("{}:0", args.target)
            .to_socket_addrs()?
            .find(|addr| ip_version_matches(&addr.ip(), args.ip_version))
            .context("DNS lookup returned no answers matching the requested --ip-version")?
            .ip()
    };

    let method = args.method.build(target, args.size)?;

    println!(
        "tracing {} ({target}), {} hops max, {} byte packets",
        args.target, args.max_hops, args.size
    );

    let probes = trace::run(
        method.as_ref(),
        args.first_hop..=args.max_hops,
        args.timeout,
    )?;
    print_results(&probes);

    Ok(())
}
