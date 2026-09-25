# ringroute

A minimal traceroute built on [io_uring](https://kernel.dk/io_uring.pdf).

## Goal

ringroute exists to demonstrate io_uring usage. At this time, it is **not**
meant to be a replacement for `traceroute`, `mtr`, or any other production
network diagnostic tool. Not only is there no guarantee of feature parity, but
the use of modern kernel features limits which environments this can be run in.

## How it works

At its core, ringroute works like any other traceroute tool. Each router that
forwards an IP packet decrements its time-to-live (TTL) by one. If decrementing
the TTL would reduce it to zero, the router discards the packet and will
typically send an ICMP Time Exceeded message back to the sender. These responses
reveal the router's own IP address. To discover the path to a target, ringroute
sends probes with increasing TTL values. A probe sent with TTL _N_ expires at
the _N_th hop, allowing us to identify that device from its ICMP response.

## Usage

To build from source:
```sh
git clone git@github.com:pchaseh/ringroute.git
cd ringroute
cargo build --release
```

Run with `--help` to see usage:
```sh
./ringroute --help
```

ringroute uses [env_logger](https://github.com/rust-cli/env_logger) for
application logging. The `RUST_LOG` environment variable can be used to set the
log level:
```sh
RUST_LOG=debug ./ringroute . . .
````
When not set, `RUST_LOG` defaults to `error`.

## Requirements

- Linux 6.0 or newer compiled with `CONFIG_IO_URING=y`
- Rust toolchain (including Cargo)

## Limitations

- One probe is sent per hop, and all hops are probed at once.
- The trace always waits for the full timeout before printing results.
- Options to influence routing (eg. specifying source address, network device)
  are not implemented.
