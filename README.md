# netlink-packet-amneziawg

Parses and emits [AmneziaWG](https://docs.amnezia.org/documentation/amnezia-wg/)
generic netlink packets on Linux, the same way the `awg` tool configures
AmneziaWG interfaces through the kernel module.

The crate is built on
[`netlink-packet-wireguard`](https://crates.io/crates/netlink-packet-wireguard).
Attributes AmneziaWG shares with WireGuard are parsed and emitted by that
crate; this one adds:

- the `amneziawg` generic netlink family;
- the device attributes AmneziaWG appends (junk packets, magic headers,
  header protection, timers, the 3.1 flags) and `WGDEVICE_A_PEER`;
- the peer keepalive, which the AmneziaWG 3.0 module sends as a `u32` range
  instead of WireGuard's `u16`.

Allowed IPs, flags, timestamps and commands are the upstream types, re-exported
under `AmneziaWireguard*` names.

## Installation

The crate is not published on crates.io. Add it as a git dependency:

```toml
[dependencies]
netlink-packet-amneziawg = { git = "https://github.com/slipmesh/netlink-packet-amneziawg" }
```

## Usage

See [`examples/get_amneziawg_info.rs`](examples/get_amneziawg_info.rs) and
[`examples/set_amneziawg.rs`](examples/set_amneziawg.rs).

## Tests

```bash
cargo test
```

The integration tests in `tests/integration.rs` create `amneziawg` interfaces.
They need the AmneziaWG kernel module and root, and skip themselves otherwise:

```bash
sudo -E env "PATH=$PATH" cargo test --test integration
```

## License

[MIT](LICENSE-MIT).

## Acknowledgements

The AmneziaWG attribute handling, the tests and the examples come from
[frkn-dev/netlink-packet-amnezia-wireguard](https://github.com/frkn-dev/netlink-packet-amnezia-wireguard),
itself a fork of
[rust-netlink/netlink-packet-wireguard](https://github.com/rust-netlink/netlink-packet-wireguard),
on which this crate now builds.
