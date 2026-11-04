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

The crate is not published on crates.io. Add it as a git dependency on a release tag, one of the
[releases](https://github.com/slipmesh/netlink-packet-amneziawg/releases):

```toml
[dependencies]
netlink-packet-amneziawg = { git = "https://github.com/slipmesh/netlink-packet-amneziawg", tag = "v0.1.0" }
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

## Release

Run the Release PR workflow (Actions, then Release PR). It opens `chore: release vX.Y.Z`, which
sets `version` in `Cargo.toml` to the next version the commits since the last tag call for, or to
the version given, and regenerates `CHANGELOG.md` with git-cliff. Merging that PR releases it: once
the checks of that push pass, the commit is tagged `vX.Y.Z` and gets a GitHub Release with its
`CHANGELOG.md` section as the notes. Nothing is built; the tag is what a consumer depends on.

Every other push and pull request runs only the checks, and `cargo audit` also runs weekly.

## License

[MIT](LICENSE-MIT).

## Acknowledgements

The AmneziaWG attribute handling, the tests and the examples come from
[frkn-dev/netlink-packet-amnezia-wireguard](https://github.com/frkn-dev/netlink-packet-amnezia-wireguard),
itself a fork of
[rust-netlink/netlink-packet-wireguard](https://github.com/rust-netlink/netlink-packet-wireguard),
on which this crate now builds.
