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
- the peer keepalive, which AmneziaWG 3.0 made a range;
- `AmneziaWireguardRange`, the value of every attribute the AmneziaWG 3.0
  module takes as a range: the magic headers, the keepalive and the device
  timing and padding attributes. One value `v` is `v.into()`.

Ranges are emitted in the form of the AmneziaWG 3.0 module (genl family
version 3). The forms older modules send, a magic header as a number or a
string and the keepalive as one interval, are read into the same ranges. A
device of an older module can still be read and given its other attributes,
but not a magic header or a keepalive.

Allowed IPs, flags, timestamps and commands are the upstream types, re-exported
under `AmneziaWireguard*` names.

## Installation

The crate is not published on crates.io. Add it as a git dependency on a release tag, one of the
[releases](https://github.com/slipmesh/netlink-packet-amneziawg/releases):

```toml
[dependencies]
netlink-packet-amneziawg = { git = "https://github.com/slipmesh/netlink-packet-amneziawg", tag = "v0.2.0" }
```

## Usage

See [`examples/get_amneziawg_info.rs`](examples/get_amneziawg_info.rs) and
[`examples/set_amneziawg.rs`](examples/set_amneziawg.rs).

## Tests

```bash
cargo test
```

The integration tests in `tests/integration.rs` create `amneziawg` interfaces.
They need the AmneziaWG 3.0 kernel module or later and root, and skip
themselves otherwise. `AWG_INTEGRATION=1` makes a test that cannot run here
fail instead of skip:

```bash
sudo -E env "PATH=$PATH" AWG_INTEGRATION=1 cargo test --test integration
```

## Release

Run the Release PR workflow (Actions, then Release PR). It opens `chore: release vX.Y.Z`, which
sets `version` in `Cargo.toml` to the version given, or else to the one the commits since the last
tag call for, and regenerates `CHANGELOG.md` with git-cliff. Merging that PR releases it: once
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
