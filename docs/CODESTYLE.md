# Code style

## Formatting and lints

- `cargo fmt` with [`rustfmt.toml`](../rustfmt.toml): edition 2024, Unix newlines, field-init and
  `?` shorthand.
- `cargo clippy --all-targets -- -D warnings` with [`clippy.toml`](../clippy.toml); a warning is
  an error.
- Markdown follows [`.markdownlint-cli2.jsonc`](../.markdownlint-cli2.jsonc).

## What lives here

- Attributes AmneziaWG shares with WireGuard are parsed and emitted by `netlink-packet-wireguard`;
  this crate maps them to and from the upstream types and does not encode them itself.
- Types AmneziaWG did not change are the upstream types, re-exported under an `AmneziaWireguard*`
  name in `lib.rs`. A type gets its own definition only when its wire format differs.

## Naming

- Public types are `AmneziaWireguard*`, so they can be used next to the upstream `Wireguard*`
  types. Variants keep the upstream name where the attribute is shared.
- Netlink constants carry the kernel UAPI name and value: `WGDEVICE_A_*`, `WGPEER_A_*`.
- Unit tests are named `test_<subject>` for the attribute or behaviour they pin:
  `test_device_peer_wire_format`, `test_keepalive_range_roundtrip`.

## Error handling

- Parsing code does not `unwrap` or index into a payload without checking its length; it reads
  through the `parse_*` helpers and returns their `DecodeError` with a `.context()` naming the
  kernel attribute: `"invalid WGDEVICE_A_JC value"`.
- Emitting may `unwrap` the `emit_*` helpers: the buffer is sized by the same `value_len`, so a
  failure there is a bug in this crate, not bad input.
- No silent fallback values. A case the code has already ruled out panics with the reason
  (`unreachable!` or `expect`); it never ends in a default such as `0` that would go out on the
  wire.

## Layout

- One module per netlink nesting level: `message.rs` for the family, `attribute.rs` for device
  attributes, `peer.rs` for peers; `range.rs` holds the AmneziaWG range wire format.
- Tests of the wire format sit in `src/test.rs`, compiled on little-endian targets only because
  their byte captures are little-endian. A helper with no wire bytes, such as `range.rs`, keeps
  its tests in a `#[cfg(test)] mod tests` at the end of its own file. Tests that need the kernel
  module sit in `tests/integration.rs` and skip themselves without it.
- A change to the wire format comes with a test that pins the bytes, not only a roundtrip: a
  roundtrip passes when emit and parse are wrong the same way.

## Comments

Code says what it does; a comment says only why it has to be that way - an external constraint
or a non-obvious consequence, most often how a kernel module version puts an attribute on the
wire. No history of how the code got here, and no pointers to files or functions in other
repositories.
