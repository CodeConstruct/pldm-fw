# PLDM firmware update utility

The PLDM firmware update utility **has moved**.

This code has been refactored into the
[`mctp-rs`](https://github.com/CodeConstruct/mctp-rs) workspace, so we now
have separate components for the MCTP, PLDM, and PLDM for Firmware Update
code.

These have all been published as Rust crates too; this particular one
is [`pldm-fw`](https://crates.io/crates/pldm-fw).

---

Simple utility to talk PLDM for Firmware Update (type 5) to a Firmware Device,
using the Linux MCTP networking support.

## Building

If cross compiling, an appropriate linker path needs to be added to either `~/.cargo/config.toml`, or
`.cargo/config.toml` in the source directory.

```toml
[target.armv7-unknown-linux-musleabihf]
linker = "arm-linux-gnueabihf-gcc"
```

Cross compile to an AST2600:

```
cargo build --release --target armv7-unknown-linux-musleabihf
```

Output executable is `./target/armv7-unknown-linux-musleabihf/release/pldm-fw`
