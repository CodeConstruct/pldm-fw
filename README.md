# PLDM firmware update utility

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
