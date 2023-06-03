// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * PLDM firmware update utility.
 *
 * Copyright (c) 2023 Code Construct
 */

mod mctp;
mod pldm;
mod pldm_fw;

use clap::{Parser, Subcommand};
use enumset::{EnumSet, EnumSetType};
use std::fmt::Write;

fn comma_separated<T: EnumSetType + std::fmt::Debug>(e: EnumSet<T>) -> String {
    let mut s = String::new();
    let mut first = true;
    for i in e.iter() {
        write!(s, "{}{:?}", if first { "" } else { "," }, i).unwrap();
        first = false;
    }
    s
}

fn print_device_info(
    dev: &pldm_fw::DeviceIdentifiers,
    fwp: &pldm_fw::FirmwareParameters,
) {
    println!("Device: {}", dev);
    println!("Firmware Parameters:");
    println!("  Active version:  {}", fwp.active);
    println!("  Pending version: {}", fwp.pending);
    println!(
        "  Update caps: [0x{:x}]:{}",
        fwp.caps.as_u32(),
        if fwp.caps.is_empty() { " none" } else { "" }
    );
    for cap in fwp.caps.iter() {
        println!("    * {:?}", cap);
    }
    println!(
        "  Components:{}",
        if fwp.components.is_empty() { " none" } else { "" }
    );
    for (idx, comp) in fwp.components.iter().enumerate() {
        println!("    [{}]", idx);
        println!("      Classification:  {:?}", comp.classification);
        println!("      Index:           {:?}", comp.classificationindex);
        println!("      Identifier:      0x{:04x}", comp.identifier);
        println!("      Active Version:  {}", comp.active);
        println!("      Pending Version: {}", comp.pending);
        println!(
            "      Activation:      [0x{:x}] {}",
            comp.activation_methods.as_u32(),
            comma_separated(comp.activation_methods)
        );
        println!(
            "      Update caps:     [0x{:x}] {}",
            comp.caps_during_update.as_u32(),
            comma_separated(comp.caps_during_update)
        );
    }
}

fn eid_parse(s: &str) -> Result<u8, String> {
    const HEX_PREFIX: &str = "0x";
    const HEX_PREFIX_LEN: usize = HEX_PREFIX.len();

    let result = if s.to_ascii_lowercase().starts_with(HEX_PREFIX) {
        u8::from_str_radix(&s[HEX_PREFIX_LEN..], 16)
    } else {
        s.parse()
    };

    result.map_err(|e| e.to_string())
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// MCTP EID of device
    #[clap(value_parser=eid_parse)]
    eid: u8,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    Inventory,
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();
    let sock = mctp::MctpSocket::new()?;

    let dev = pldm_fw::query_device_identifiers(&sock, args.eid)?;
    let params = pldm_fw::query_firmware_parameters(&sock, args.eid)?;

    match args.command {
        Some(Command::Inventory) | None => print_device_info(&dev, &params),
    }

    Ok(())
}
