// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * PLDM firmware update utility.
 *
 * Copyright (c) 2023 Code Construct
 */

mod mctp;
mod pldm;
mod pldm_fw;
mod pldm_fw_pkg;

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
    for (cap, is_set) in fwp.caps.values() {
        println!("    * {}", cap.to_desc(is_set));
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

fn print_package(pkg: &pldm_fw_pkg::Package) {
    println!("Package:");
    println!("  Identifier:   {}", pkg.identifier);
    println!("  Version:      {}", pkg.version);
    println!("  Applicable devices:");
    for (idx, dev) in pkg.devices.iter().enumerate() {
        println!("   {:2}: {}", idx, dev.ids);
        println!("       version:    {}", dev.version);
        println!("       options:    0x{:x}", dev.option_flags);
        println!("       components: {}", dev.components.as_index_str());
    }
    println!("  Components:");
    for (idx, cmp) in pkg.components.iter().enumerate() {
        println!("   {:2}:", idx);
        println!("       classification: {:?}", cmp.classification);
        println!("       identifier:     0x{:04x}", cmp.identifier);
        println!("       version:        {}", cmp.version);
        println!("       comparison:     0x{:08x}", cmp.comparison_stamp);
        println!("       options:        0x{:04x}", cmp.options);
        println!("       activation:     0x{:04x}", cmp.activation_method);
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
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    Inventory {
        /// MCTP EID of device
        #[clap(value_parser=eid_parse)]
        eid: u8,
    },
    Update {
        /// MCTP EID of device
        #[clap(value_parser=eid_parse)]
        eid: u8,
        file: String,
    },
    Cancel {
        /// MCTP EID of device
        #[clap(value_parser=eid_parse)]
        eid: u8,
    },
    PkgInfo {
        file: String,
    },
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();

    match args.command {
        Some(Command::Inventory { eid }) => {
            let ep = mctp::MctpEndpoint::new(eid)?;
            let dev = pldm_fw::query_device_identifiers(&ep)?;
            let params = pldm_fw::query_firmware_parameters(&ep)?;

            print_device_info(&dev, &params)
        }
        Some(Command::Update { eid, file }) => {
            let f = std::fs::File::open(file)?;
            let pkg = pldm_fw_pkg::Package::parse(f)?;
            let ep = mctp::MctpEndpoint::new(eid)?;
            let dev = pldm_fw::query_device_identifiers(&ep)?;
            let fwp = pldm_fw::query_firmware_parameters(&ep)?;
            let mut update = pldm_fw::Update::new(&dev, &fwp, pkg)?;
            println!("update: {:#?}", update);

            let _ = pldm_fw::request_update(&ep, &update)?;
            pldm_fw::pass_component_table(&ep, &update)?;
            pldm_fw::update_components(&ep, &mut update)?;
            /*
            let _ = pldm_fw::cancel_update(&ep);
            */
        }
        Some(Command::Cancel { eid }) => {
            let ep = mctp::MctpEndpoint::new(eid)?;
            let _ = pldm_fw::cancel_update(&ep);
        }
        Some(Command::PkgInfo { file }) => {
            let f = std::fs::File::open(file)?;
            let pkg = pldm_fw_pkg::Package::parse(f)?;
            print_package(&pkg);
        }
        None => {
            todo!();
        }
    }

    Ok(())
}
