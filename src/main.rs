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

use anyhow::Context;
use argh::FromArgs;
use enumset::{EnumSet, EnumSetType};
use std::io::Write;
use std::fmt::Write as _;

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

fn print_device(dev: &pldm_fw::DeviceIdentifiers) {
    println!("Device: {}", dev);
}

fn print_update(update: &pldm_fw::Update) {
    println!("Update:");
    println!("  Package version: {}", update.package.version);
    println!("  Components to update:");
    for (idx, cmp_idx) in update.components.iter().enumerate() {
        let cmp = &update.package.components[*cmp_idx];
        println!("   {:2}: id {:04x}, version {}", idx, cmp.identifier, cmp.version);
    }
}

fn confirm_update() -> bool {
    let mut line = String::new();

    print!("\nConfirm update (y,N)? ");
    let _ = std::io::stdout().flush();
    let rc = std::io::stdin().read_line(&mut line);

    if ! rc.is_ok() {
        return false;
    }

    line.trim().to_ascii_lowercase() == "y"
}

fn open_package(fname: String) -> anyhow::Result<pldm_fw_pkg::Package> {
    let f = std::fs::File::open(&fname)
        .with_context(|| format!("Can't open PLDM package {}", fname))?;

    let pkg = pldm_fw_pkg::Package::parse(f)
        .with_context(|| format!("Can't parse PLDM package {}", fname))?;

    Ok(pkg)
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

#[derive(FromArgs, Debug)]
#[argh(description = "PLDM update utility")]
struct Args {
    #[argh(subcommand)]
    command: Command,
}

#[derive(FromArgs, Debug)]
#[argh(subcommand)]
enum Command {
    Inventory(InventoryCommand),
    Update(UpdateCommand),
    Cancel(CancelCommand),
    PkgInfo(PkgInfoCommand),
}

#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "inventory", description = "Query FD inventory")]
struct InventoryCommand {
    /// MCTP EID of device
    #[argh(positional, from_str_fn(eid_parse))]
    eid: u8,
}

#[derive(FromArgs, Debug)]
#[argh(
    subcommand,
    name = "update",
    description = "Update FD from a package file"
)]
struct UpdateCommand {
    /// MCTP EID of device
    #[argh(positional, from_str_fn(eid_parse))]
    eid: u8,

    #[argh(positional)]
    file: String,

    /// force a specific device from this package (by index)
    #[argh(option)]
    force_device: Option<usize>,

    /// explicitly specify components (by index)
    #[argh(option)]
    force_components: Vec<usize>,
}

#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "cancel", description = "Cancel ongoing update")]
struct CancelCommand {
    /// MCTP EID of device
    #[argh(positional, from_str_fn(eid_parse))]
    eid: u8,
}

#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "pkg-info", description = "Query package contents")]
struct PkgInfoCommand {
    #[argh(positional)]
    file: String,
}

fn main() -> anyhow::Result<()> {
    let args: Args = argh::from_env();

    match args.command {
        Command::Inventory(i) => {
            let ep = mctp::MctpEndpoint::new(i.eid)?;
            let dev = pldm_fw::query_device_identifiers(&ep)?;
            let params = pldm_fw::query_firmware_parameters(&ep)?;

            print_device_info(&dev, &params)
        }
        Command::Update(u) => {
            let pkg = open_package(u.file)?;
            let ep = mctp::MctpEndpoint::new(u.eid)?;
            let dev = pldm_fw::query_device_identifiers(&ep)?;
            let fwp = pldm_fw::query_firmware_parameters(&ep)?;
            let mut update = pldm_fw::Update::new(
                &dev,
                &fwp,
                pkg,
                u.force_device,
                u.force_components,
            )?;

            println!("Proposed update:");
            print_device(&dev);
            print_update(&update);

            let c = confirm_update();
            if !c {
                return Ok(())
            }

            let _ = pldm_fw::request_update(&ep, &update)?;
            pldm_fw::pass_component_table(&ep, &update)?;
            pldm_fw::update_components(&ep, &mut update)?;
        }
        Command::Cancel(c) => {
            let ep = mctp::MctpEndpoint::new(c.eid)?;
            let _ = pldm_fw::cancel_update(&ep);
        }
        Command::PkgInfo(p) => {
            let pkg = open_package(p.file)?;
            print_package(&pkg);
        }
    }

    Ok(())
}
