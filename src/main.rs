// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * PLDM firmware update utility.
 *
 * Copyright (c) 2023 Code Construct
 */

mod mctp;
mod pldm;
mod pldm_fw;

const EID: u8 = 0x09;

fn main() -> std::io::Result<()> {
    let sock = mctp::MctpSocket::new()?;

    let dev = pldm_fw::query_device_identifiers(&sock, EID)?;

    println!("device: {}", dev);

    Ok(())
}
