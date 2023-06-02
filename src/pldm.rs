// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * PLDM firmware update utility: PLDM message definitions.
 *
 * Copyright (c) 2023 Code Construct
 */

use std::io::Result;

use crate::mctp::{self, MctpSockAddr, MctpSocket};

pub const MCTP_TYPE_PLDM: u8 = 0x01;

pub struct PldmRequest {
    pub typ: u8,
    pub cmd: u8,
    pub data: Vec<u8>,
}

impl PldmRequest {
    pub fn new(typ: u8, cmd: u8) -> Self {
        Self {
            typ,
            cmd,
            data: Vec::new(),
        }
    }

    #[allow(dead_code)]
    pub fn set_data(&mut self, data: Vec<u8>) {
        self.data = data;
    }
}

pub struct PldmResponse {
    pub cc: u8,
    pub data: Vec<u8>,
}

pub fn pldm_xfer(
    sk: &MctpSocket,
    eid: u8,
    req: PldmRequest,
) -> Result<PldmResponse> {
    let tx_addr = MctpSockAddr::new(eid, MCTP_TYPE_PLDM, mctp::MCTP_TAG_OWNER);

    let mut tx_buf = Vec::with_capacity(req.data.len() + 2);
    tx_buf.push(1 << 7);
    tx_buf.push(req.typ & 0x3f);
    tx_buf.push(req.cmd);
    tx_buf.extend_from_slice(&req.data);

    sk.sendto(&tx_buf, &tx_addr)?;

    let mut rx_buf = [0u8; 1024]; // todo: set size? peek?
    let (sz, _rx_addr) = sk.recvfrom(&mut rx_buf)?;

    if sz < 4 {
        todo!();
    }

    let rsp = PldmResponse {
        cc: rx_buf[3],
        data: rx_buf[4..sz].to_vec(),
    };

    Ok(rsp)
}
