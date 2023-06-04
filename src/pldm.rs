// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * PLDM firmware update utility: PLDM message definitions.
 *
 * Copyright (c) 2023 Code Construct
 */

use std::io::Result;

use crate::mctp::MctpEndpoint;

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

pub fn pldm_xfer(ep: &MctpEndpoint, req: PldmRequest) -> Result<PldmResponse> {
    let mut tx_buf = Vec::with_capacity(req.data.len() + 2);
    tx_buf.push(1 << 7);
    tx_buf.push(req.typ & 0x3f);
    tx_buf.push(req.cmd);
    tx_buf.extend_from_slice(&req.data);

    ep.send(MCTP_TYPE_PLDM, &tx_buf)?;

    let mut rx_buf = [0u8; 1024]; // todo: set size? peek?
    let sz = ep.recv(&mut rx_buf)?;

    if sz < 4 {
        todo!();
    }

    let rsp = PldmResponse {
        cc: rx_buf[3],
        data: rx_buf[4..sz].to_vec(),
    };

    Ok(rsp)
}
