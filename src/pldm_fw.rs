// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * PLDM firmware update utility: PLDM type 5 messaging
 *
 * Copyright (c) 2023 Code Construct
 */

use crate::mctp::MctpSocket;
use crate::pldm;
use core::fmt;
use std::io::{self, Result};

use nom::{
    combinator::{complete, map},
    multi::{length_count, length_data, length_value},
    number::complete::{le_u16, le_u32, le_u8},
    sequence::tuple,
    IResult,
};

const PLDM_TYPE_FW: u8 = 5;

//type VResult<I,O> = IResult<I, O, VerboseError<I>>;
type VResult<I, O> = IResult<I, O>;

#[derive(Debug)]
enum DescriptorString {
    String(String),
    Bytes(Vec<u8>),
}

impl fmt::Display for DescriptorString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::String(s) => write!(f, "{}", s),
            Self::Bytes(bs) => {
                for b in bs {
                    write!(f, "{:02x}", b)?;
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug)]
enum Descriptor {
    PciVid(u16),
    Vendor(DescriptorString),
}

fn parse_string(typ: u8, buf: &[u8]) -> VResult<&[u8], DescriptorString> {
    let v = buf.to_vec();
    let s = match typ {
        0 => DescriptorString::Bytes(v),
        1 | 2 => DescriptorString::String(String::from_utf8(v).unwrap()),
        _ => unimplemented!(),
    };
    Ok((&[], s))
}

impl Descriptor {
    pub fn parse_pcivid(buf: &[u8]) -> VResult<&[u8], Self> {
        let (rest, id) = le_u16(buf)?;
        Ok((rest, Self::PciVid(id)))
    }

    pub fn parse_vendor(buf: &[u8]) -> VResult<&[u8], Self> {
        // TODO: we're parsing the entire descriptor as bytes for now,
        // extract the title string in future.
        let (r, s) = parse_string(0, buf)?;
        Ok((r, Self::Vendor(s)))
    }

    pub fn parse(buf: &[u8]) -> VResult<&[u8], Self> {
        let (rem, (typ, data)) = tuple((le_u16, length_data(le_u16)))(buf)?;
        let f = match typ {
            0x0000 => Self::parse_pcivid,
            0xffff => Self::parse_vendor,
            _ => unimplemented!(),
        };
        let (_, r) = complete(f)(data)?;
        Ok((rem, r))
    }
}

impl fmt::Display for Descriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PciVid(id) => write!(f, "pci-vid:{:04x}", id),
            Self::Vendor(s) => write!(f, "vendor:{}", s),
        }
    }
}

#[derive(Debug)]
pub struct DeviceIdentifiers {
    ids: Vec<Descriptor>,
}

impl DeviceIdentifiers {
    pub fn parse(buf: &[u8]) -> VResult<&[u8], Self> {
        length_count(le_u8, Descriptor::parse)(buf)
            .map(|(rest, ids)| (rest, Self { ids }))
    }
}

impl fmt::Display for DeviceIdentifiers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for id in self.ids.iter() {
            write!(f, "{}{}", if first { "" } else { "," }, id)?;
            first = false;
        }
        Ok(())
    }
}

pub fn query_device_identifiers(
    sk: &MctpSocket,
    eid: u8,
) -> Result<DeviceIdentifiers> {
    let req = pldm::PldmRequest::new(PLDM_TYPE_FW, 0x01);

    let rsp = pldm::pldm_xfer(sk, eid, req)?;

    if rsp.cc != 0 {
        return Err(io::Error::new(io::ErrorKind::Other, "PLDM error"));
    }

    let f = length_value(map(le_u32, |l| l + 1), DeviceIdentifiers::parse);

    let res = complete(f)(rsp.data.as_slice());

    res.map(|(_, d)| d)
        .map_err(|_e| io::Error::new(io::ErrorKind::Other, "parse error"))
}
