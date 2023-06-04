// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * PLDM firmware update utility: PLDM type 5 messaging
 *
 * Copyright (c) 2023 Code Construct
 */

use crate::mctp::MctpEndpoint;
use crate::pldm;
use core::fmt;
use std::io::{self, Result};

use enumset::{EnumSet, EnumSetType};
use itertools::Itertools;

use nom::{
    branch::alt,
    bytes::complete::{tag, take},
    character::complete::{i32 as c_i32, u32 as c_u32},
    combinator::{complete, map, map_parser, value},
    multi::{count, length_count, length_data, length_value},
    number::complete::{le_u16, le_u32, le_u8},
    sequence::tuple,
    IResult,
};

const PLDM_TYPE_FW: u8 = 5;

//type VResult<I,O> = IResult<I, O, VerboseError<I>>;
type VResult<I, O> = IResult<I, O>;

#[derive(Debug)]
pub enum DescriptorString {
    String(String),
    Bytes(Vec<u8>),
}

impl fmt::Display for DescriptorString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let trim_chars = ['\0', ' '];
        match self {
            Self::String(s) => {
                write!(
                    f,
                    "{}",
                    s.trim_end_matches(&trim_chars).escape_default()
                )
            }
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
pub enum Descriptor {
    PciVid(u16),
    Vendor(DescriptorString),
}

fn parse_string(typ: u8, buf: &[u8]) -> VResult<&[u8], DescriptorString> {
    let v = buf.to_vec();
    let s = match typ {
        0 => DescriptorString::Bytes(v),
        1 | 2 => DescriptorString::String(String::from_utf8(v).unwrap()),
        3 => {
            let b16 = v
                .iter()
                .tuples()
                .map(|(a, b)| ((*a as u16) << 8 | (*b as u16)))
                .collect::<Vec<u16>>();

            DescriptorString::String(String::from_utf16(&b16).unwrap())
        }
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
    pub ids: Vec<Descriptor>,
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
    ep: &MctpEndpoint,
) -> Result<DeviceIdentifiers> {
    let req = pldm::PldmRequest::new(PLDM_TYPE_FW, 0x01);

    let rsp = pldm::pldm_xfer(ep, req)?;

    if rsp.cc != 0 {
        return Err(io::Error::new(io::ErrorKind::Other, "PLDM error"));
    }

    let f = length_value(map(le_u32, |l| l + 1), DeviceIdentifiers::parse);

    let res = complete(f)(rsp.data.as_slice());

    res.map(|(_, d)| d)
        .map_err(|_e| io::Error::new(io::ErrorKind::Other, "parse error"))
}

pub type PldmDate = chrono::naive::NaiveDate;

#[derive(Debug)]
#[allow(dead_code)]
pub struct ComponentVersion {
    pub stamp: u32,
    pub version: DescriptorString,
    pub date: Option<PldmDate>,
}

impl fmt::Display for ComponentVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.version)?;
        if let Some(d) = self.date {
            write!(f, " ({:?})", d)?;
        }
        if self.stamp != 0 {
            write!(f, " [{:08x}]", self.stamp)?;
        }
        Ok(())
    }
}

pub fn pldm_date_parse(buf: &[u8]) -> VResult<&[u8], Option<PldmDate>> {
    /* YYYYMMDD */
    let (r, o) = alt((
        value(None, tag([0u8; 8])),
        map(
            tuple((
                map_parser(take(4u8), c_i32),
                map_parser(take(2u8), c_u32),
                map_parser(take(2u8), c_u32),
            )),
            Some,
        ),
    ))(buf)?;

    let d = o.and_then(|(y, m, d)| PldmDate::from_ymd_opt(y, m, d));

    Ok((r, d))
}

#[derive(Debug)]
pub enum ComponentClassification {
    Unknown,
    Other,
    Firmware,
}

impl From<u16> for ComponentClassification {
    fn from(x: u16) -> Self {
        match x {
            0x0000 => Self::Unknown,
            0x0001 => Self::Other,
            0x000a => Self::Firmware,
            _ => unimplemented!(),
        }
    }
}

#[derive(EnumSetType, Debug)]
pub enum ActivationMethod {
    PendingComponentImageSet = 7,
    PendingImage = 6,
    ACPowerCycle = 5,
    DCPowerCycle = 4,
    SystemReboot = 3,
    MediumSpecificReset = 2,
    SelfContained = 1,
    Automatic = 0,
}

type ActivationMethods = EnumSet<ActivationMethod>;

#[derive(EnumSetType, Debug)]
pub enum DeviceCapability {
    ComponentUpdateFailureRecovery = 0,
    ComponentUpdateFailureRetry = 1,
    FDHostFunctionalityDuringUpdate = 2,
    FDPartialUpdates = 3,
    FDUpdateModeRestrictionOSActive = 4,
    FDDowngradeRestrictions = 8,
    SecurityRevisionUpdateRequest = 9,
}

impl DeviceCapability {
    pub fn to_desc(&self, is_set: bool) -> String {
        match self {
            Self::ComponentUpdateFailureRecovery =>
                format!("Device will{} revert to previous component on failure",
                        if is_set { " not" } else { "" }),
            Self::ComponentUpdateFailureRetry =>
                format!("{} restarting update on failure",
                        if is_set { "Requires" } else { "Does not require" }),
            Self::FDHostFunctionalityDuringUpdate =>
                format!("Host functionality is{} reduced during update",
                        if is_set { "" } else { " not" }),
            Self::FDPartialUpdates =>
                format!("Device can{} accept a partial update",
                        if is_set { "" } else { "not" }),
            Self::FDUpdateModeRestrictionOSActive =>
                String::from(if is_set {
                    "No host OS restrictions during update"
                } else {
                    "Device unable to update while host OS active"
                }),
            Self::FDDowngradeRestrictions =>
                String::from(if is_set {
                    "No downgrade restrictions"
                } else {
                    "Downgrades may be restricted"
                }),
            Self::SecurityRevisionUpdateRequest =>
                format!("Device components {} have security revision numbers",
                        if is_set { "may" } else { "do not" }),
        }
    }
}

#[derive(Debug)]
pub struct DeviceCapabilities(EnumSet<DeviceCapability>);

impl DeviceCapabilities {
    pub fn from_u32(x: u32) -> Self {
        let x = x & EnumSet::<DeviceCapability>::all().as_u32();
        Self(EnumSet::<DeviceCapability>::from_u32(x))
    }

    pub fn as_u32(&self) -> u32 {
        self.0.as_u32()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn values(&self) -> Vec<(DeviceCapability, bool)> {
        EnumSet::<DeviceCapability>::all()
            .iter()
            .map(|cap| (cap, self.0.contains(cap)))
            .collect()
    }
}

#[derive(EnumSetType, Debug)]
pub enum ComponentCapability {
    FDApplyState = 0,
    ComponentDowngrade = 2,
    SecurityRevisionUpdateRequest = 3,
    SecurityRevisionNotLatest = 4,
}

pub type ComponentCapabilities = EnumSet<ComponentCapability>;

#[derive(Debug)]
#[allow(dead_code)]
pub struct Component {
    pub classification: ComponentClassification,
    pub identifier: u16,
    pub classificationindex: u8,
    pub active: ComponentVersion,
    pub pending: ComponentVersion,
    pub activation_methods: ActivationMethods,
    pub caps_during_update: ComponentCapabilities,
}

impl Component {
    pub fn parse(buf: &[u8]) -> VResult<&[u8], Self> {
        let (
            r,
            (
                classification,
                identifier,
                classificationindex,
                c1,
                c2,
                activation_methods,
                caps_during_update,
            ),
        ) = tuple((
            le_u16,
            le_u16,
            le_u8,
            tuple((le_u32, le_u8, le_u8, pldm_date_parse)),
            tuple((le_u32, le_u8, le_u8, pldm_date_parse)),
            le_u16,
            le_u32,
        ))(buf)?;

        let (r, (c1_buf, c2_buf)) = tuple((take(c1.2), take(c2.2)))(r)?;

        let (_, c1_str) = parse_string(c1.1, c1_buf)?;
        let (_, c2_str) = parse_string(c2.1, c2_buf)?;

        let c = Component {
            classification: classification.into(),
            identifier,
            classificationindex,
            active: ComponentVersion {
                stamp: c1.0,
                version: c1_str,
                date: c1.3,
            },
            pending: ComponentVersion {
                stamp: c2.0,
                version: c2_str,
                date: c2.3,
            },
            activation_methods: ActivationMethods::from_u16(activation_methods),
            caps_during_update: ComponentCapabilities::from_u32(
                caps_during_update,
            ),
        };

        Ok((r, c))
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct FirmwareParameters {
    pub caps: DeviceCapabilities,
    pub components: Vec<Component>,
    pub active: DescriptorString,
    pub pending: DescriptorString,
}

impl FirmwareParameters {
    pub fn parse(buf: &[u8]) -> VResult<&[u8], Self> {
        let (r, p) = tuple((le_u32, le_u16, le_u8, le_u8, le_u8, le_u8))(buf)?;

        let (
            caps,
            ccount,
            active_str_type,
            active_str_len,
            pending_str_type,
            pending_str_len,
        ) = p;

        let (r, active_buf) = take(active_str_len)(r)?;
        let (_, active) = parse_string(active_str_type, active_buf)?;
        let (r, pending_buf) = take(pending_str_len)(r)?;
        let (_, pending) = parse_string(pending_str_type, pending_buf)?;

        let (r, components) = count(Component::parse, ccount as usize)(r)?;

        let fp = FirmwareParameters {
            caps: DeviceCapabilities::from_u32(caps),
            components,
            active,
            pending,
        };

        Ok((r, fp))
    }
}

pub fn query_firmware_parameters(
    ep: &MctpEndpoint,
) -> Result<FirmwareParameters> {
    let req = pldm::PldmRequest::new(PLDM_TYPE_FW, 0x02);

    let rsp = pldm::pldm_xfer(ep, req)?;

    if rsp.cc != 0 {
        return Err(io::Error::new(io::ErrorKind::Other, "PLDM error"));
    }

    let f = FirmwareParameters::parse;

    let res = complete(f)(rsp.data.as_slice());

    res.map(|(_, d)| d)
        .map_err(|_e| io::Error::new(io::ErrorKind::Other, "parse error"))
}

const XFER_SIZE: usize = 16 * 1024;

#[derive(Debug)]
pub struct RequestUpdateResponse {
    pub fd_metadata_len: u16,
    pub fd_will_sent_gpd: u8,
    pub gpd_max_xfer_size: u16,
}

impl RequestUpdateResponse {
    pub fn parse(buf: &[u8]) -> VResult<&[u8], Self> {
        let (r, t) = tuple((le_u16, le_u8, le_u16))(buf)?;
        Ok((
            r,
            RequestUpdateResponse {
                fd_metadata_len: t.0,
                fd_will_sent_gpd: t.1,
                gpd_max_xfer_size: t.2,
            },
        ))
    }
}

pub fn request_update(ep: &MctpEndpoint) -> Result<RequestUpdateResponse> {
    let mut req = pldm::PldmRequest::new(PLDM_TYPE_FW, 0x10);

    req.data.extend_from_slice(&XFER_SIZE.to_le_bytes());
    req.data.extend_from_slice(&1u16.to_le_bytes()); // NumberOfComponents
    req.data.extend_from_slice(&1u8.to_le_bytes()); // MaximumOutstandingTransferRequests
    req.data.extend_from_slice(&0u16.to_le_bytes()); // PackageDataLength
    req.data.extend_from_slice(&1u8.to_le_bytes());
    req.data.extend_from_slice(&4u8.to_le_bytes());
    req.data.extend_from_slice("meep".as_bytes()); // component image version string

    let rsp = pldm::pldm_xfer(ep, req)?;

    if rsp.cc != 0 {
        return Err(io::Error::new(io::ErrorKind::Other, "PLDM error"));
    }

    println!("request rsp: {:?}", rsp.data);

    let res = complete(RequestUpdateResponse::parse)(rsp.data.as_slice());

    res.map(|(_, d)| d)
        .map_err(|_e| io::Error::new(io::ErrorKind::Other, "parse error"))
}

pub fn cancel_update(ep: &MctpEndpoint) -> Result<()> {
    let req = pldm::PldmRequest::new(PLDM_TYPE_FW, 0x1d);
    let rsp = pldm::pldm_xfer(ep, req)?;
    println!("cancel rsp: cc {:x}, data {:?}", rsp.cc, rsp.data);
    Ok(())
}
