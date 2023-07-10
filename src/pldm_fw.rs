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
    combinator::{
        all_consuming, complete, flat_map, map, map_parser, rest, value,
    },
    multi::{count, length_count, length_value},
    number::complete::{le_u16, le_u32, le_u8},
    sequence::tuple,
    IResult,
};

use crate::pldm_fw_pkg;

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

impl DescriptorString {
    pub fn write_utf8_bytes(&self, v: &mut Vec<u8>) {
        match self {
            Self::String(s) => {
                v.push(0x01);
                v.push(s.len() as u8);
                v.extend_from_slice(s.as_bytes());
            }
            Self::Bytes(b) => {
                v.push(0x00);
                v.push(b.len() as u8);
                v.extend_from_slice(b);
            }
        }
    }
}

#[derive(Debug)]
pub enum Descriptor {
    PciVid(u16),
    Vendor {
        title: Option<DescriptorString>,
        data: Vec<u8>,
    },
}

pub fn parse_string<'a>(
    typ: u8,
    len: u8,
) -> impl FnMut(&'a [u8]) -> VResult<&'a [u8], DescriptorString> {
    map(take(len), move |d: &[u8]| {
        let v = d.to_vec();
        match typ {
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
        }
    })
}

// Where we have type, length and data all adjacent (and in that order)
pub fn parse_string_adjacent(buf: &[u8]) -> VResult<&[u8], DescriptorString> {
    let (r, (typ, len)) = tuple((le_u8, le_u8))(buf)?;
    parse_string(typ, len)(r)
}

impl Descriptor {
    pub fn parse_pcivid(buf: &[u8]) -> VResult<&[u8], Self> {
        map(le_u16, Self::PciVid)(buf)
    }

    pub fn parse_vendor(buf: &[u8]) -> VResult<&[u8], Self> {
        // Attempt to parse with a proper title string; if not present just
        // consume everything as byte data
        let f1 = |(t, d): (_, &[u8])| Self::Vendor {
            title: Some(t),
            data: d.to_vec(),
        };
        let f2 = |d: &[u8]| Self::Vendor {
            title: None,
            data: d.to_vec(),
        };
        alt((map(tuple((parse_string_adjacent, rest)), f1), map(rest, f2)))(buf)
    }

    pub fn parse(buf: &[u8]) -> VResult<&[u8], Self> {
        let f = |(typ, len)| {
            let g = match typ {
                0x0000 => Self::parse_pcivid,
                0xffff => Self::parse_vendor,
                _ => unimplemented!(),
            };
            map_parser(take(len), all_consuming(g))
        };
        flat_map(tuple((le_u16, le_u16)), f)(buf)
    }
}

impl fmt::Display for Descriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PciVid(id) => write!(f, "pci-vid:{:04x}", id),
            Self::Vendor { title, data } => {
                match title {
                    Some(t) => write!(f, "vendor:{}", t)?,
                    None => write!(f, "vendor:")?,
                }
                write!(f, "[")?;
                for b in data {
                    write!(f, "{:02x}", b)?;
                }
                write!(f, "]")?;
                Ok(())
            }
        }
    }
}

impl PartialEq for Descriptor {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Vendor { data: s, .. }, Self::Vendor { data: o, .. }) => {
                s == o
            }
            (Self::PciVid(s), Self::PciVid(o)) => s == o,
            _ => false,
        }
    }
}

#[derive(Debug)]
pub struct DeviceIdentifiers {
    pub ids: Vec<Descriptor>,
}

impl PartialEq for DeviceIdentifiers {
    fn eq(&self, other: &Self) -> bool {
        self.ids == other.ids
    }
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

impl ComponentClassification {
    fn as_u16(&self) -> u16 {
        match self {
            Self::Unknown => 0x0000,
            Self::Other => 0x0001,
            Self::Firmware => 0x000a,
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

        let (r, c1_str) = parse_string(c1.1, c1.2)(r)?;
        let (r, c2_str) = parse_string(c2.1, c2.2)(r)?;

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

        let (r, active) = parse_string(active_str_type, active_str_len)(r)?;
        let (r, pending) = parse_string(pending_str_type, pending_str_len)(r)?;

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
}

impl RequestUpdateResponse {
    pub fn parse(buf: &[u8]) -> VResult<&[u8], Self> {
        let (r, t) = tuple((le_u16, le_u8))(buf)?;
        Ok((
            r,
            RequestUpdateResponse {
                fd_metadata_len: t.0,
                fd_will_sent_gpd: t.1,
            },
        ))
    }
}

pub fn request_update(
    ep: &MctpEndpoint,
    update: &Update,
) -> Result<RequestUpdateResponse> {
    let mut req = pldm::PldmRequest::new(PLDM_TYPE_FW, 0x10);

    req.data.extend_from_slice(&XFER_SIZE.to_le_bytes());
    req.data.extend_from_slice(&1u16.to_le_bytes()); // NumberOfComponents
    req.data.extend_from_slice(&1u8.to_le_bytes()); // MaximumOutstandingTransferRequests
    req.data.extend_from_slice(&0u16.to_le_bytes()); // PackageDataLength
    update.package.version.write_utf8_bytes(&mut req.data);

    let rsp = pldm::pldm_xfer(ep, req)?;

    if rsp.cc != 0 {
        return Err(io::Error::new(io::ErrorKind::Other, "PLDM error"));
    }

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

#[derive(Debug)]
pub struct Update {
    package: pldm_fw_pkg::Package,
    components: Vec<usize>,
}

impl Update {
    pub fn new(
        dev: &DeviceIdentifiers,
        _fwp: &FirmwareParameters,
        pkg: pldm_fw_pkg::Package,
        force_device: Option<usize>,
    ) -> Result<Self> {
        let dev = match force_device {
            Some(n) => &pkg.devices[n],
            None => {
                let fwdevs = pkg
                    .devices
                    .iter()
                    .filter(|d| &d.ids == dev)
                    .collect::<Vec<_>>();

                if fwdevs.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "no matching devices",
                    ));
                }

                if fwdevs.len() != 1 {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "multiple matching devices",
                    ));
                }

                *fwdevs.first().unwrap()
            }
        };

        let components = dev.components.as_index_vec();

        Ok(Self {
            package: pkg,
            components,
        })
    }
}

fn xfer_flags(idx: usize, len: usize) -> u8 {
    let mut xfer_flags: u8 = 0x0;
    if idx == 0 {
        xfer_flags |= 0x1;
    }
    if idx == len - 1 {
        xfer_flags |= 0x4;
    }
    if xfer_flags == 0 {
        xfer_flags = 0x2;
    }
    xfer_flags
}

pub fn pass_component_table(ep: &MctpEndpoint, update: &Update) -> Result<()> {
    let components = &update.components;
    let len = components.len();

    for (n, idx) in components.iter().enumerate() {
        let component = update.package.components.get(*idx).unwrap();
        let mut req = pldm::PldmRequest::new(PLDM_TYPE_FW, 0x13);

        req.data.push(xfer_flags(n, len));
        req.data.extend_from_slice(
            &component.classification.as_u16().to_le_bytes(),
        );
        req.data.extend_from_slice(&component.identifier.to_le_bytes());

        // todo: match index from fwp?
        req.data.extend_from_slice(&0x0000u16.to_le_bytes());

        req.data.extend_from_slice(&component.comparison_stamp.to_le_bytes());

        component.version.write_utf8_bytes(&mut req.data);

        let rsp = pldm::pldm_xfer(ep, req)?;

        if rsp.cc != 0 {
            println!("PassComponentTable command failed, cc 0x{:02x}", rsp.cc);
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "PLDM(PCT) error",
            ));
        }
    }

    Ok(())
}

pub fn update_component(
    ep: &MctpEndpoint,
    package: &pldm_fw_pkg::Package,
    component: &pldm_fw_pkg::PackageComponent,
) -> Result<()> {
    let mut req = pldm::PldmRequest::new(PLDM_TYPE_FW, 0x14);

    req.data.extend_from_slice(&component.classification
                              .as_u16().to_le_bytes());
    req.data.extend_from_slice(&component.identifier.to_le_bytes());

    // todo: classification index: match index from fwp?
    req.data.extend_from_slice(&0x00u8.to_le_bytes());

    req.data.extend_from_slice(&component.comparison_stamp.to_le_bytes());

    let sz: u32 = component.file_size as u32;
    req.data.extend_from_slice(&sz.to_le_bytes());

    // todo: flags: request forced update?
    req.data.extend_from_slice(&0u32.to_le_bytes());

    component.version.write_utf8_bytes(&mut req.data);

    println!("update component req: {:02x?}", req);

    let rsp = pldm::pldm_xfer(ep, req)?;

    if rsp.cc != 0 {
        println!("UpdateComponent command failed: cc 0x{:02x}", rsp.cc);
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "PLDM(UC) error",
        ));
    }

    loop {
        // we should be in update mode, handle incoming data requests
        let fw_req = pldm::pldm_rx_req(ep)?;

        match fw_req.cmd {
            0x15 => {
                /* Request Firmware Data */
                let res: IResult<_, _> = all_consuming(tuple((le_u32, le_u32)))(
                    fw_req.data.as_slice(),
                );

                let (_, (offset, len)) = res.map_err(|_e| {
                    io::Error::new(io::ErrorKind::Other, "parse error")
                })?;

                println!(
                    "Data request: offset 0x{:08x}, len 0x{:08x}",
                    offset, len
                );

                let mut buf = Vec::new();
                buf.resize(len as usize, 0u8);

                package.read_component(component, offset, &mut buf)?;

                let mut fw_resp = fw_req.response();

                fw_resp.cc = 0;
                fw_resp.data = buf;

                pldm::pldm_tx_resp(ep, &fw_resp)?;
            }
            0x16 => {
                /* Transfer Complete */
                let res = fw_req.data[0];
                if res == 0 {
                    println!("firmware transfer complete");
                } else {
                    println!("fimware transfer error: 0x{:02x}", res);
                }
                let mut fw_resp = fw_req.response();
                fw_resp.cc = 0;
                pldm::pldm_tx_resp(ep, &fw_resp)?;
                if res != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "PLDM(TC) error"),
                    );
                }
                break;
            }
            _ => {
                println!("unknown req during transfer");
                println!(" {:?}", fw_req);

                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "unexpected command during update",
                ));
            }
        }
    }

    /* Verify results.. */
    let fw_req = pldm::pldm_rx_req(ep)?;
    match fw_req.cmd {
        0x17 => {
            let res = fw_req.data[0];
            println!("fimware verify result: 0x{:02x}", res);
            if res != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "verify failure",
                ));
            }
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "unexpected command during verify",
            ));
        }
    }
    let mut fw_resp = fw_req.response();
    fw_resp.cc = 0;
    pldm::pldm_tx_resp(ep, &fw_resp)?;

    /* Apply */
    let fw_req = pldm::pldm_rx_req(ep)?;
    match fw_req.cmd {
        0x18 => {
            let res = fw_req.data[0];
            println!("fimware apply result: 0x{:02x}", res);
            if res != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "apply failure",
                ));
            }
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "unexpected command during apply",
            ));
        }
    }

    let mut fw_resp = fw_req.response();
    fw_resp.cc = 0;
    pldm::pldm_tx_resp(ep, &fw_resp)?;

    Ok(())
}

pub fn update_components(ep: &MctpEndpoint, update: &mut Update) -> Result<()> {
    // We'll need to receive incoming data requests, so bind() now.
    ep.bind(pldm::MCTP_TYPE_PLDM)?;

    let components = update.components.clone();

    for idx in components {
        let component = update.package.components.get(idx).unwrap();
        update_component(&ep, &update.package, component)?;
    }

    Ok(())
}
