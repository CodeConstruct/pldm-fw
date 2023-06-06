// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * PLDM firmware update utility: PLDM type 5 package parsing
 *
 * Copyright (c) 2023 Code Construct
 */

use nom::{
    bytes::complete::take,
    combinator::{all_consuming, map, map_res},
    multi::{count, length_count},
    number::complete::{le_u16, le_u32, le_u8},
    sequence::tuple,
    IResult,
};
use std::io::{self, BufReader, Read, Result};
use uuid::Uuid;

use crate::pldm_fw::{
    self, parse_string, parse_string_adjacent, Descriptor, DescriptorString,
};

type VResult<I, O> = IResult<I, O>;

#[derive(Debug)]
pub struct ComponentBitmap {
    n_bits: usize,
    bits: Vec<u8>,
}

impl<'a> ComponentBitmap {
    pub fn parse(
        component_bits: u16,
    ) -> impl FnMut(&'a [u8]) -> VResult<&'a [u8], Self> {
        let bytes = (component_bits + 7) / 8;
        map(take(bytes), move |b: &[u8]| ComponentBitmap {
            n_bits: component_bits as usize,
            bits: b.to_vec(),
        })
    }

    pub fn bit(&self, i: usize) -> bool {
        let idx = i / 8;
        let offt = i % 8;
        self.bits[idx] & (1 << offt) != 0
    }

    pub fn as_index_str(&self) -> String {
        let mut s = String::new();
        let mut first = true;
        for i in 0usize..self.n_bits {
            if self.bit(i) {
                s.push_str(&format!("{}{}", if first { "" } else { ", " }, i));
                first = false;
            }
        }
        s
    }

    pub fn as_index_vec(&self) -> Vec<usize> {
        let mut v = Vec::new();
        for i in 0usize..self.n_bits {
            if self.bit(i) {
                v.push(i)
            }
        }
        v
    }
}

#[derive(Debug)]
pub struct PackageDevice {
    pub ids: pldm_fw::DeviceIdentifiers,
    pub option_flags: u32,
    pub version: pldm_fw::DescriptorString,
    pub components: ComponentBitmap,
}

impl PackageDevice {
    pub fn parse(buf: &[u8], component_bits: u16) -> VResult<&[u8], Self> {
        let (
            r,
            (len, desc_count, flags, set_ver_type, set_ver_len, pkg_data_len),
        ) = tuple((le_u16, le_u8, le_u32, le_u8, le_u8, le_u16))(buf)?;

        // split the length bytes into r
        let (rest, r) = take(len - 11)(r)?;

        let (r, components) = ComponentBitmap::parse(component_bits)(r)?;
        let (r, set_ver) = parse_string(set_ver_type, set_ver_len)(r)?;
        let (r, ids) = count(Descriptor::parse, desc_count as usize)(r)?;
        let (_, _pkg_data) = all_consuming(take(pkg_data_len))(r)?;

        let pkgdev = PackageDevice {
            ids: pldm_fw::DeviceIdentifiers { ids },
            option_flags: flags,
            version: set_ver,
            components,
        };

        Ok((rest, pkgdev))
    }
}

#[derive(Debug)]
pub struct PackageComponent {
    pub classification: pldm_fw::ComponentClassification,
    pub identifier: u16,
    pub comparison_stamp: u32,
    pub options: u16,
    pub activation_method: u16,
    pub file_offset: usize,
    pub file_size: usize,
    pub version: DescriptorString,
}

impl PackageComponent {
    pub fn parse(buf: &[u8]) -> VResult<&[u8], Self> {
        let (
            r,
            (
                classification,
                identifier,
                comparison_stamp,
                options,
                activation_method,
                file_offset,
                file_size,
                version,
            ),
        ) = tuple((
            le_u16,
            le_u16,
            le_u32,
            le_u16,
            le_u16,
            le_u32,
            le_u32,
            parse_string_adjacent,
        ))(buf)?;

        let c = PackageComponent {
            classification: classification.into(),
            identifier,
            comparison_stamp,
            options,
            activation_method,
            file_offset: file_offset as usize,
            file_size: file_size as usize,
            version,
        };
        Ok((r, c))
    }
}

#[derive(Debug)]
pub struct Package {
    pub identifier: Uuid,
    pub version: DescriptorString,
    pub devices: Vec<PackageDevice>,
    pub components: Vec<PackageComponent>,
    pub reader: BufReader<std::fs::File>,
}

impl Package {
    pub fn parse(f: std::fs::File) -> Result<Self> {
        const HDR_INIT_SIZE: usize = 16 + 1 + 2;
        let mut reader = BufReader::new(f);
        let mut init = [0u8; HDR_INIT_SIZE];
        reader.read_exact(&mut init)?;

        let errfn =
            |_| io::Error::new(io::ErrorKind::Other, "package parse error");

        let (_, (
            identifier,
            _hdr_format,
            hdr_size,
        )) = all_consuming(tuple((
            map_res(take(16usize), Uuid::from_slice),
            le_u8,
            le_u16,
        )))(&init).map_err(errfn)?;

        let mut hdr_usize = hdr_size as usize;
        if hdr_usize < HDR_INIT_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "package parse error",
            ));
        }

        hdr_usize -= HDR_INIT_SIZE;

        let mut buf = Vec::<u8>::new();
        buf.resize(hdr_usize, 0);
        reader.read_exact(&mut buf)?;

        let (r, (
                _release_date_time,
                component_bitmap_length,
                version
        )) = tuple((
                take(13usize),
                le_u16,
                parse_string_adjacent,
        ))(&buf).map_err(errfn)?;

        let f = |d| PackageDevice::parse(d, component_bitmap_length);
        let (r, devices) = length_count(le_u8, f)(r).map_err(errfn)?;

        let f = |d| PackageComponent::parse(d);
        let (_, components) = length_count(le_u16, f)(r).map_err(errfn)?;

        Ok(Package {
            identifier,
            version,
            devices,
            components,
            reader,
        })
    }
}
