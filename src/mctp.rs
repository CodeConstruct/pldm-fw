// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * PLDM firmware update utility: MCTP sockets interface
 *
 * Copyright (c) 2023 Code Construct
 */

use core::mem;
use std::fmt;
use std::io::{Error, Result};
use std::os::unix::io::RawFd;

/* until we have these in libc... */
const AF_MCTP: libc::sa_family_t = 45;
#[repr(C)]
#[allow(non_camel_case_types)]
struct sockaddr_mctp {
    smctp_family: libc::sa_family_t,
    __smctp_pad0: u16,
    smctp_network: u32,
    smctp_addr: u8,
    smctp_type: u8,
    smctp_tag: u8,
    __smctp_pad1: u8,
}

pub const MCTP_TAG_OWNER: u8 = 0x08;
pub const MCTP_NET_ANY: u32 = 0x00;

pub struct MctpSocket(RawFd);
pub struct MctpSockAddr(sockaddr_mctp);

impl MctpSockAddr {
    pub fn new(eid: u8, typ: u8, tag: u8) -> Self {
        MctpSockAddr(sockaddr_mctp {
            smctp_family: AF_MCTP,
            __smctp_pad0: 0,
            smctp_network: MCTP_NET_ANY,
            smctp_addr: eid,
            smctp_type: typ,
            smctp_tag: tag,
            __smctp_pad1: 0,
        })
    }

    fn zero() -> Self {
        Self::new(0, 0, 0)
    }

    fn as_raw(&self) -> (*const libc::sockaddr, libc::socklen_t) {
        (
            &self.0 as *const sockaddr_mctp as *const libc::sockaddr,
            mem::size_of::<sockaddr_mctp>() as libc::socklen_t,
        )
    }

    fn as_raw_mut(&mut self) -> (*mut libc::sockaddr, libc::socklen_t) {
        (
            &mut self.0 as *mut sockaddr_mctp as *mut libc::sockaddr,
            mem::size_of::<sockaddr_mctp>() as libc::socklen_t,
        )
    }
}

impl fmt::Debug for MctpSockAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "McptSockAddr(family={}, net={}, addr={}, type={}, tag={})",
            self.0.smctp_family,
            self.0.smctp_network,
            self.0.smctp_addr,
            self.0.smctp_type,
            self.0.smctp_tag
        )
    }
}

impl Drop for MctpSocket {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

impl MctpSocket {
    pub fn new() -> Result<Self> {
        let rc = unsafe {
            libc::socket(
                AF_MCTP.into(),
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                0,
            )
        };
        if rc < 0 {
            return Err(Error::last_os_error());
        }
        Ok(MctpSocket(rc))
    }

    pub fn recvfrom(&self, buf: &mut [u8]) -> Result<(usize, MctpSockAddr)> {
        let mut addr = MctpSockAddr::zero();
        let (addr_ptr, mut addr_len) = addr.as_raw_mut();
        let buf_ptr = buf.as_mut_ptr() as *mut libc::c_void;
        let buf_len = buf.len() as libc::size_t;

        let rc = unsafe {
            libc::recvfrom(self.0, buf_ptr, buf_len, 0, addr_ptr, &mut addr_len)
        };

        if rc < 0 {
            Err(Error::last_os_error())
        } else {
            Ok((rc as usize, addr))
        }
    }

    pub fn sendto(&self, buf: &[u8], addr: &MctpSockAddr) -> Result<usize> {
        let (addr_ptr, addr_len) = addr.as_raw();
        let buf_ptr = buf.as_ptr() as *const libc::c_void;
        let buf_len = buf.len() as libc::size_t;

        let rc = unsafe {
            libc::sendto(self.0, buf_ptr, buf_len, 0, addr_ptr, addr_len)
        };

        if rc < 0 {
            Err(Error::last_os_error())
        } else {
            Ok(rc as usize)
        }
    }
}
