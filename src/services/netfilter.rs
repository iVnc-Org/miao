//! Minimal nf_tables ownership queries/cleanup. Does not require the nft executable.
use nix::libc;
use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

pub fn message(
    kind: u16,
    flags: u16,
    sequence: u32,
    family: u8,
    resource: u16,
    attributes: &[u8],
) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(&((20 + attributes.len()) as u32).to_ne_bytes());
    message.extend_from_slice(&kind.to_ne_bytes());
    message.extend_from_slice(&flags.to_ne_bytes());
    message.extend_from_slice(&sequence.to_ne_bytes());
    message.extend_from_slice(&0u32.to_ne_bytes());
    message.extend_from_slice(&[family, 0]);
    message.extend_from_slice(&resource.to_be_bytes());
    message.extend_from_slice(attributes);
    message
}

pub fn exchange(message: &[u8], sequence: u32) -> io::Result<Vec<u8>> {
    // SAFETY: initialized sockaddr/timeval/buffers with their exact lengths; fd is owned.
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_NETFILTER,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let timeout = libc::timeval {
        tv_sec: 2,
        tv_usec: 0,
    };
    if unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &timeout as *const _ as *const _,
            std::mem::size_of_val(&timeout) as _,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    address.nl_family = libc::AF_NETLINK as _;
    if unsafe {
        libc::sendto(
            fd.as_raw_fd(),
            message.as_ptr().cast(),
            message.len(),
            0,
            &address as *const _ as *const _,
            std::mem::size_of_val(&address) as _,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    loop {
        let mut response = [0u8; 8192];
        let received = unsafe {
            libc::recv(
                fd.as_raw_fd(),
                response.as_mut_ptr().cast(),
                response.len(),
                0,
            )
        };
        if received < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut remaining = &response[..received as usize];
        while remaining.len() >= 16 {
            let length = u32::from_ne_bytes(remaining[..4].try_into().unwrap()) as usize;
            if length < 16 || length > remaining.len() {
                return Err(io::Error::other("invalid netfilter response length"));
            }
            let kind = u16::from_ne_bytes(remaining[4..6].try_into().unwrap());
            let received_sequence = u32::from_ne_bytes(remaining[8..12].try_into().unwrap());
            if kind == 2 {
                if length < 20 {
                    return Err(io::Error::other("truncated netfilter error"));
                }
                let code = i32::from_ne_bytes(remaining[16..20].try_into().unwrap());
                if code < 0 {
                    return Err(io::Error::from_raw_os_error(-code));
                }
            }
            if received_sequence == sequence {
                return Ok(remaining[..length].to_vec());
            }
            let aligned = (length + 3) & !3;
            if aligned > remaining.len() {
                break;
            }
            remaining = &remaining[aligned..];
        }
        if received < 16 {
            return Err(io::Error::other("truncated netfilter response"));
        }
    }
}

fn table_name() -> Vec<u8> {
    let mut attribute = Vec::new();
    attribute.extend_from_slice(&13u16.to_ne_bytes());
    attribute.extend_from_slice(&1u16.to_ne_bytes()); // NFTA_TABLE_NAME
    attribute.extend_from_slice(b"sing-box\0");
    attribute.resize(16, 0);
    attribute
}

pub fn table_handle() -> io::Result<Option<u64>> {
    let reply = match exchange(&message((10 << 8) | 1, 5, 1, 1, 0, &table_name()), 1) {
        Ok(reply) => reply,
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut attributes = reply
        .get(20..)
        .ok_or_else(|| io::Error::other("missing nftables table data"))?;
    while attributes.len() >= 4 {
        let length = u16::from_ne_bytes(attributes[..2].try_into().unwrap()) as usize;
        let kind = u16::from_ne_bytes(attributes[2..4].try_into().unwrap()) & 0x3fff;
        if length < 4 || length > attributes.len() {
            return Err(io::Error::other("invalid nftables table attribute"));
        }
        if kind == 4 && length == 12 {
            return Ok(Some(u64::from_be_bytes(
                attributes[4..12].try_into().unwrap(),
            )));
        }
        let aligned = (length + 3) & !3;
        if aligned > attributes.len() {
            break;
        }
        attributes = &attributes[aligned..];
    }
    Err(io::Error::other(
        "nftables table has no stable ownership handle",
    ))
}

pub fn delete_owned_table(handle: u64) -> io::Result<()> {
    if table_handle()? != Some(handle) {
        return Ok(());
    }
    let mut attributes = Vec::new();
    // Match both the name and kernel-assigned handle, so a replacement is not deleted.
    attributes.extend_from_slice(&12u16.to_ne_bytes());
    attributes.extend_from_slice(&4u16.to_ne_bytes());
    attributes.extend_from_slice(&handle.to_be_bytes());
    let mut batch = message(16, 1, 1, 0, 10, &[]); // NFNL_MSG_BATCH_BEGIN
    batch.extend(message((10 << 8) | 2, 5, 2, 1, 0, &attributes));
    batch.extend(message(17, 1, 3, 0, 10, &[]));
    match exchange(&batch, 2) {
        Ok(_) => Ok(()),
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(()),
        Err(error) => Err(error),
    }
}
