//! Exact IPv4 ownership cleanup, including table IDs unsupported by BusyBox ip.
use nix::libc;
use std::{
    collections::BTreeSet,
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

fn exchange(kind: u16, payload: &[u8], dump: bool) -> io::Result<Vec<Vec<u8>>> {
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
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
    let mut request = Vec::new();
    request.extend_from_slice(&((16 + payload.len()) as u32).to_ne_bytes());
    request.extend_from_slice(&kind.to_ne_bytes());
    request.extend_from_slice(&(if dump { 0x301u16 } else { 5u16 }).to_ne_bytes());
    request.extend_from_slice(&1u32.to_ne_bytes());
    request.extend_from_slice(&0u32.to_ne_bytes());
    request.extend_from_slice(payload);
    let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    address.nl_family = libc::AF_NETLINK as _;
    if unsafe {
        libc::sendto(
            fd.as_raw_fd(),
            request.as_ptr().cast(),
            request.len(),
            0,
            &address as *const _ as *const _,
            std::mem::size_of_val(&address) as _,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut records = Vec::new();
    let mut total = 0;
    loop {
        let mut buffer = [0u8; 65536];
        let count = unsafe {
            libc::recv(
                fd.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                libc::MSG_TRUNC,
            )
        };
        if count < 0 {
            return Err(io::Error::last_os_error());
        }
        if count == 0 || count as usize > buffer.len() {
            return Err(io::Error::other("truncated routing response"));
        }
        total += count as usize;
        if total > 4 * 1024 * 1024 {
            return Err(io::Error::other("routing dump exceeded limit"));
        }
        let mut remaining = &buffer[..count as usize];
        while remaining.len() >= 16 {
            let length = u32::from_ne_bytes(remaining[..4].try_into().unwrap()) as usize;
            if length < 16 || length > remaining.len() {
                return Err(io::Error::other("invalid routing message"));
            }
            let kind = u16::from_ne_bytes(remaining[4..6].try_into().unwrap());
            let flags = u16::from_ne_bytes(remaining[6..8].try_into().unwrap());
            if u32::from_ne_bytes(remaining[8..12].try_into().unwrap()) == 1 {
                if flags & 0x10 != 0 {
                    return Err(io::Error::other("routing dump interrupted"));
                }
                if kind == 2 || kind == 3 {
                    if length >= 20 {
                        let code = i32::from_ne_bytes(remaining[16..20].try_into().unwrap());
                        if code < 0 {
                            return Err(io::Error::from_raw_os_error(-code));
                        }
                    } else if kind == 2 {
                        return Err(io::Error::other("truncated routing error"));
                    }
                    if kind == 3 || !dump {
                        return Ok(records);
                    }
                } else if matches!(kind, 24 | 32) {
                    if length < 28 {
                        return Err(io::Error::other("short routing payload"));
                    }
                    records.push(remaining[16..length].to_vec());
                }
            }
            let aligned = (length + 3) & !3;
            if aligned > remaining.len() {
                break;
            }
            remaining = &remaining[aligned..];
        }
    }
}

fn attribute(payload: &[u8], wanted: u16) -> Option<&[u8]> {
    let mut remaining = payload.get(12..)?;
    while remaining.len() >= 4 {
        let length = u16::from_ne_bytes(remaining[..2].try_into().ok()?) as usize;
        let kind = u16::from_ne_bytes(remaining[2..4].try_into().ok()?) & 0x3fff;
        if length < 4 || length > remaining.len() {
            return None;
        }
        if kind == wanted {
            return Some(&remaining[4..length]);
        }
        remaining = remaining.get((length + 3) & !3..)?;
    }
    None
}
fn number(payload: &[u8], kind: u16) -> Option<u32> {
    Some(u32::from_ne_bytes(
        attribute(payload, kind)?.try_into().ok()?,
    ))
}
pub fn priority(rule: &[u8]) -> u32 {
    number(rule, 6).unwrap_or(0)
}
pub fn table(payload: &[u8]) -> u32 {
    number(payload, 15).unwrap_or_else(|| payload.get(4).copied().unwrap_or(0) as u32)
}

pub fn rules() -> io::Result<BTreeSet<Vec<u8>>> {
    let mut header = [0u8; 12];
    header[0] = libc::AF_INET as u8;
    Ok(exchange(34, &header, true)?
        .into_iter()
        .map(|mut rule| {
            // Interface detachment and unresolved goto targets are transient, not ownership.
            let flags = u32::from_ne_bytes(rule[8..12].try_into().unwrap()) & !0x1c;
            rule[8..12].copy_from_slice(&flags.to_ne_bytes());
            rule
        })
        .collect())
}
fn delete(kind: u16, payload: &[u8]) -> io::Result<()> {
    match exchange(kind, payload, false) {
        Ok(_) => Ok(()),
        Err(error) if matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ESRCH)) => Ok(()),
        Err(error) => Err(error),
    }
}
pub fn delete_rule(rule: &[u8]) -> io::Result<()> {
    delete(33, rule)
}

fn owned_redirect_route(route: &[u8], tables: &BTreeSet<u32>) -> bool {
    route.len() >= 12
        && route[0] == libc::AF_INET as u8
        && route[1] == 32
        && route[6] == 254
        && route[7] == 2
        && attribute(route, 1) == Some(&[127, 0, 0, 1][..])
        && number(route, 4).is_some()
        && tables.contains(&table(route))
}
pub fn cleanup_redirect_routes(tables: &BTreeSet<u32>) -> io::Result<()> {
    if tables.is_empty() {
        return Ok(());
    }
    let mut header = [0u8; 12];
    header[0] = libc::AF_INET as u8;
    for route in exchange(26, &header, true)? {
        if owned_redirect_route(&route, tables) {
            delete(25, &route)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn attr(kind: u16, data: &[u8]) -> Vec<u8> {
        let mut value = Vec::new();
        value.extend_from_slice(&((4 + data.len()) as u16).to_ne_bytes());
        value.extend_from_slice(&kind.to_ne_bytes());
        value.extend_from_slice(data);
        value.resize((value.len() + 3) & !3, 0);
        value
    }
    #[test]
    fn large_table_cleanup_requires_exact_owned_local_host_route() {
        let id = 420548906u32;
        let tables = BTreeSet::from([id]);
        let mut route = vec![2, 32, 0, 0, 0, 3, 254, 2, 0, 0, 0, 0];
        route.extend(attr(1, &[127, 0, 0, 1]));
        route.extend(attr(4, &2u32.to_ne_bytes()));
        route.extend(attr(15, &id.to_ne_bytes()));
        assert_eq!(table(&route), id);
        assert!(owned_redirect_route(&route, &tables));
        assert!(!owned_redirect_route(&route, &BTreeSet::from([id + 1])));
        route[1] = 8;
        assert!(!owned_redirect_route(&route, &tables));
        route[1] = 32;
        route[7] = 1;
        assert!(!owned_redirect_route(&route, &tables));
        route[7] = 2;
        route[16] = 126;
        assert!(!owned_redirect_route(&route, &tables));
    }
}
