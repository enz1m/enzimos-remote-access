// SPDX-License-Identifier: MIT
//! Read-only TCP observations. No test connection is opened to a service.
use enzimos_platform::{Error, Result, require};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Socket {
    pub address: IpAddr,
    pub port: u16,
    pub remote_address: IpAddr,
    pub remote_port: u16,
    pub state: String,
}
pub fn endpoint(value: &str) -> Result<(IpAddr, u16)> {
    let (address, port) = value
        .split_once(':')
        .ok_or_else(|| Error("tcp-observation-invalid".into()))?;
    require(
        matches!(address.len(), 8 | 32)
            && port.len() == 4
            && address
                .bytes()
                .chain(port.bytes())
                .all(|b| b.is_ascii_hexdigit()),
        "tcp-observation-invalid",
    )?;
    let mut bytes = address
        .as_bytes()
        .chunks_exact(2)
        .map(|b| {
            u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16)
                .map_err(|_| Error("tcp-observation-invalid".into()))
        })
        .collect::<Result<Vec<_>>>()?;
    for word in bytes.chunks_exact_mut(4) {
        word.reverse();
    }
    let ip = if bytes.len() == 4 {
        IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(bytes.as_slice()).unwrap(),
        ))
    } else {
        IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(bytes.as_slice()).unwrap(),
        ))
    };
    let port =
        u16::from_str_radix(port, 16).map_err(|_| Error("tcp-observation-invalid".into()))?;
    Ok((ip, port))
}
pub fn parse(body: &str) -> Result<BTreeMap<u64, Socket>> {
    require(
        body.len() <= 4 * 1024 * 1024 && !body.contains('\0'),
        "tcp-observation-bound",
    )?;
    let mut lines = body.lines();
    let header = lines
        .next()
        .ok_or_else(|| Error("tcp-observation-invalid".into()))?;
    let fields = header.split_whitespace().take(4).collect::<Vec<_>>();
    require(
        fields.len() == 4
            && fields[0] == "sl"
            && fields[1] == "local_address"
            && matches!(fields[2], "rem_address" | "remote_address")
            && fields[3] == "st",
        "tcp-observation-header",
    )?;
    let mut table = BTreeMap::new();
    for (i, line) in lines.enumerate() {
        require(i < 32768, "tcp-observation-count")?;
        let f = line.split_whitespace().collect::<Vec<_>>();
        require(
            (10..=32).contains(&f.len())
                && f[0].ends_with(':')
                && f[3].len() == 2
                && f[3].bytes().all(|b| b.is_ascii_hexdigit()),
            "tcp-observation-invalid",
        )?;
        let (address, port) = endpoint(f[1])?;
        let (remote_address, remote_port) = endpoint(f[2])?;
        let inode = f[9]
            .parse::<u64>()
            .map_err(|_| Error("tcp-observation-invalid".into()))?;
        // TIME_WAIT and other kernel-only entries can have inode zero; they do
        // not identify a descriptor owned by an admitted process.
        if inode == 0 {
            continue;
        }
        require(
            !table.contains_key(&inode),
            "tcp-observation-duplicate-inode",
        )?;
        table.insert(
            inode,
            Socket {
                address,
                port,
                remote_address,
                remote_port,
                state: f[3].to_ascii_uppercase(),
            },
        );
    }
    Ok(table)
}
#[allow(unsafe_code, reason = "Linux syscall ABI (geteuid, getpid).")]
pub fn table() -> Result<BTreeMap<u64, Socket>> {
    let uid = unsafe { libc::geteuid() };
    let pid = unsafe { libc::getpid() };
    let mut table = BTreeMap::new();
    // /proc/net is a self symlink. Use our numeric PID and stay in the descriptor
    // walker; kernel namespace observations never come from request paths.
    for name in ["tcp", "tcp6"] {
        let path = std::path::PathBuf::from(format!("/proc/{pid}/net/{name}"));
        let body = enzimos_platform::files::read_kernel_owned(&path, 4 * 1024 * 1024, uid)?;
        for (inode, socket) in parse(
            std::str::from_utf8(&body).map_err(|_| Error("tcp-observation-encoding".into()))?,
        )? {
            require(
                table.insert(inode, socket).is_none(),
                "tcp-observation-duplicate-inode",
            )?;
        }
    }
    Ok(table)
}
#[allow(unsafe_code, reason = "Linux syscall ABI (readlinkat).")]
pub fn inodes(pid: u32, uid: u32) -> Result<BTreeSet<u64>> {
    use std::os::fd::AsRawFd;
    require(pid > 0 && pid < i32::MAX as u32, "process-socket-pid")?;
    let path = std::path::PathBuf::from(format!("/proc/{pid}/fd"));
    let directory = enzimos_platform::files::directory(&path, Some(uid))?;
    let mut owned = BTreeSet::new();
    let mut count = 0;
    for entry in std::fs::read_dir(&path)? {
        count += 1;
        require(count <= 4096, "process-fd-bound")?;
        let name = entry?.file_name();
        let spelling = name
            .to_str()
            .ok_or_else(|| Error("process-fd-encoding".into()))?;
        require(
            !spelling.is_empty() && spelling.bytes().all(|b| b.is_ascii_digit()),
            "process-fd-name",
        )?;
        let name = std::ffi::CString::new(spelling).unwrap();
        let mut body = [0u8; 4096];
        let n = unsafe {
            libc::readlinkat(
                directory.as_raw_fd(),
                name.as_ptr(),
                body.as_mut_ptr().cast(),
                body.len(),
            )
        };
        if n < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                continue;
            }
            return Err(Error("process-fd-observation-unavailable".into()));
        }
        require((n as usize) < body.len(), "process-fd-target-bound")?;
        if let Some(inode) = socket_link(
            std::str::from_utf8(&body[..n as usize])
                .map_err(|_| Error("process-fd-encoding".into()))?,
        )? {
            owned.insert(inode);
        }
    }
    Ok(owned)
}
pub fn socket_link(value: &str) -> Result<Option<u64>> {
    if !value.starts_with("socket:[") {
        return Ok(None);
    }
    let id = value
        .strip_prefix("socket:[")
        .and_then(|s| s.strip_suffix(']'))
        .ok_or_else(|| Error("socket-descriptor-invalid".into()))?;
    require(
        !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()),
        "socket-descriptor-invalid",
    )?;
    let id = id
        .parse()
        .map_err(|_| Error("socket-descriptor-invalid".into()))?;
    require(id > 0, "socket-descriptor-invalid")?;
    Ok(Some(id))
}
pub fn listening(
    table: &BTreeMap<u64, Socket>,
    owned: &BTreeSet<u64>,
    address: IpAddr,
    port: u16,
) -> bool {
    owned.iter().any(|id| {
        table
            .get(id)
            .is_some_and(|s| s.state == "0A" && s.address == address && s.port == port)
    })
}
