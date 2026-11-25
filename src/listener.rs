// SPDX-License-Identifier: MIT
use enzimos_platform::{Result, require};
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// Reserve a single-stack listener on `address`.
///
/// # Errors
///
/// Fails for scoped addresses or when the reservation is refused.
#[allow(
    unsafe_code,
    reason = "Linux syscall ABI (bind, listen, setsockopt, socket)."
)]
pub fn reserve(address: SocketAddr) -> Result<TcpListener> {
    let family = if address.is_ipv6() {
        libc::AF_INET6
    } else {
        libc::AF_INET
    };
    // SAFETY: socket takes no pointers.
    let raw = unsafe {
        libc::socket(
            family,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            libc::IPPROTO_TCP,
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: `raw` was just returned by socket and is owned by nothing else.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    if address.is_ipv6() {
        let one: libc::c_int = 1;
        require(
            // SAFETY: The option value points at `one` with its exact size, and `fd` is open.
            unsafe {
                libc::setsockopt(
                    fd.as_raw_fd(),
                    libc::IPPROTO_IPV6,
                    libc::IPV6_V6ONLY,
                    (&one as *const libc::c_int).cast(),
                    std::mem::size_of_val(&one) as u32,
                )
            } == 0,
            "desktop-reserved-listener-dual-stack",
        )?;
    }
    let rc = match address {
        SocketAddr::V4(a) => {
            let sockaddr = libc::sockaddr_in {
                sin_family: libc::AF_INET as u16,
                sin_port: a.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(a.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: `address` is a complete sockaddr_in passed with its size, and `fd` is open.
            unsafe {
                libc::bind(
                    fd.as_raw_fd(),
                    (&sockaddr as *const libc::sockaddr_in).cast(),
                    std::mem::size_of_val(&sockaddr) as u32,
                )
            }
        }
        SocketAddr::V6(a) => {
            require(
                a.scope_id() == 0 && a.flowinfo() == 0,
                "scoped desktop address refused",
            )?;
            let sockaddr = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as u16,
                sin6_port: a.port().to_be(),
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr {
                    s6_addr: a.ip().octets(),
                },
                sin6_scope_id: 0,
            };
            // SAFETY: `address` is a complete sockaddr_in6 passed with its size, and `fd` is open.
            unsafe {
                libc::bind(
                    fd.as_raw_fd(),
                    (&sockaddr as *const libc::sockaddr_in6).cast(),
                    std::mem::size_of_val(&sockaddr) as u32,
                )
            }
        }
    };
    require(
        // SAFETY: listen takes no pointers and `fd` keeps the descriptor open.
        rc == 0 && unsafe { libc::listen(fd.as_raw_fd(), 16) } == 0,
        "desktop-listener-reservation-refused",
    )?;
    Ok(TcpListener::from(fd))
}
#[allow(unsafe_code, reason = "Linux syscall ABI (getsockopt).")]
fn option(fd: i32, level: i32, name: i32) -> Result<i32> {
    let mut value = 0i32;
    let mut len = std::mem::size_of_val(&value) as libc::socklen_t;
    require(
        // SAFETY: The option buffer is `value` with its size in `len`.
        unsafe { libc::getsockopt(fd, level, name, (&mut value as *mut i32).cast(), &mut len) }
            == 0
            && len as usize == std::mem::size_of_val(&value),
        "desktop-reserved-listener-invalid",
    )?;
    Ok(value)
}

// Takes ownership only after the fixed systemd activation envelope matches.
/// The reserved listener passed by systemd, checked against `expected`.
///
/// # Errors
///
/// Fails when the descriptor is missing, invalid, or bound elsewhere.
#[allow(unsafe_code, reason = "Linux syscall ABI (fcntl, fstat).")]
pub fn receive(expected: SocketAddr) -> Result<TcpListener> {
    require(
        std::env::var("LISTEN_PID").ok().as_deref()
            == Some(std::process::id().to_string().as_str())
            && std::env::var("LISTEN_FDS").ok().as_deref() == Some("1")
            && std::env::var("LISTEN_FDNAMES").ok().as_deref() == Some("desktop-listener"),
        "desktop-reserved-listener-required",
    )?;
    // SAFETY: F_GETFD takes no pointers; it only checks that descriptor 3 is open.
    let flags = unsafe { libc::fcntl(3, libc::F_GETFD) };
    require(flags >= 0, "desktop-listener-descriptor-invalid")?;
    // SAFETY: Systemd passed descriptor 3 to this process alone, as checked above, and it is
    // adopted once.
    let fd = unsafe { OwnedFd::from_raw_fd(3) };
    require(
        // SAFETY: F_SETFD takes no pointers and `fd` owns the descriptor.
        unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC) } == 0,
        "desktop-listener-descriptor-invalid",
    )?;
    // SAFETY: `libc::stat` is a plain C struct, for which all-zero bytes are a valid value.
    let mut info: libc::stat = unsafe { std::mem::zeroed() };
    require(
        // SAFETY: `info` is a writable `libc::stat` and `fd` keeps the descriptor open.
        unsafe { libc::fstat(fd.as_raw_fd(), &mut info) } == 0
            && info.st_mode & libc::S_IFMT == libc::S_IFSOCK
            && info.st_uid == 0,
        "desktop-reserved-listener-invalid",
    )?;
    require(
        option(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_TYPE)? == libc::SOCK_STREAM
            && option(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PROTOCOL)? == libc::IPPROTO_TCP
            && option(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_ACCEPTCONN)? == 1
            && option(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_REUSEPORT)? == 0,
        "desktop-reserved-listener-invalid",
    )?;
    let family = option(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_DOMAIN)?;
    require(
        family
            == if expected.is_ipv6() {
                libc::AF_INET6
            } else {
                libc::AF_INET
            },
        "desktop-reserved-listener-mismatch",
    )?;
    if expected.is_ipv6() {
        require(
            option(fd.as_raw_fd(), libc::IPPROTO_IPV6, libc::IPV6_V6ONLY)? == 1,
            "desktop-reserved-listener-dual-stack",
        )?;
    }
    let connection = TcpListener::from(fd);
    let actual = connection.local_addr()?;
    require(
        actual == expected
            && !matches!(actual.ip(),IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some()),
        "desktop-reserved-listener-mismatch",
    )?;
    Ok(connection)
}
