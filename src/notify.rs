// SPDX-License-Identifier: MIT
//! Explicit Unix datagrams and SCM_RIGHTS; no environment-selected notify target.
use enzimos_platform::{Result, require};
use std::{
    fs::File,
    os::{
        fd::{AsRawFd, BorrowedFd, FromRawFd},
        unix::{ffi::OsStrExt, net::UnixDatagram},
    },
    path::Path,
    time::{Duration, Instant},
};
#[allow(
    unsafe_code,
    reason = "Linux syscall ABI (CMSG_DATA, CMSG_FIRSTHDR, CMSG_LEN, CMSG_SPACE and others)."
)]
pub(crate) fn send(path: &Path, message: &[u8], descriptor: Option<BorrowedFd<'_>>) -> Result<()> {
    require(
        !message.is_empty() && message.len() <= 4096 && !message.contains(&0),
        "desktop-listener-notification-invalid",
    )?;
    let bytes = path.as_os_str().as_bytes();
    // SAFETY: `libc::sockaddr_un` is a plain C struct, for which all-zero bytes are a valid value.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    require(
        path.is_absolute() && !bytes.contains(&0) && bytes.len() < address.sun_path.len(),
        "desktop-listener-notify-path",
    )?;
    address.sun_family = libc::AF_UNIX as _;
    for (target, byte) in address.sun_path.iter_mut().zip(bytes) {
        *target = *byte as _;
    }
    let socket = UnixDatagram::unbound()?;
    socket.set_nonblocking(true)?;
    let mut iov = libc::iovec {
        iov_base: message.as_ptr().cast_mut().cast(),
        iov_len: message.len(),
    };
    // SAFETY: `libc::msghdr` is a plain C struct, for which all-zero bytes are a valid value.
    let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
    header.msg_name = (&mut address as *mut libc::sockaddr_un).cast();
    header.msg_namelen = std::mem::size_of_val(&address) as _;
    header.msg_iov = &mut iov;
    header.msg_iovlen = 1;
    // usize storage guarantees cmsghdr alignment, unlike a byte-vector buffer.
    let mut control = [0usize; 8];
    if let Some(fd) = descriptor {
        header.msg_control = control.as_mut_ptr().cast();
        header.msg_controllen =
            // SAFETY: CMSG_SPACE only computes a size.
            unsafe { libc::CMSG_SPACE(std::mem::size_of::<i32>() as _) } as usize;
        require(
            header.msg_controllen <= std::mem::size_of_val(&control),
            "desktop-listener-descriptor-bound",
        )?;
        // SAFETY: `header` points at `control`, whose size was checked to hold one descriptor
        // header.
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&header);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<i32>() as _) as _;
            std::ptr::write(libc::CMSG_DATA(cmsg).cast::<i32>(), fd.as_raw_fd());
        }
    }
    require(
        // SAFETY: `header` and the buffers it points at outlive the call.
        unsafe { libc::sendmsg(socket.as_raw_fd(), &header, libc::MSG_NOSIGNAL) }
            == message.len() as isize,
        "desktop-listener-store-send-failed",
    )
}
#[allow(unsafe_code, reason = "Linux syscall ABI (pipe2, poll).")]
pub(crate) fn barrier(path: &Path) -> Result<()> {
    let mut pair = [-1; 2];
    require(
        // SAFETY: `pair` has room for the two descriptors pipe2 writes.
        unsafe { libc::pipe2(pair.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } == 0,
        "desktop-listener-store-receipt-uncertain",
    )?;
    // SAFETY: pipe2 succeeded, so `pair[0]` is a fresh descriptor owned by nothing else.
    let read = unsafe { File::from_raw_fd(pair[0]) };
    // SAFETY: pipe2 succeeded, so `pair[1]` is a fresh descriptor owned by nothing else.
    let write = unsafe { File::from_raw_fd(pair[1]) };
    use std::os::fd::AsFd;
    send(path, b"BARRIER=1", Some(write.as_fd()))?;
    drop(write);
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        require(
            !remaining.is_zero(),
            "desktop-listener-store-receipt-uncertain",
        )?;
        let mut poll = libc::pollfd {
            fd: read.as_raw_fd(),
            events: 0,
            revents: 0,
        };
        // SAFETY: `poll` is one writable pollfd and the count is 1.
        let rc = unsafe {
            libc::poll(
                &mut poll,
                1,
                remaining.as_millis().min(i32::MAX as u128).max(1) as _,
            )
        };
        if rc < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        require(
            rc > 0
                && poll.revents & (libc::POLLERR | libc::POLLNVAL) == 0
                && poll.revents & libc::POLLHUP != 0,
            "desktop-listener-store-receipt-uncertain",
        )?;
        return Ok(());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        os::fd::AsFd,
    };
    #[allow(
        unsafe_code,
        reason = "Linux syscall ABI (CMSG_DATA, CMSG_FIRSTHDR, CMSG_LEN, fcntl and others)."
    )]
    fn receive(socket: &UnixDatagram) -> (Vec<u8>, File) {
        let mut bytes = [0u8; 4096];
        let mut control = [0usize; 8];
        let mut iov = libc::iovec {
            iov_base: bytes.as_mut_ptr().cast(),
            iov_len: bytes.len(),
        };
        // SAFETY: `libc::msghdr` is a plain C struct, for which all-zero bytes are a valid value.
        let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
        header.msg_iov = &mut iov;
        header.msg_iovlen = 1;
        header.msg_control = control.as_mut_ptr().cast();
        header.msg_controllen = std::mem::size_of_val(&control);
        let count =
            // SAFETY: `header` points at buffers that outlive the call.
            unsafe { libc::recvmsg(socket.as_raw_fd(), &mut header, libc::MSG_CMSG_CLOEXEC) };
        assert!(count > 0 && header.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) == 0);
        // SAFETY: `header` was filled by recvmsg.
        let c = unsafe { libc::CMSG_FIRSTHDR(&header) };
        assert!(!c.is_null());
        // SAFETY: `c` is a non-null header recvmsg wrote inside `control`.
        unsafe {
            assert_eq!((*c).cmsg_level, libc::SOL_SOCKET);
            assert_eq!((*c).cmsg_type, libc::SCM_RIGHTS);
            assert_eq!(
                (*c).cmsg_len,
                libc::CMSG_LEN(std::mem::size_of::<i32>() as _) as usize
            );
            let fd = std::ptr::read(libc::CMSG_DATA(c).cast::<i32>());
            assert!(libc::fcntl(fd, libc::F_GETFD) & libc::FD_CLOEXEC != 0);
            (bytes[..count as usize].to_vec(), File::from_raw_fd(fd))
        }
    }
    #[test]
    fn explicit_descriptor_and_barrier_receipt_cross_private_unix_socket() {
        let root = tempfile::Builder::new()
            .prefix("notify-")
            .tempdir_in(std::path::PathBuf::from(
                std::env::var_os("ENZIMOS_TEST_TMPDIR")
                    .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into()),
            ))
            .unwrap();
        let path = root.path().join("socket");
        let receiver = UnixDatagram::bind(&path).unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let fixture = std::thread::spawn(move || {
            let (message, mut fd) = receive(&receiver);
            assert_eq!(message, b"FDSTORE=1\nFDNAME=desktop-listener\nFDPOLL=0");
            let mut contents = Vec::new();
            fd.read_to_end(&mut contents).unwrap();
            assert_eq!(contents, b"private-descriptor");
            let (message, fd) = receive(&receiver);
            assert_eq!(message, b"BARRIER=1");
            drop(fd);
        });
        let fd =
            enzimos_platform::memfile::sealed("notify-fixture", b"private-descriptor").unwrap();
        send(
            &path,
            b"FDSTORE=1\nFDNAME=desktop-listener\nFDPOLL=0",
            Some(fd.as_fd()),
        )
        .unwrap();
        barrier(&path).unwrap();
        fixture.join().unwrap();
        assert!(send(&path, b"bad\0message", None).is_err());
        // An unacknowledged barrier cannot be mistaken for successful delivery.
        let unacked = root.path().join("unacked");
        let receiver = UnixDatagram::bind(&unacked).unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let fixture = std::thread::spawn(move || {
            let (_, mut fd) = receive(&receiver);
            // Writing bytes is not the prescribed receipt, which requires HUP.
            fd.write_all(b"not-an-ack").unwrap();
            std::thread::sleep(Duration::from_millis(2300));
            drop(fd);
        });
        assert!(barrier(&unacked).is_err());
        fixture.join().unwrap();
    }
}
