// SPDX-License-Identifier: MIT
use enzimos_remote_access::sockets;
use std::{collections::BTreeSet, net::IpAddr};
#[test]
fn exact_proc_endpoints_socket_inode_and_listener_ownership() {
    assert_eq!(
        sockets::endpoint("0100007F:08AE").unwrap(),
        ("127.0.0.1".parse::<IpAddr>().unwrap(), 2222)
    );
    assert_eq!(
        sockets::endpoint("00000000000000000000000001000000:08AE").unwrap(),
        ("::1".parse::<IpAddr>().unwrap(), 2222)
    );
    for bad in [
        "0100007F:22222",
        "0100007:08AE",
        "G100007F:08AE",
        "0100007F:08AE:00",
    ] {
        assert!(sockets::endpoint(bad).is_err());
    }
    let body = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n 0: 0100007F:08AE 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 456 1\n 1: 0100007F:08AE 0100007F:1234 01 00000000:00000000 00:00000000 00000000 0 0 457 1\n";
    let table = sockets::parse(body).unwrap();
    let address = "127.0.0.1".parse().unwrap();
    assert!(sockets::listening(
        &table,
        &BTreeSet::from([456]),
        address,
        2222
    ));
    assert!(!sockets::listening(
        &table,
        &BTreeSet::from([457]),
        address,
        2222
    ));
    assert!(!sockets::listening(
        &table,
        &BTreeSet::from([999]),
        address,
        2222
    ));
    assert!(sockets::parse(&body.replace("457", "456")).is_err());
    assert_eq!(sockets::socket_link("socket:[456]").unwrap(), Some(456));
    assert_eq!(sockets::socket_link("/etc/passwd").unwrap(), None);
    for invalid in ["socket:[0]", "socket:[1]junk", "socket:[-1]", "socket:[1"] {
        assert!(sockets::socket_link(invalid).is_err());
    }
    let ipv6_header = body.replace("rem_address", "remote_address");
    assert_eq!(sockets::parse(&ipv6_header).unwrap(), table);
    assert!(sockets::parse(&body.replace("rem_address", "unknown_address")).is_err());
}
#[test]
#[allow(unsafe_code, reason = "Linux syscall ABI (geteuid, getpid).")]
fn native_kernel_observation_accepts_both_headers_without_opening_a_listener() {
    sockets::table().unwrap();
    // SAFETY: getpid has no preconditions and cannot fail.
    let pid = unsafe { libc::getpid() } as u32;
    // SAFETY: geteuid has no preconditions and cannot fail.
    let uid = unsafe { libc::geteuid() };
    sockets::inodes(pid, uid).unwrap();
    assert!(sockets::inodes(0, uid).is_err());
}
