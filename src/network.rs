use crate::auth::{CaptivePortalStatus, captive_portal_status, get_current_ssid};
use colored::*;
use std::fs;
use std::io;
use std::mem;
use std::os::fd::RawFd;

const RTMGRP_LINK: u32 = 1;
const RTMGRP_IPV4_IFADDR: u32 = 0x10;
const RTMGRP_IPV6_IFADDR: u32 = 0x100;
const RTMGRP_IPV4_ROUTE: u32 = 0x40;
const RTMGRP_IPV6_ROUTE: u32 = 0x400;

const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const RTM_NEWADDR: u16 = 20;
const RTM_DELADDR: u16 = 21;
const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;

pub fn run_network_watcher() -> Result<(), Box<dyn std::error::Error>> {
    let listener = NetlinkListener::new()?;
    let mut last_snapshot = NetworkSnapshot::read();

    println!("{}", "├─ Watcher de red iniciado".bright_green());
    println!(
        "{}",
        "├─ Esperando eventos Netlink del kernel".bright_black()
    );
    print_snapshot("└─ Estado inicial", &last_snapshot);

    loop {
        let events = listener.recv_events()?;

        if events.is_empty() {
            continue;
        }

        let current_snapshot = NetworkSnapshot::read();
        print_events(&events);

        if current_snapshot != last_snapshot {
            print_snapshot("└─ Estado actualizado", &current_snapshot);
            last_snapshot = current_snapshot;
        } else {
            println!("{}", "└─ Sin cambio observable de red".bright_black());
        }
    }
}

struct NetlinkListener {
    fd: RawFd,
}

impl NetlinkListener {
    fn new() -> io::Result<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };

        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let groups = RTMGRP_LINK
            | RTMGRP_IPV4_IFADDR
            | RTMGRP_IPV6_IFADDR
            | RTMGRP_IPV4_ROUTE
            | RTMGRP_IPV6_ROUTE;
        let mut addr = unsafe { mem::zeroed::<libc::sockaddr_nl>() };
        addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        addr.nl_pid = 0;
        addr.nl_groups = groups;

        let bind_result = unsafe {
            libc::bind(
                fd,
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };

        if bind_result < 0 {
            let error = io::Error::last_os_error();
            unsafe {
                libc::close(fd);
            }
            return Err(error);
        }

        Ok(Self { fd })
    }

    fn recv_events(&self) -> io::Result<Vec<String>> {
        let mut buffer = [0u8; 8192];
        let bytes_read = unsafe {
            libc::recv(
                self.fd,
                buffer.as_mut_ptr() as *mut libc::c_void,
                buffer.len(),
                0,
            )
        };

        if bytes_read < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(parse_netlink_events(&buffer[..bytes_read as usize]))
    }
}

impl Drop for NetlinkListener {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NetworkSnapshot {
    ssid: Option<String>,
    default_interface: Option<String>,
    portal: PortalReport,
}

impl NetworkSnapshot {
    fn read() -> Self {
        Self {
            ssid: get_current_ssid().ok().filter(|ssid| !ssid.is_empty()),
            default_interface: get_default_interface().ok().flatten(),
            portal: PortalReport::read(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PortalReport {
    Authenticated,
    RequiresAuth,
    Unavailable(String),
}

impl PortalReport {
    fn read() -> Self {
        match captive_portal_status() {
            Ok(CaptivePortalStatus::Authenticated) => Self::Authenticated,
            Ok(CaptivePortalStatus::RequiresAuth { .. }) => Self::RequiresAuth,
            Ok(CaptivePortalStatus::Unavailable { reason }) => Self::Unavailable(reason),
            Err(error) => Self::Unavailable(error.to_string()),
        }
    }
}

fn parse_netlink_events(buffer: &[u8]) -> Vec<String> {
    let header_size = mem::size_of::<libc::nlmsghdr>();
    let mut offset = 0;
    let mut events = Vec::new();

    while offset + header_size <= buffer.len() {
        let header =
            unsafe { std::ptr::read_unaligned(buffer[offset..].as_ptr() as *const libc::nlmsghdr) };

        if header.nlmsg_len < header_size as u32 {
            break;
        }

        let message_len = align_to_4(header.nlmsg_len as usize);
        if offset + message_len > buffer.len() {
            break;
        }

        if let Some(event) = describe_netlink_event(header.nlmsg_type) {
            events.push(event.to_string());
        }

        offset += message_len;
    }

    events.sort();
    events.dedup();
    events
}

fn align_to_4(value: usize) -> usize {
    (value + 3) & !3
}

fn describe_netlink_event(message_type: u16) -> Option<&'static str> {
    match message_type {
        RTM_NEWLINK => Some("interfaz activa o modificada"),
        RTM_DELLINK => Some("interfaz eliminada"),
        RTM_NEWADDR => Some("dirección IP asignada"),
        RTM_DELADDR => Some("dirección IP eliminada"),
        RTM_NEWROUTE => Some("ruta de red actualizada"),
        RTM_DELROUTE => Some("ruta de red eliminada"),
        _ => None,
    }
}

fn get_default_interface() -> io::Result<Option<String>> {
    let routes = fs::read_to_string("/proc/net/route")?;

    for line in routes.lines().skip(1) {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() > 2 && fields[1] == "00000000" {
            return Ok(Some(fields[0].to_string()));
        }
    }

    Ok(None)
}

fn print_events(events: &[String]) {
    println!(
        "{} {}",
        "├─ Evento de red:".bright_cyan().bold(),
        events.join(", ").bright_white()
    );
}

fn print_snapshot(prefix: &str, snapshot: &NetworkSnapshot) {
    println!("{}", prefix.bright_cyan().bold());
    println!(
        "{} {}",
        "   ├─ SSID:".bright_black(),
        snapshot
            .ssid
            .as_deref()
            .unwrap_or("sin WiFi detectado")
            .bright_white()
    );
    println!(
        "{} {}",
        "   ├─ Interfaz por defecto:".bright_black(),
        snapshot
            .default_interface
            .as_deref()
            .unwrap_or("sin ruta por defecto")
            .bright_white()
    );
    println!(
        "{} {}",
        "   └─ Portal cautivo:".bright_black(),
        describe_portal(&snapshot.portal)
    );
}

fn describe_portal(portal: &PortalReport) -> ColoredString {
    match portal {
        PortalReport::Authenticated => "autenticado".bright_green(),
        PortalReport::RequiresAuth => "requiere autenticación".bright_yellow(),
        PortalReport::Unavailable(reason) => format!("no disponible ({reason})").bright_red(),
    }
}
