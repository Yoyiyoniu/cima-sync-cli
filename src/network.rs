use crate::auth::{
    login, CaptivePortalStatus, captive_portal_status, get_current_ssid,
};
use crate::logging::LOG_TARGET;
use colored::*;
use std::fs;
use std::io;
use std::mem;
use std::os::fd::RawFd;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

const NETWORK_SCRIPT_EMBEDDED: &str = include_str!("../scripts/force-network.sh");

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

/// Resuelve `scripts/force-network.sh`: env, árbol del proyecto, junto al binario,
/// cwd, o **materializa** la copia embebida en caché (`~/.cache/cima-sync-cli/` en Linux).
pub fn resolve_force_network_script() -> Option<PathBuf> {
    if let Ok(custom) = std::env::var("CIMA_SYNC_FORCE_NETWORK_SCRIPT") {
        let p = PathBuf::from(custom);
        if p.is_file() {
            return Some(p);
        }
    }

    let manifest_script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/force-network.sh");
    if manifest_script.is_file() {
        return Some(manifest_script);
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            for rel in ["scripts/force-network.sh", "../scripts/force-network.sh"] {
                let candidate = dir.join(rel);
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
    }

    if let Ok(cwd) = std::env::current_dir() {
        let candidate = cwd.join("scripts/force-network.sh");
        if candidate.is_file() {
            return Some(candidate);
        }
    }

    materialize_embedded_force_network_script().ok()
}

fn materialize_embedded_force_network_script() -> io::Result<PathBuf> {
    let base = dirs::cache_dir()
        .or_else(|| dirs::data_local_dir())
        .unwrap_or_else(std::env::temp_dir);
    let dir = base.join("cima-sync-cli");
    fs::create_dir_all(&dir)?;
    let path = dir.join("force-network.sh");

    let need_write = match fs::read_to_string(&path) {
        Ok(existing) => existing != NETWORK_SCRIPT_EMBEDDED,
        Err(_) => true,
    };
    if need_write {
        fs::write(&path, NETWORK_SCRIPT_EMBEDDED)?;
    }
    #[cfg(unix)]
    {
        let mut perm = fs::metadata(&path)?.permissions();
        perm.set_mode(0o755);
        fs::set_permissions(&path, perm)?;
    }

    tracing::info!(
        target: LOG_TARGET,
        "[Network] Script embebido materializado en {}",
        path.display()
    );
    Ok(path)
}

/// Red con clave: `wifi_password` o variable de entorno `CIMA_SYNC_WIFI_PASSWORD` antes de llamar.
pub fn run_force_network(iface: &str, wifi_ssid: &str, wifi_password: Option<&str>) -> io::Result<()> {
    let script = resolve_force_network_script().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "No se encontró ni se pudo extraer force-network.sh. Define CIMA_SYNC_FORCE_NETWORK_SCRIPT, \
             coloca scripts/ junto al binario, o revisa permisos de caché (~/.cache/cima-sync-cli/).",
        )
    })?;

    tracing::info!(
        target: LOG_TARGET,
        "[Network] Force reconnect | iface={} | ssid={} | script={}",
        iface,
        wifi_ssid,
        script.display(),
    );

    let mut cmd = Command::new("bash");
    cmd.arg(script.as_os_str()).arg(iface).arg(wifi_ssid);
    if let Some(pw) = wifi_password.filter(|s| !s.is_empty()) {
        cmd.env("CIMA_SYNC_WIFI_PASSWORD", pw);
    }
    let status = cmd.status()?;

    if !status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("force-network.sh terminó con código {status}"),
        ));
    }

    Ok(())
}

const AUTO_LOGIN_COOLDOWN: Duration = Duration::from_secs(45);

const PORTAL_STALE_DEFAULT: Duration = Duration::from_secs(75);

fn portal_stale_max() -> Duration {
    std::env::var("CIMA_SYNC_PORTAL_REFRESH_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(PORTAL_STALE_DEFAULT)
}

pub fn run_auto_login_watcher(username: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    let listener = NetlinkListener::new()?;
    let stale_max = portal_stale_max();

    let mut last_link = NetworkLink::read();
    let mut last_portal = PortalReport::read();
    let mut last_portal_probe = Instant::now();
    let mut login_cooldown: Option<Instant> = None;

    println!("{}", "├─ Auto-login persistente (Netlink + portal UABC)".bright_green());
    tracing::info!(target: LOG_TARGET, "[AutoLogin] Watcher started user={}", username);
    println!(
        "{}",
        "├─ Escuchando el kernel; se reautentica si el portal lo pide".bright_black()
    );
    tracing::info!(
        target: LOG_TARGET,
        "[Kernel] Netlink subscription ready; auto-login cooldown={}s portal_refresh={}s",
        AUTO_LOGIN_COOLDOWN.as_secs(),
        stale_max.as_secs()
    );
    let initial_snapshot = NetworkSnapshot::from_parts(&last_link, &last_portal);
    print_snapshot("└─ Estado inicial", &initial_snapshot);
    try_auto_login_for_portal(&last_portal, None, username, password, &mut login_cooldown);

    loop {
        let events = listener.recv_events()?;

        if events.is_empty() {
            continue;
        }

        print_events(&events);

        let current_link = NetworkLink::read();
        let link_changed = current_link != last_link;
        let portal_stale =
            Instant::now().duration_since(last_portal_probe) >= stale_max;
        let need_portal_probe = link_changed || portal_stale;

        // Solo se llama al portal (HTTP) si el enlace cambió o caducó la última sonda.
        let current_portal = if need_portal_probe {
            let p = PortalReport::read();
            last_portal_probe = Instant::now();
            p
        } else {
            last_portal.clone()
        };

        let snapshot_changed = link_changed || current_portal != last_portal;

        if snapshot_changed {
            let snap = NetworkSnapshot::from_parts(&current_link, &current_portal);
            print_snapshot("└─ Estado actualizado", &snap);
            last_link = current_link;
        } else {
            println!("{}", "└─ Sin cambio observable de red".bright_black());
            tracing::debug!(
                target: LOG_TARGET,
                "[Kernel] Event received; network snapshot unchanged",
            );
        }

        let previous_portal = mem::replace(&mut last_portal, current_portal);
        try_auto_login_for_portal(
            &last_portal,
            Some(&previous_portal),
            username,
            password,
            &mut login_cooldown,
        );
    }
}

fn try_auto_login_for_portal(
    portal: &PortalReport,
    previous: Option<&PortalReport>,
    username: &str,
    password: &str,
    cooldown: &mut Option<Instant>,
) {
    let transitioned = previous.map_or(true, |prev| prev != portal);
    match portal {
        PortalReport::Authenticated => {
            *cooldown = None;
            if transitioned {
                tracing::info!(target: LOG_TARGET, "[AutoLogin] Portal autenticado");
            } else {
                tracing::debug!(target: LOG_TARGET, "[AutoLogin] Portal sigue autenticado");
            }
        }
        PortalReport::RequiresAuth => {
            let now = Instant::now();
            if let Some(t) = *cooldown {
                if now.duration_since(t) < AUTO_LOGIN_COOLDOWN {
                    tracing::info!(
                        target: LOG_TARGET,
                        "[AutoLogin] Cooldown {}s; sin reintento aún",
                        AUTO_LOGIN_COOLDOWN.as_secs()
                    );
                    return;
                }
            }
            *cooldown = Some(now);

            println!(
                "{}",
                "├─ Portal: requiere sesión → auto-login…".bright_yellow().bold()
            );
            tracing::info!(
                target: LOG_TARGET,
                "[AutoLogin] Intentando login portal user={}",
                username
            );

            match login(username, password) {
                Ok(_) => {
                    println!(
                        "{} {}",
                        "├─ ✓".bright_green().bold(),
                        "Auto-login completado".bright_green()
                    );
                    tracing::info!(target: LOG_TARGET, "[AutoLogin] Login OK");
                }
                Err(e) => {
                    println!(
                        "{} {} {}",
                        "├─ ✗".bright_red().bold(),
                        "Auto-login falló:".bright_red(),
                        e.to_string().red()
                    );
                    tracing::warn!(target: LOG_TARGET, "[AutoLogin] Error: {}", e);
                }
            }
        }
        PortalReport::Unavailable(reason) => {
            if transitioned {
                tracing::info!(
                    target: LOG_TARGET,
                    "[AutoLogin] Portal no comprobable: {}",
                    reason
                );
            } else {
                tracing::debug!(
                    target: LOG_TARGET,
                    "[AutoLogin] Portal sigue no comprobable: {}",
                    reason
                );
            }
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

/// Lectura barata del enlace local (sin red): SSID + interfaz por defecto.
#[derive(Debug, Clone, PartialEq, Eq)]
struct NetworkLink {
    ssid: Option<String>,
    default_interface: Option<String>,
}

impl NetworkLink {
    fn read() -> Self {
        Self {
            ssid: get_current_ssid().ok().filter(|ssid| !ssid.is_empty()),
            default_interface: get_default_interface().ok().flatten(),
        }
    }
}

/// Snapshot completo (enlace + portal). Solo se usa para imprimir UI/log.
#[derive(Debug, Clone, PartialEq, Eq)]
struct NetworkSnapshot {
    ssid: Option<String>,
    default_interface: Option<String>,
    portal: PortalReport,
}

impl NetworkSnapshot {
    fn from_parts(link: &NetworkLink, portal: &PortalReport) -> Self {
        Self {
            ssid: link.ssid.clone(),
            default_interface: link.default_interface.clone(),
            portal: portal.clone(),
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
    tracing::info!(
        target: LOG_TARGET,
        "[Kernel] {}",
        events.join(", ")
    );
}

fn print_snapshot(prefix: &str, snapshot: &NetworkSnapshot) {
    println!("{}", prefix.bright_cyan().bold());
    let ssid = snapshot
        .ssid
        .as_deref()
        .unwrap_or("sin WiFi detectado");
    let iface = snapshot
        .default_interface
        .as_deref()
        .unwrap_or("sin ruta por defecto");
    println!(
        "{} {}",
        "   ├─ SSID:".bright_black(),
        ssid.bright_white()
    );
    println!(
        "{} {}",
        "   ├─ Interfaz por defecto:".bright_black(),
        iface.bright_white()
    );
    println!(
        "{} {}",
        "   └─ Portal cautivo:".bright_black(),
        describe_portal(&snapshot.portal)
    );
    tracing::info!(
        target: LOG_TARGET,
        "[Network] Snapshot | ssid={} | default_if={} | portal={}",
        ssid,
        iface,
        portal_plain(&snapshot.portal),
    );
}

fn portal_plain(portal: &PortalReport) -> String {
    match portal {
        PortalReport::Authenticated => "authenticated".into(),
        PortalReport::RequiresAuth => "requires_auth".into(),
        PortalReport::Unavailable(reason) => format!("unavailable ({reason})"),
    }
}

fn describe_portal(portal: &PortalReport) -> ColoredString {
    match portal {
        PortalReport::Authenticated => "autenticado".bright_green(),
        PortalReport::RequiresAuth => "requiere autenticación".bright_yellow(),
        PortalReport::Unavailable(reason) => format!("no disponible ({reason})").bright_red(),
    }
}
