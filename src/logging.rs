use std::path::PathBuf;
use std::sync::OnceLock;
use tracing_subscriber::fmt::time::SystemTime;

static LOG_GUARD: OnceLock<tracing_appender::non_blocking::WorkerGuard> = OnceLock::new();

pub const LOG_TARGET: &str = "CIMA-SYNC";
const LOG_FILE: &str = "logs/cima-sync.log";

pub fn log_system_inventory() {
    let hostname = read_trimmed("/etc/hostname").unwrap_or_else(|| "unknown".to_string());
    let kernel = read_trimmed("/proc/sys/kernel/osrelease").unwrap_or_else(|| "unknown".to_string());
    let os_name = format!("{}-{}", std::env::consts::OS, std::env::consts::FAMILY);
    let arch = std::env::consts::ARCH;
    let cpu_model = read_cpu_model().unwrap_or_else(|| "unknown".to_string());
    let cpu_threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(0);
    let total_ram_kib = read_mem_total_kib().unwrap_or(0);
    let total_ram_gib = (total_ram_kib as f64) / (1024.0 * 1024.0);

    tracing::info!(
        target: LOG_TARGET,
        "[System] Host inventory | hostname={} | os={} | kernel={} | arch={} | cpu_model={} | cpu_threads={} | ram_kib={} | ram_gib={:.2} | runtime={} | version={}",
        hostname,
        os_name,
        kernel,
        arch,
        cpu_model,
        cpu_threads,
        total_ram_kib,
        total_ram_gib,
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
    );
}

pub fn log_system_inventory_and_version() {
    log_system_inventory();
}

pub fn init() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let log_path = match std::env::var_os("CIMA_SYNC_LOG_PATH") {
        Some(custom) => PathBuf::from(custom),
        None => std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(LOG_FILE),
    };
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;

    let (non_blocking, guard) = tracing_appender::non_blocking(file);
    LOG_GUARD
        .set(guard)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::AlreadyExists, "log ya inicializado"))?;

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_writer(non_blocking)
        .with_timer(SystemTime)
        .with_ansi(false)
        .with_target(true)
        .with_level(true)
        .try_init()
        .map_err(|e| format!("no se pudo registrar el recolector de trazas: {e}"))?;

    Ok(log_path)
}

fn read_trimmed(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn read_mem_total_kib() -> Option<u64> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    let line = meminfo.lines().find(|line| line.starts_with("MemTotal:"))?;
    let parts = line.split_whitespace().collect::<Vec<_>>();
    parts.get(1)?.parse::<u64>().ok()
}

fn read_cpu_model() -> Option<String> {
    let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").ok()?;
    for line in cpuinfo.lines() {
        if let Some(value) = line.strip_prefix("model name\t: ") {
            return Some(value.trim().to_string());
        }
        if let Some(value) = line.strip_prefix("Hardware\t: ") {
            return Some(value.trim().to_string());
        }
    }
    None
}
