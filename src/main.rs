mod auth;
mod config;
mod logging;
mod network;
mod utils;

use std::path::PathBuf;

use clap::Parser;
use colored::*;
use rpassword;

use auth::login;
use config::{
    auto_login_credentials, load_config, merged_network, resolve_auth_password, resolve_auth_user,
};
use logging::LOG_TARGET;
use network::{run_auto_login_watcher, run_force_network};
use utils::print_banner;

#[derive(Parser)]
#[command(name = "Cima Sync - CLI")]
#[command(about = "Auth on captive portal on UABC wifi using CLI")]
#[command(disable_help_flag = true)]
struct Cli {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long, short = 'a')]
    auth: Option<String>,
    #[arg(long)]
    auto_login: bool,
    #[arg(long)]
    force_network: bool,
    #[arg(long)]
    iface: Option<String>,
    #[arg(long)]
    wifi_ssid: Option<String>,
    #[arg(long, short = 'h')]
    help: bool,
}

fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("fallo al instalar CryptoProvider por defecto");

    match logging::init() {
        Ok(path) => {
            tracing::info!(
                target: LOG_TARGET,
                "[App] Startup | version={} | log_file={}",
                env!("CARGO_PKG_VERSION"),
                path.display(),
            );
            logging::log_system_inventory_and_version();
        }
        Err(e) => eprintln!(
            "Advertencia: no se puede escribir el registro corporativo en archivo: {e}",
        ),
    }

    let cli = Cli::parse();

    let file_cfg = match load_config(&cli.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{} {}", "✗ Config:".bright_red().bold(), e.red());
            std::process::exit(1);
        }
    };

    if cli.help {
        tracing::info!(target: LOG_TARGET, "[CLI] Help requested (--help)");
        print_commands();
        return;
    }

    let net = merged_network(&cli.iface, &cli.wifi_ssid, file_cfg.as_ref());

    if cli.force_network {
        tracing::info!(
            target: LOG_TARGET,
            "[CLI] Force network | iface={} | ssid={}",
            net.iface,
            net.wifi_ssid
        );
        print_banner();
        if file_cfg.is_some() {
            println!("{}", "├─ Usando config (JSON) + flags CLI".bright_black());
        }
        println!(
            "{} {} → {}",
            "├─ Forzando WiFi en".bright_cyan().bold(),
            net.iface.bright_white(),
            net.wifi_ssid.bright_green()
        );
        match run_force_network(
            &net.iface,
            &net.wifi_ssid,
            net.wifi_password.as_deref(),
        ) {
            Ok(()) => {
                tracing::info!(target: LOG_TARGET, "[Network] Force reconnect completed");
                println!(
                    "{} {}",
                    "├─ ✓".bright_green().bold(),
                    "Script de red ejecutado correctamente".bright_green()
                );
            }
            Err(error) => {
                tracing::error!(
                    target: LOG_TARGET,
                    "[Network] Force reconnect failed: {}",
                    error
                );
                println!(
                    "\n{} {} {}",
                    "✗".bright_red().bold(),
                    "Error:".bright_red().bold(),
                    error.to_string().red()
                );
                std::process::exit(1);
            }
        }
        if !cli.auto_login {
            return;
        }
        println!(
            "{}",
            "├─ Continuando con --auto-login (vigilancia Netlink)…".bright_black()
        );
    }

    if cli.auto_login {
        let (user, pass) = match auto_login_credentials(&cli.auth, file_cfg.as_ref()) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{} {}", "✗".bright_red().bold(), e.red());
                std::process::exit(1);
            }
        };

        tracing::info!(
            target: LOG_TARGET,
            "[CLI] Auto-login persistente user={}",
            user
        );

        if !cli.force_network {
            print_banner();
        }

        if let Err(error) = run_auto_login_watcher(&user, &pass) {
            tracing::error!(
                target: LOG_TARGET,
                "[AutoLogin] Watcher error: {}",
                error
            );
            println!(
                "\n{} {} {}",
                "✗".bright_red().bold(),
                "Error:".bright_red().bold(),
                error.to_string().red()
            );
        }
        return;
    }

    let auth_user = resolve_auth_user(&cli.auth, file_cfg.as_ref());
    if let Some(user) = auth_user {
        tracing::info!(
            target: LOG_TARGET,
            "[CLI] Authentication requested user={}",
            user
        );
        print_banner();

        let password = match resolve_auth_password(file_cfg.as_ref()) {
            Some(p) => {
                println!("{}", "├─ Contraseña tomada de config (JSON)".bright_black());
                p
            }
            None => rpassword::prompt_password(format!("{}", "│ Contraseña: ".bright_yellow()))
                .expect("contraseña requerida"),
        };

        println!("{}", "├─ Autenticando...".bright_black());

        let lg = login(&user, &password);
        match lg {
            Ok(_) => {
                tracing::info!(
                    target: LOG_TARGET,
                    "[Auth] Authentication completed successfully user={}",
                    user
                );
                println!(
                    "{} {}",
                    "├─ ✓".bright_green().bold(),
                    "Sesión iniciada correctamente".bright_green()
                );
                println!(
                    "{} {}",
                    "├─ ✓".bright_green().bold(),
                    "Ya puedes utilizar WiFi".bright_white()
                );
                println!(
                    "{} {}",
                    "├─ ✓".bright_green().bold(),
                    "Más información:".bright_black()
                );
                println!(
                    "{} {}",
                    "└─ 🌐".bright_green().bold(),
                    "https://cima-sync.app".bright_cyan().underline()
                );
            }
            Err(error) => {
                tracing::error!(
                    target: LOG_TARGET,
                    "[Auth] Authentication failed user={}: {}",
                    user,
                    error
                );
                println!(
                    "\n{} {} {}",
                    "✗".bright_red().bold(),
                    "Error:".bright_red().bold(),
                    error.to_string().red()
                );
            }
        }
        return;
    }

    tracing::info!(
        target: LOG_TARGET,
        "[CLI] No arguments provided; printing usage"
    );
    print_commands();
}

fn print_commands() {
    print_banner();
    println!("{}", "Available Commands:".bright_white().bold());
    println!(
        "{} {}",
        "  --config".bright_cyan(),
        "ruta/config.json (user, pass, wifi_ssid, iface, wifi_password)".bright_black()
    );
    println!(
        "{} {}",
        "  --auth".bright_cyan(),
        "<username>  (si falta, se usa «user» del JSON)".bright_black()
    );
    println!(
        "{} {}",
        "  --auto-login".bright_cyan(),
        "Netlink + re-login portal (requiere user y pass en JSON)".bright_black()
    );
    println!(
        "{} {}",
        "  --force-network".bright_cyan(),
        "WiFi desde JSON; con --auto-login: fuerza WiFi y luego vigila".bright_black()
    );
    println!(
        "{} {}",
        "  --iface".bright_cyan(),
        "Sobreescribe «iface» del JSON (default sin JSON: wlan0)".bright_black()
    );
    println!(
        "{} {}",
        "  --wifi-ssid".bright_cyan(),
        "Sobreescribe «wifi_ssid» del JSON (default: UABC-2.4G)".bright_black()
    );
    println!(
        "{} {}",
        "  cargo run".bright_cyan(),
        "cargo run -- --config config.json --auto-login".bright_black()
    );
    println!(
        "\n{} {}  ·  {} {}",
        "Tip:".bright_yellow(),
        "config.example.json".bright_cyan(),
        "Sin --config se busca".bright_yellow(),
        "config.json en el proyecto o cwd".bright_cyan()
    );
    println!(
        "{} {}\n",
        "Ayuda:".bright_yellow(),
        "--help".bright_cyan()
    );
}
