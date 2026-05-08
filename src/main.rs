mod auth;
mod logging;
mod network;
mod utils;

use clap::Parser;
use colored::*;
use rpassword;

use auth::login;
use logging::LOG_TARGET;
use network::{run_force_network, run_network_watcher};
use utils::print_banner;

#[derive(Parser)]
#[command(name = "Cima Sync - CLI")]
#[command(about = "Auth on captive portal on UABC wifi using CLI")]
#[command(disable_help_flag = true)]
struct Cli {
    #[arg(long, short = 'a')]
    auth: Option<String>,
    #[arg(long, short = 'w')]
    watch: bool,
    #[arg(long)]
    force_network: bool,
    #[arg(long, default_value = "wlan0")]
    iface: String,
    /// SSID al que conecta `--force-network` (red pública UABC 2.4 GHz por defecto).
    #[arg(long, default_value = "UABC-2.4G")]
    wifi_ssid: String,
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

    if cli.help {
        tracing::info!(target: LOG_TARGET, "[CLI] Help requested (--help)");
        print_commands();
        return;
    }

    if cli.force_network {
        tracing::info!(
            target: LOG_TARGET,
            "[CLI] Force network | iface={} | ssid={}",
            cli.iface,
            cli.wifi_ssid
        );
        print_banner();
        println!(
            "{} {} → {}",
            "├─ Forzando WiFi en".bright_cyan().bold(),
            cli.iface.bright_white(),
            cli.wifi_ssid.bright_green()
        );
        match run_force_network(&cli.iface, &cli.wifi_ssid) {
            Ok(()) => {
                tracing::info!(target: LOG_TARGET, "[Network] Force reconnect completed");
                println!(
                    "{} {}",
                    "└─ ✓".bright_green().bold(),
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
            }
        }
        return;
    }

    if cli.watch {
        tracing::info!(target: LOG_TARGET, "[CLI] Watch mode enabled (--watch)");
        print_banner();
        if let Err(error) = run_network_watcher() {
            tracing::error!(
                target: LOG_TARGET,
                "[Watch] Network watcher error: {}",
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

    match cli.auth {
        Some(user) => {
            tracing::info!(
                target: LOG_TARGET,
                "[CLI] Authentication requested (--auth) user={}",
                user
            );
            print_banner();

            let password =
                rpassword::prompt_password(format!("{}", "│ Contraseña: ".bright_yellow()))
                    .unwrap();

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
        }
        None => {
            tracing::info!(
                target: LOG_TARGET,
                "[CLI] No arguments provided; printing usage"
            );
            print_commands();
        }
    }
}

fn print_commands() {
    print_banner();
    println!("{}", "Available Commands:".bright_white().bold());
    println!(
        "{} {}",
        "  --auth".bright_cyan(),
        "<username>".bright_black()
    );
    println!(
        "{} {}",
        "  --watch".bright_cyan(),
        "Escucha cambios de red y estado del portal".bright_black()
    );
    println!(
        "{} {}",
        "  --force-network".bright_cyan(),
        "WiFi rápido hacia --wifi-ssid; paciente: env CIMA_SYNC_WIFI_PATIENT=1".bright_black()
    );
    println!(
        "{} {}",
        "  --iface".bright_cyan(),
        "Interfaz WiFi (default: wlan0)".bright_black()
    );
    println!(
        "{} {}",
        "  --wifi-ssid".bright_cyan(),
        "SSID destino (default: UABC-2.4G); WPA: env CIMA_SYNC_WIFI_PASSWORD".bright_black()
    );
    println!(
        "{} {}",
        "  cargo run".bright_cyan(),
        "cargo run -- --force-network   (el «--» pasa flags al binario, no a cargo)".bright_black()
    );
    println!(
        "\n{} Use {} for more information\n",
        "Tip:".bright_yellow(),
        "--help".bright_cyan()
    );
}
