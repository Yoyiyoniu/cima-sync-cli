mod auth;
mod logging;
mod network;
mod utils;

use clap::Parser;
use colored::*;
use rpassword;

use auth::login;
use logging::LOG_TARGET;
use network::run_network_watcher;
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
        "\n{} Use {} for more information\n",
        "Tip:".bright_yellow(),
        "--help".bright_cyan()
    );
}
