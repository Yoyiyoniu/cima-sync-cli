mod auth;
mod network;
mod utils;

use clap::Parser;
use colored::*;
use rpassword;

use auth::login;
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

    let cli = Cli::parse();

    if cli.help {
        print_commands();
        return;
    }

    if cli.watch {
        print_banner();
        if let Err(error) = run_network_watcher() {
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
            print_banner();

            let password =
                rpassword::prompt_password(format!("{}", "│ Contraseña: ".bright_yellow()))
                    .unwrap();

            println!("{}", "├─ Autenticando...".bright_black());

            let lg = login(&user, &password);
            match lg {
                Ok(_) => {
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
