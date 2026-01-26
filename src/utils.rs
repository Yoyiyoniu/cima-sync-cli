use colored::*;

pub fn print_banner() {
    println!("\n{}", "┌─────────────────────────────────────┐".bright_cyan());
    println!("{}", "│  █▀▀ █ █▀▄▀█ ▄▀█   █▀ █▄█ █▄░█ █▀▀  │".bright_cyan().bold());
    println!("{}", "│  █▄▄ █ █░▀░█ █▀█   ▄█ ░█░ █░▀█ █▄▄  │".bright_cyan().bold());
    println!("{}\n", "└─────────────────────────────────────┘".bright_cyan());
}