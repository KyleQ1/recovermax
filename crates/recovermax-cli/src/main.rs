mod cli;
mod daemon;
mod tui;

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "recovermax",
    version,
    about = "High-performance data recovery tool",
    long_about = "High-performance data recovery tool.\n\n\
        Run with no arguments to show the daemon-backed workflow:\n  \
        recovermax\n\n\
        Open a specific image directly in the stateful interpreter:\n  \
        recovermax /path/to/image.img\n\n\
        Or use subcommands for scripted one-shot mode:\n  \
        recovermax scan /path/to/image.img -o scan.scn"
)]
struct TopLevel {
    /// Image path for interactive mode
    image: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<cli::Command>,
}

fn main() -> Result<()> {
    // RUST_LOG wins when set; otherwise keep warn-level output visible so
    // core library warnings (session size mismatch, corrupt metadata, etc.)
    // reach the user without them having to opt in.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .init();

    let args = TopLevel::parse();

    match (args.command, args.image) {
        // Subcommand mode: recovermax scan image.img ...
        (Some(cmd), _) => {
            let wrapped = cli::Args { command: cmd };
            cli::run(wrapped)
        }
        // Interactive mode with explicit image
        (None, Some(image)) => tui::run_tui(&image, None),
        // No args at all -> show daemon-first guidance
        (None, None) => {
            print_default_guidance();
            Ok(())
        }
    }
}

fn print_default_guidance() {
    println!("RecoverMax");
    println!();
    println!("Daemon foundation:");
    println!("  recovermax daemon start --workspace case1");
    println!("  recovermax daemon status --workspace case1 --json");
    println!("  recovermax daemon release --workspace case1");
    println!("  recovermax daemon stop --workspace case1");
    println!();
    println!("Daemon-backed scan routing is planned next.");
    println!();
    println!("Current direct modes:");
    println!("  recovermax /path/to/image.img");
    println!("  recovermax scan /path/to/image.img -o scan.scn");
    println!();
    println!("Run 'recovermax --help' for all commands.");
}
