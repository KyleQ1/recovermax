mod cli;
mod shell;

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
        Run with just an image path for interactive mode:\n  \
        recovermax /path/to/image.img\n\n\
        Or use subcommands for scripted/one-shot mode:\n  \
        recovermax scan /path/to/image.img -o scan.json"
)]
struct TopLevel {
    /// Image path for interactive mode
    image: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<cli::Command>,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = TopLevel::parse();

    match (args.command, args.image) {
        // Subcommand mode: recovermax scan image.img ...
        (Some(cmd), _) => {
            let wrapped = cli::Args { command: cmd };
            cli::run(wrapped)
        }
        // Interactive mode: recovermax image.img
        (None, Some(image)) => {
            shell::run_interactive(&image)
        }
        // No args at all
        (None, None) => {
            println!("RecoverMax v{}", env!("CARGO_PKG_VERSION"));
            println!();
            println!("Interactive mode:");
            println!("  recovermax <image>              Open image in interactive shell");
            println!();
            println!("One-shot commands:");
            println!("  recovermax info <image>          Show image info");
            println!("  recovermax scan <image>          Scan for filesystems");
            println!("  recovermax recover <image> ...   Recover files");
            println!("  recovermax carve <image> ...     Raw carve by signature");
            println!("  recovermax hexdump <image> ...   Hex dump region");
            println!();
            println!("Run 'recovermax --help' for full usage.");
            Ok(())
        }
    }
}
