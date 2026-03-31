use std::path::PathBuf;

use anyhow::Result;
use clap::Subcommand;

use recovermax_core::io::ImageReader;
use recovermax_core::scan::Scanner;
use recovermax_core::carve;
use recovermax_core::recover;

pub struct Args {
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Show information about a disk image or device
    Info {
        /// Path to disk image or block device
        image: PathBuf,
    },

    /// Scan a disk image for recoverable filesystems and files
    Scan {
        /// Path to disk image or block device
        image: PathBuf,

        /// Output scan results to file (JSON)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Recover files from a disk image
    Recover {
        /// Path to disk image or block device
        image: PathBuf,

        /// Destination directory for recovered files
        #[arg(short, long)]
        dest: PathBuf,

        /// Load a previous scan file instead of re-scanning
        #[arg(short, long)]
        scan_file: Option<PathBuf>,

        /// Recover specific path (e.g. /home/username)
        #[arg(short, long)]
        path: Option<String>,
    },

    /// Raw carve files by signature (like photorec)
    Carve {
        /// Path to disk image or block device
        image: PathBuf,

        /// Destination directory for carved files
        #[arg(short, long)]
        dest: PathBuf,

        /// File types to carve (e.g. jpg,png,pdf). Default: all known types
        #[arg(short, long)]
        types: Option<String>,
    },

    /// Hex dump a region of the image
    Hexdump {
        /// Path to disk image or block device
        image: PathBuf,

        /// Offset in bytes (supports 0x prefix for hex)
        #[arg(short, long, default_value = "0")]
        offset: String,

        /// Number of bytes to dump
        #[arg(short, long, default_value = "512")]
        length: usize,
    },
}

pub fn run(args: Args) -> Result<()> {
    match args.command {
        Command::Info { image } => {
            let reader = ImageReader::open(&image)?;
            println!("Image: {}", image.display());
            println!("Size:  {} ({} bytes)", bytesize::ByteSize(reader.len()), reader.len());

            let scanner = Scanner::new(&reader);
            let partitions = scanner.detect_partitions()?;

            if partitions.is_empty() {
                println!("\nNo partition table found. Image may be a raw partition.");
            } else {
                println!("\nPartitions:");
                for (i, p) in partitions.iter().enumerate() {
                    println!(
                        "  #{}: {} offset={} size={} type={}",
                        i,
                        p.name,
                        bytesize::ByteSize(p.offset),
                        bytesize::ByteSize(p.size),
                        p.fs_type
                    );
                }
            }

            // Try to detect filesystem directly
            let fs_info = scanner.detect_filesystem(0)?;
            if let Some(info) = fs_info {
                println!("\nFilesystem at offset 0:");
                println!("  Type:       {}", info.fs_type);
                println!("  Label:      {}", info.label);
                println!("  Block size: {}", info.block_size);
                println!("  Total size: {}", bytesize::ByteSize(info.total_size));
            }

            Ok(())
        }

        Command::Scan { image, output } => {
            let reader = ImageReader::open(&image)?;
            let scanner = Scanner::new(&reader);
            let report = scanner.full_scan()?;

            println!("{}", report.summary());

            if let Some(path) = output {
                let json = serde_json::to_string_pretty(&report)?;
                std::fs::write(&path, json)?;
                println!("\nScan saved to {}", path.display());
            }

            Ok(())
        }

        Command::Recover { image, dest, scan_file, path } => {
            let reader = ImageReader::open(&image)?;

            let report = if let Some(sf) = scan_file {
                let data = std::fs::read_to_string(&sf)?;
                serde_json::from_str(&data)?
            } else {
                let scanner = Scanner::new(&reader);
                scanner.full_scan()?
            };

            let recoverer = recover::Recoverer::new(&reader, &dest);
            recoverer.recover(&report, path.as_deref())?;

            Ok(())
        }

        Command::Carve { image, dest, types } => {
            let reader = ImageReader::open(&image)?;
            let type_filter: Option<Vec<&str>> = types.as_deref().map(|t| t.split(',').collect());
            let carver = carve::Carver::new(&reader, &dest);
            carver.carve(type_filter.as_deref())?;

            Ok(())
        }

        Command::Hexdump { image, offset, length } => {
            let reader = ImageReader::open(&image)?;
            let off = if offset.starts_with("0x") || offset.starts_with("0X") {
                u64::from_str_radix(offset.trim_start_matches("0x").trim_start_matches("0X"), 16)?
            } else {
                offset.parse()?
            };
            let data = reader.read_at(off, length)?;
            print_hexdump_pub(data, off);
            Ok(())
        }
    }
}

pub fn print_hexdump_pub(data: &[u8], base_offset: u64) {
    for (i, chunk) in data.chunks(16).enumerate() {
        let addr = base_offset + (i * 16) as u64;
        print!("{:08x}  ", addr);

        for (j, byte) in chunk.iter().enumerate() {
            print!("{:02x} ", byte);
            if j == 7 {
                print!(" ");
            }
        }

        if chunk.len() < 16 {
            for j in chunk.len()..16 {
                print!("   ");
                if j == 7 {
                    print!(" ");
                }
            }
        }

        print!(" |");
        for byte in chunk {
            if byte.is_ascii_graphic() || *byte == b' ' {
                print!("{}", *byte as char);
            } else {
                print!(".");
            }
        }
        println!("|");
    }
}
