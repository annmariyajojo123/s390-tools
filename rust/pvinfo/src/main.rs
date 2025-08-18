//! pvinfo tool implementation
//!
//! Usage:
//!     pvinfo --se-status
//!
//! Requirements:
//!   1) Verifies the UV directory is present.
//!   2) Prints Secure Execution mode (Guest / Host / Neither / Error if both)

// Necessary Packages 
use clap::Parser;
use std::fs;
use std::path::Path;
use std::process;

// Path to the UV directory 
const UV_FOLDER: &str = "/home/annmariyajojo/Documents/s390_tools_learning/s390-tools/uv";

// Path to the pvinfo soure code
const PVINFO_SRC: &str = "/home/annmariyajojo/Documents/s390_tools_learning/s390-tools/rust/pvinfo/src";


/// Simple CLI for pvinfo
#[derive(Parser, Debug)]
#[command(author, version, about = "Protected Virtualization info")]
struct Cli {
    /// Show Secure Execution status (Guest / Host / Neither)
    #[arg(long)]
    se_status: bool,

}

fn main() {


    let args = Cli::parse();

    // Check if uv folder exists or not 
    verify_uv_folder();

    let mut any = false;

    // Run SE-status if requested
    if args.se_status {
        determine_se_mode(Path::new(UV_FOLDER));
        any = true;
    }


    // If no flags at all → show usage hint
    if !any {
        eprintln!("Hint: run with --se-status or --facilities");
    }
}


// Function to check if the UV directory exists
fn verify_uv_folder() {
    if !Path::new(UV_FOLDER).exists() {
        println!("UV directory not found at {UV_FOLDER}");
        println!("Does not operate as a SE host or SE guest.");
        process::exit(0);
    }
}

// Function interprets "0" or "1" from a file
fn read_flag_file(path: &Path) -> bool {
    if let Ok(content) = fs::read_to_string(path) {
        return content.trim() == "1";
    }
    false
}

// Read flags and decide SE mode
fn determine_se_mode(base_dir: &Path) {
    let guest_flag = read_flag_file(&base_dir.join("prot_virt_guest"));
    let host_flag = read_flag_file(&base_dir.join("prot_virt_host"));

    match (guest_flag, host_flag) {
        (true, false) => println!("Secure Execution Guest Mode"),
        (false, true) => println!("Secure Execution Host Mode"),
        (false, false) => println!("Secure Execution is disabled (neither guest nor host)"),
        (true, true) => println!("Configuration error: system cannot be both SE guest and SE host"),
    }
}


