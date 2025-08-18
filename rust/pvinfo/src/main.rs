//! pvinfo tool implementation
//!
//! Usage:
//!     pvinfo
//!     pvinfo --se-status
//!     pvinfo --facilities
//!
//! Requirements:
//!   1) Verifies the UV directory is present.
//!   2) Prints Secure Execution mode (Guest / Host / Neither / Error if both)
//!   3) If no option specified the tool must show all available information
//!   

// Necessary Packages 
use clap::Parser;
use std::fs;
use std::path::Path;
use std::process;

// Path to the UV directory 
const UV_FOLDER: &str = "/home/annmariyajojo/Documents/s390_tools_learning/s390-tools/uv";

// Path to the pvinfo soure code
const PVINFO_SRC: &str = "/home/annmariyajojo/Documents/s390_tools_learning/s390-tools/rust/pvinfo/src";

/// Paths
const UV_QUERY_DIR: &str = "/home/annmariyajojo/Documents/s390_tools_learning/s390-tools/uv/query";
const FACILITIES_FILE: &str = "facilities";               // Hex mask file
const FACILITIES_DESC_FILE: &str = "facilities_value.txt"; // Descriptions


/// Simple CLI for pvinfo
#[derive(Parser, Debug)]
#[command(author, version, about = "Protected Virtualization info")]
struct Cli {
    /// Show Secure Execution status (Guest / Host / Neither)
    #[arg(long)]
    se_status: bool,

    /// Show active Ultravisor facilities
    #[arg(long)]
    facilities: bool,

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

    if args.facilities {
    handle_facilities(
        &Path::new(UV_FOLDER).join("query"),
        Path::new(PVINFO_SRC),
    );
    any = true;
    }


  // Show everything in default
    if !any {
        show_everything();
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


/*==================== SE status ====================*/

// Read flags and decide Secure Execution Mode
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


/*==================== Facilities ====================*/


/// Read facilities hex mask from uv/query/facilities
fn read_facilities_mask(query_dir: &Path) -> Option<u64> {
    let path = query_dir.join(FACILITIES_FILE);

    // Read file into a string
    let content = fs::read_to_string(&path).ok()?;
    let first_line = content.lines().find(|l| !l.trim().is_empty())?.trim();

    // Remove optional "0x" prefix
    let hex_str = first_line.trim_start_matches("0x");

    // Parse as u64 (hexadecimal)
    u64::from_str_radix(hex_str, 16).ok()
}

/// Print active facilities based on the mask
fn print_facilities(mask: u64, desc_file: &Path) {
    // Read descriptions (each line corresponds to a bit)
    let content = fs::read_to_string(desc_file).unwrap_or_else(|_| {
        eprintln!("Could not read {}", desc_file.display());
        return String::new();
    });

    let lines: Vec<&str> = content.lines().collect();
    let mut found = false;

    // Each line = one bit (line 0 = highest bit, line 63 = lowest bit)
    for (line_index, line) in lines.iter().enumerate() {
        let bit_position = 63 - line_index;

        if (mask & (1u64 << bit_position)) != 0 {
            // Special case: bit 10 → always say reserved
            if bit_position == 10 {
                println!("Reserved (Bit-10)");
            }
            // If line itself is marked reserved → print with bit number
            else if line.contains("Reserved") {
                println!("{} (Bit-{})", line, bit_position);
            }
            // Normal case → just print description
            else {
                println!("{}", line);
            }
            found = true;
        }
    }

    // Handle extra case: if any bits above 33 are set but no description line exists
    for bit_position in (34..64).rev() {
        if (mask & (1u64 << bit_position)) != 0 {
            if (63 - bit_position) >= lines.len() {
                println!("Bit-{} is active", bit_position);
                found = true;
            }
        }
    }

    if !found {
        println!("(no active facilities)");
    }
}


/// Top-level handler for facilities
pub fn handle_facilities(query_dir: &Path, src_dir: &Path) {
    let desc_path = src_dir.join(FACILITIES_DESC_FILE);

    match read_facilities_mask(query_dir) {
        Some(mask) if mask != 0 => {
            print_facilities(mask, &desc_path);
        }
        _ => println!("No facilities found or file empty."),
    }
}


fn show_everything() {
    println!("--- Secure Execution Status ----");
    determine_se_mode(Path::new(UV_FOLDER));

    println!("\n---- Facilities ----");
    handle_facilities(
        &Path::new(UV_FOLDER).join("query"),
        Path::new(PVINFO_SRC),
    );
}
