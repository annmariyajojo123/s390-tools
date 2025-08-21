//! pvinfo tool implementation
//!
//! Usage:
//!     pvinfo
//!     pvinfo --se-status
//!     pvinfo --facilities
//!     pvinfo --feature-indications
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

// Path for feature-indication
const FEATURE_BITS_FILE: &str = "feature_indications";                 
const FEATURE_TEXT_FILE: &str = "feature_indications_value.txt";       

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

    /// Show Ultravisor feature indications
    #[arg(long)]
    feature_indications: bool,
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

    if args.feature_indications {
    handle_feature_indications(
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

/// CLI: `pvinfo --se-status`
///
/// Reads the SE guest/host flags and prints the Secure Execution mode:
/// - Guest / Host / Neither / Error if both
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


/// Shared hex mask reader
fn read_hex_mask(path: &Path) -> Option<u64> {
    let content = fs::read_to_string(path).ok()?;
    let first_line = content.lines().find(|l| !l.trim().is_empty())?.trim();
    let hex_str = first_line.trim_start_matches("0x");
    u64::from_str_radix(hex_str, 16).ok()
}

/*==================== Shared Bitmask Printer ====================*/

fn render_mask_bits(mask: u64, desc_file: &Path, reserved_bits: &[usize]) {
    let content = fs::read_to_string(desc_file).unwrap_or_default();
    let lines: Vec<&str> = content.lines().collect();
    let mut any = false;

    // Each line corresponds to a bit (line 0 = Bit 63, line 63 = Bit 0)
    for (line_index, line) in lines.iter().enumerate() {
        let bit_position = 63 - line_index;

        if (mask & (1u64 << bit_position)) != 0 {
            if reserved_bits.contains(&line_index) {
                println!("Confidential - report as reserved Bit-{}", line_index);
            } else if line.contains("Reserved") {
                println!("{} Bit-{}", line, line_index);
            } else {
                println!("{}", line);
            }
            any = true;
        }
    }

    // Handle bits beyond description file
    for extra_line in lines.len()..64 {
        let bit_position = 63 - extra_line;
        if (mask & (1u64 << bit_position)) != 0 {
            println!("Bit-{} is active", extra_line);
            any = true;
        }
    }

    if !any {
        println!("(no active entries)");
    }
}


/// General-purpose bitmask reader + renderer
fn process_bitmask(
    query_dir: &Path,
    src_dir: &Path,
    file_name: &str,
    desc_file: &str,
    reserved_bits: &[usize],
    heading: &str,
) {
    let mask = match read_hex_mask(&query_dir.join(file_name)) {
        Some(m) if m != 0 => m,
        _ => {
            println!("No {} found or file empty.", heading);
            return;
        }
    };

    println!("\n{}", heading);
    render_mask_bits(mask, &src_dir.join(desc_file), reserved_bits);
}


/*==================== Facilities ====================*/

/// CLI: `pvinfo --facilities`
///
/// Reads the `facilities` mask from `uv/query/facilities`
/// and uses the description file `facilities_value.txt` to print
/// active Ultravisor facilities.

pub fn handle_facilities(query_dir: &Path, src_dir: &Path) {
    process_bitmask(
        query_dir,
        src_dir,
        FACILITIES_FILE,
        FACILITIES_DESC_FILE,
        &[10],
        "Facilities: Installed Ultravisor Calls",
    );
}

/*==================== Show Everything ====================*/

/// CLI: `pvinfo` (no flags)
///
/// Runs all sections:
/// - Secure Execution Status
/// - Facilities
/// - Feature Indications

fn show_everything() {
    println!("Secure Execution Status: ");
    determine_se_mode(Path::new(UV_FOLDER));

    println!("\n Facilities: ");
    handle_facilities(
        &Path::new(UV_FOLDER).join("query"),
        Path::new(PVINFO_SRC),
    );

    println!("\nFeature Indications: ");
    handle_feature_indications(
    &Path::new(UV_FOLDER).join("query"),
    Path::new(PVINFO_SRC),
    );


}

/*==================== Feature indications ====================*/

/// CLI: `pvinfo --feature-indications`
///
/// Reads the `feature_indications` mask from `uv/query/feature_indications`
/// and uses the description file `feature_indications_value.txt` to print
/// Ultravisor features.  
/// Bits `[0, 2, 3]` are confidential/reserved and printed specially.

pub fn handle_feature_indications(query_dir: &Path, src_dir: &Path) {
    process_bitmask(
        query_dir,
        src_dir,
        FEATURE_BITS_FILE,
        FEATURE_TEXT_FILE,
        &[0, 2, 3],
        "Feature Indications: Ultravisor Features",
    );
}

