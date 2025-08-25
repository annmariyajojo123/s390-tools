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
use clap::{Parser, CommandFactory};
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

// Path for supported plaintext add secret flags
const SUPP_ADD_SECRET_PCF_FILE: &str = "supp_add_secret_pcf";

// Path for supported add secret request versions
const SUPP_ADD_SECRET_REQ_FILE: &str = "supp_add_secret_req_ver";

//Path for Supported Attestation Request Version
const SUPP_ATTEST_REQ_VER_FILE: &str = "supp_att_req_hdr_ver";

//Path for Supported plaintext control flag
const SUPP_SE_HDR_PCF_FILE: &str = "supp_se_hdr_pcf";
const SUPP_SE_HDR_PCF_DESC_FILE: &str = "supp_se_hdr_pcf_value.txt";




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

    /// Show Supported Plaintext Add Secret Flags
    #[arg(long)]
    supported_plaintext_add_secret_flags: bool,

    /// Show Supported Add Secret Request Versions
    #[arg(long)]
    supported_add_secret_request_versions: bool,

    /// Show Supported Attestation Request Versions
    #[arg(long)]
    supported_attestation_request_versions: bool,

    #[arg(long)]
    supported_plaintext_control_flags: bool,

}

fn main() {
    let raw_args: Vec<String> = std::env::args().collect();

    // Special case: if user typed only "--", show help
    if raw_args.len() == 2 && raw_args[1] == "--" {
        Cli::command().print_help().unwrap();
        std::process::exit(1);
    }

    let args = Cli::parse();

    verify_uv_folder();

    let mut any = false;

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

    if args.supported_plaintext_add_secret_flags {
    handle_supported_plaintext_add_secret_flags(
        &Path::new(UV_FOLDER).join("query"),
    );
    any = true;
    }

   if args.supported_add_secret_request_versions {
    show_supported_add_secret_req_versions(
        &Path::new(UV_FOLDER).join("query"),
    );
    any = true;
    }

    if args.supported_attestation_request_versions {
     handle_supported_attestation_request_versions(
        &Path::new(UV_FOLDER).join("query"),
    );
    any = true;
    }

    if args.supported_plaintext_control_flags {
     handle_supported_plaintext_control_flags(
        &Path::new(UV_FOLDER).join("query"),
        Path::new(PVINFO_SRC),
    );
    any = true;
    }

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

    // Always add a clean blank line before the heading
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
    println!("Secure Execution Status:");
    determine_se_mode(Path::new(UV_FOLDER));

    
    handle_facilities(
        &Path::new(UV_FOLDER).join("query"),
        Path::new(PVINFO_SRC),
    );

    handle_feature_indications(
        &Path::new(UV_FOLDER).join("query"),
        Path::new(PVINFO_SRC),
    );

    handle_supported_plaintext_add_secret_flags(
        &Path::new(UV_FOLDER).join("query"),
    );

    show_supported_add_secret_req_versions(
       &Path::new(UV_FOLDER).join("query"),
    );

    handle_supported_attestation_request_versions(
        &Path::new(UV_FOLDER).join("query"),
    );

    handle_supported_plaintext_control_flags(
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

/*==================== Supported Plaintext Add Secret Flags ====================*/

/// CLI: `pvinfo --supported-plaintext-add-secret-flags`
///
/// Reads the `supp_add_secret_pcf` mask from `uv/query/supp_add_secret_pcf`.
/// If bit 0 is active → prints "Disable dumping".
fn handle_supported_plaintext_add_secret_flags(query_dir: &Path) {
    let file_path = query_dir.join(SUPP_ADD_SECRET_PCF_FILE);
    let mask = match read_hex_mask(&file_path) {
        Some(m) => m,
        None => {
            println!("Supported Plaintext Add Secret Flags file not found.");
            return;
        }
    };

    println!("\nSupported Plaintext Add Secret Flags:");
    let mut any = false;

    if (mask & (1u64 << 0)) != 0 {
        println!("Disable dumping");
        any = true;
    }

    if !any {
        println!("no active flags");
    }
}


/*==================== Supported Add Secret Request Versions ====================*/

/// CLI: `pvinfo --supported-add-secret-request-versions`
///
/// Reads the `supp_add_secret_req_ver` file and prints supported versions.
/// Each active bit means:
/// - Bit 0 → version 0x100
/// - Bit 1 → version 0x200
/// - ...
/// - Bit 63 → version 0x4000
fn show_supported_add_secret_req_versions(query_dir: &Path) {
    let file_path = query_dir.join(SUPP_ADD_SECRET_REQ_FILE);
    let mask = match read_hex_mask(&file_path) {
        Some(m) => m,
        None => {
            println!("Supported Add Secret Request Versions file not found.");
            return;
        }
    };

    println!("\nSupported Add Secret Request Versions:");
    let versions = extract_supported_versions(mask);

    if versions.is_empty() {
        println!("no supported versions");
    } else {
        for v in versions {
            println!("{}", v);
        }
    }
}

/// Helper: Convert a hex bitmask into a list of supported versions.
fn extract_supported_versions(mask: u64) -> Vec<String> {
    let mut supported = Vec::new();

    for bit in 0..64 {
        if (mask & (1u64 << bit)) != 0 {
            let version = (bit + 1) * 0x100;
            supported.push(format!("version {:x} hex is supported", version));
        }
    }

    supported
}


/*==================== Supported Attestation Request Versions ====================*/
/// CLI: `pvinfo --supported-attestation-request-versions`
///
/// Reads the `supp_att_req_hdr_ver` mask from `uv/query/supp_att_req_hdr_ver`.
/// Each set bit indicates a supported version: (bit_index + 1) * 0x100 in hex.
fn handle_supported_attestation_request_versions(query_dir: &Path) {
    let file_path = query_dir.join(SUPP_ATTEST_REQ_VER_FILE);
    let mask = match read_hex_mask(&file_path) {
        Some(m) => m,
        None => {
            println!("Supported Attestation Request Versions file not found.");
            return;
        }
    };

    println!("\nSupported Attestation Request Versions:");
    let mut any = false;

    for bit in 0..64 {
        if (mask & (1u64 << bit)) != 0 {
            let version = (bit + 1) * 0x100;
            println!("Version {:x} hex is supported", version);
            any = true;
        }
    }

    if !any {
        println!("no supported versions");
    }
}

/*==================== Supported Plaintext Control Flags ====================*/
fn handle_supported_plaintext_control_flags(query_dir: &Path, src_dir: &Path) {
    process_bitmask(
        query_dir,
        src_dir,
        SUPP_SE_HDR_PCF_FILE,
        SUPP_SE_HDR_PCF_DESC_FILE,
        &[],  
        "Supported Plaintext Control Flags: ",
    );
}
