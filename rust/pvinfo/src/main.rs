//! pvinfo tool implementation

use clap::{Parser, CommandFactory};
use std::fs;
use std::path::Path;
use std::process;
use clap::Subcommand;

// Path to the UV directory 
// Path to the uv/query directory
const UV_QUERY_DIR: &str = "/home/annmariyajojo/Documents/s390_tools_learning/s390-tools/uv/query";

const UV_FOLDER: &str = "/home/annmariyajojo/Documents/s390_tools_learning/s390-tools/uv";
const PVINFO_SRC: &str = "/home/annmariyajojo/Documents/s390_tools_learning/s390-tools/rust/pvinfo/src";

/// Files in uv/query
const FACILITIES_FILE: &str = "facilities";
const FACILITIES_DESC_FILE: &str = "facilities_value.txt";

const FEATURE_BITS_FILE: &str = "feature_indications";                 
const FEATURE_TEXT_FILE: &str = "feature_indications_value.txt";       

const SUPP_ADD_SECRET_PCF_FILE: &str = "supp_add_secret_pcf";
const SUPP_ADD_SECRET_REQ_FILE: &str = "supp_add_secret_req_ver";
const SUPP_ATTEST_REQ_VER_FILE: &str = "supp_att_req_hdr_ver";

const SUPP_SE_HDR_PCF_FILE: &str = "supp_se_hdr_pcf";
const SUPP_SE_HDR_PCF_DESC_FILE: &str = "supp_se_hdr_pcf_value.txt";

const SUPP_SE_HDR_VER_FILE: &str = "supp_se_hdr_ver";

const SUPP_ATT_PFLAGS_FILE: &str = "supp_att_pflags";
const SUPP_ATT_PFLAGS_DESC_FILE: &str = "supp_att_pflags_value.txt";

const SUPP_SECRET_TYPES_FILE: &str = "supp_secret_types";
const SUPP_SECRET_TYPES_DESC_FILE: &str = "supp_secret_types_value.txt";

const MAX_ADDRESS_FILE: &str = "max_address";
const MAX_ASSOC_SECRETS_FILE: &str = "max_assoc_secrets";
const MAX_CPUS_FILE: &str = "max_cpus";
const MAX_GUESTS_FILE: &str = "max_guests";
const MAX_RETR_SECRETS_FILE: &str = "max_retr_secrets";
const MAX_SECRETS_FILE: &str = "max_secrets";


/// CLI
#[derive(Parser, Debug)]
#[command(author, version, about = "Protected Virtualization info")]
struct Cli {
    #[arg(long)] se_status: bool,
    #[arg(long)] facilities: bool,
    #[arg(long)] feature_indications: bool,
    #[arg(long)] supported_plaintext_add_secret_flags: bool,
    #[arg(long)] supported_add_secret_request_versions: bool,
    #[arg(long)] supported_attestation_request_versions: bool,
    #[arg(long)] supported_plaintext_control_flags: bool,
    #[arg(long)] supported_se_header_versions: bool,
    #[arg(long)] supported_plaintext_attestation_flags: bool,
    #[arg(long)] supported_secret_types: bool,
    #[arg(long)] limits: bool,

    #[command(subcommand)]
    command: Option<Commands>,   // NEW: handle "supported-flags"
}

#[derive(Subcommand, Debug)]
enum Commands {
    SupportedFlags {
        #[arg(long)]
        secret: bool,

         #[arg(long)]
        attestation: bool, 

        #[arg(long)]
        header: bool,
    },
}

fn main() {
    let raw_args: Vec<String> = std::env::args().collect();
    if raw_args.len() == 2 && raw_args[1] == "--" {
        Cli::command().print_help().unwrap();
        process::exit(1);
    }

    let args = Cli::parse();
    verify_uv_folder();
    let mut any = false;

    match &args.command {
    Some(Commands::SupportedFlags { secret, attestation, header }) => {
        if *secret {
            handle_supported_secret_flags_group();
        }
        if *attestation {
            handle_supported_attestation_flags_group();
        }
        if *header {
            handle_supported_header_flags_group();
        }

        // If no flags were provided, print *all three groups*
        if !*secret && !*attestation && !*header {
            handle_supported_secret_flags_group();
            handle_supported_attestation_flags_group();
            handle_supported_header_flags_group();
        }

        return; // skip normal flow
    }
        None => {
            if args.se_status {
                determine_se_mode(Path::new(UV_FOLDER));
                any = true;
            }

            if args.facilities {
                handle_facilities();
                any = true;
            }

            if args.feature_indications {
                handle_feature_indications();
                any = true;
            }

            if args.supported_plaintext_add_secret_flags {
                handle_supported_plaintext_add_secret_flags();
                any = true;
            }

            if args.supported_add_secret_request_versions {
                handle_supported_add_secret_req_versions();
                any = true;
            }

            if args.supported_attestation_request_versions {
                handle_supported_attestation_request_versions();
                any = true;
            }

            if args.supported_plaintext_control_flags {
                handle_supported_plaintext_control_flags();
                any = true;
            }

            if args.supported_se_header_versions {
                handle_supported_se_header_versions();
                any = true;
            }

            if args.supported_plaintext_attestation_flags {
                handle_supported_plaintext_attestation_flags();
                any = true;
            }

            if args.supported_secret_types {
                handle_supported_secret_types();
                any = true;
            }

            if args.limits {
                handle_limits();
                any = true;
            }

            if !any {
                show_everything();
            }
        } // <-- this closes the `None => { ... }` block
    } // <-- this closes the `match`
}

/* ========== Shared Helpers ========== */

fn verify_uv_folder() {
    if !Path::new(UV_FOLDER).exists() {
        println!("UV directory not found at {UV_FOLDER}");
        println!("Does not operate as a SE host or SE guest.");
        process::exit(0);
    }
}

fn read_flag_file(path: &Path) -> bool {
    if let Ok(content) = fs::read_to_string(path) {
        return content.trim() == "1";
    }
    false
}

fn read_hex_mask(path: &Path) -> Option<u64> {
    let content = fs::read_to_string(path).ok()?;
    let first_line = content.lines().find(|l| !l.trim().is_empty())?.trim();
    let hex_str = first_line.trim_start_matches("0x");
    u64::from_str_radix(hex_str, 16).ok()
}

/// Reads a decimal integer from a file and returns it as u64.
fn read_integer(path: &Path) -> Option<u64> {
    let content = fs::read_to_string(path).ok()?;
    let first_line = content.lines().find(|l| !l.trim().is_empty())?.trim();
    first_line.parse::<u64>().ok()
}


/// For masks that have description files
fn print_bitmask_with_desc(mask: u64, desc_file: &Path, reserved_bits: &[usize], heading: &str) {
    println!("{}", heading);
    let content = fs::read_to_string(desc_file).unwrap_or_default();
    let lines: Vec<&str> = content.lines().collect();
    let mut any = false;

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

    // Bits not covered in description file
    for extra_line in lines.len()..64 {
        let bit_position = 63 - extra_line;
        if (mask & (1u64 << bit_position)) != 0 {
            println!("Bit-{} is active", extra_line);
            any = true;
        }
    }

    if !any {
        println!("no active entries");
    }
}

/// For masks that represent supported versions
fn print_version_mask(mask: u64, heading: &str) {
    println!("{}", heading);
    let mut any = false;

    for bit in 0..64 {
        let actual_bit = 63 - bit; // MSB-first
        if (mask & (1u64 << actual_bit)) != 0 {
            let version = (bit + 1) * 0x100;
            println!("version {:x} hex is supported", version);
            any = true;
        }
    }

    if !any {
        println!("no supported versions");
    }
}

/* ========== SE status ========== */
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

/* ========== Handlers ========== */
fn handle_facilities() {
    if let Some(mask) = read_hex_mask(&Path::new(UV_QUERY_DIR).join(FACILITIES_FILE)) {
        print_bitmask_with_desc(
            mask, 
            &Path::new(PVINFO_SRC).join(FACILITIES_DESC_FILE), 
            &[10], 
            "Facilities: Installed Ultravisor Calls");
    }
}

fn handle_feature_indications() {
    if let Some(mask) = read_hex_mask(&Path::new(UV_QUERY_DIR).join(FEATURE_BITS_FILE)) {
        print_bitmask_with_desc(
            mask, 
            &Path::new(PVINFO_SRC).join(FEATURE_TEXT_FILE), 
            &[0, 2, 3], 
            "Feature Indications: Ultravisor Features");
    }
}

fn handle_supported_plaintext_add_secret_flags() {
    if let Some(mask) = read_hex_mask(&Path::new(UV_QUERY_DIR).join(SUPP_ADD_SECRET_PCF_FILE)) {
        println!("Supported Plaintext Add Secret Flags:");
        if (mask & (1u64 << 0)) != 0 {
            println!("Disable dumping");
        } else {
            println!("no active flags");
        }
    }
}

fn handle_supported_add_secret_req_versions() {
    if let Some(mask) = read_hex_mask(&Path::new(UV_QUERY_DIR).join(SUPP_ADD_SECRET_REQ_FILE)) {
        print_version_mask(
            mask, 
            "Supported Add Secret Request Versions:");
    }
}

fn handle_supported_attestation_request_versions() {
    if let Some(mask) = read_hex_mask(&Path::new(UV_QUERY_DIR).join(SUPP_ATTEST_REQ_VER_FILE)) {
        print_version_mask(
            mask, 
            "Supported Attestation Request Versions:");
    }
}

fn handle_supported_plaintext_control_flags() {
    if let Some(mask) = read_hex_mask(&Path::new(UV_QUERY_DIR).join(SUPP_SE_HDR_PCF_FILE)) {
        print_bitmask_with_desc(
            mask, 
            &Path::new(PVINFO_SRC).join(SUPP_SE_HDR_PCF_DESC_FILE), 
            &[], 
            "Supported Plaintext Control Flags:");
    }
}

fn handle_supported_se_header_versions() {
    if let Some(mask) = read_hex_mask(&Path::new(UV_QUERY_DIR).join(SUPP_SE_HDR_VER_FILE)) {
        print_version_mask(
            mask, 
            "Supported SE Header Versions:");
    }
}

fn handle_supported_plaintext_attestation_flags() {
    if let Some(mask) = read_hex_mask(&Path::new(UV_QUERY_DIR).join(SUPP_ATT_PFLAGS_FILE)) {
        print_bitmask_with_desc(
            mask, 
            &Path::new(PVINFO_SRC).join(SUPP_ATT_PFLAGS_DESC_FILE), 
            &[], 
            "Supported Plaintext Attestation Flags:");
    }
}

fn handle_supported_secret_types() {
    if let Some(mask) = read_hex_mask(&Path::new(UV_QUERY_DIR).join(SUPP_SECRET_TYPES_FILE)) {
        print_bitmask_with_desc(
            mask,
            &Path::new(PVINFO_SRC).join(SUPP_SECRET_TYPES_DESC_FILE),
            &[],
            "Supported Secret Types:",
        );
    }
}

/* ========== Limits Handling ========== */

fn handle_limits() {
    println!("Limits:");

    let limits = [
        (MAX_ADDRESS_FILE, "Maximal Address for a SE-Guest"),
        (MAX_ASSOC_SECRETS_FILE, "Maximal number of associated secrets"),
        (MAX_CPUS_FILE, "Maximal number of CPUs in one SE-Guest"),
        (MAX_GUESTS_FILE, "Maximal number of SE-Guests"),
        (MAX_RETR_SECRETS_FILE, "Maximal number of retrievable secrets"),
        (MAX_SECRETS_FILE, "Maximal number of secrets in the system"),
    ];

    for (file, desc) in limits {
        let path = Path::new(UV_QUERY_DIR).join(file);
        if let Some(val) = read_integer(&path) {
            println!("{} {}", desc, val);
        }
    }
}

/// Grouping for subcommands

fn handle_supported_secret_flags_group() {
    handle_supported_secret_types();
    handle_supported_add_secret_req_versions();
    handle_supported_plaintext_add_secret_flags();
}

fn handle_supported_attestation_flags_group() {
    handle_supported_plaintext_attestation_flags();
    handle_supported_attestation_request_versions();
}

fn handle_supported_header_flags_group() {
    handle_supported_se_header_versions();
    handle_supported_plaintext_control_flags();
}



/* ========== Show Everything ========== */
fn show_everything() {
    println!("Secure Execution Status:");
    determine_se_mode(Path::new(UV_FOLDER));

    handle_facilities();
    handle_feature_indications();
    handle_supported_plaintext_add_secret_flags();
    handle_supported_add_secret_req_versions();
    handle_supported_attestation_request_versions();
    handle_supported_plaintext_control_flags();
    handle_supported_se_header_versions();
    handle_supported_plaintext_attestation_flags();
    handle_supported_secret_types();
    handle_limits();

}
