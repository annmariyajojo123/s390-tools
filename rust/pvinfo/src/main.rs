//! pvinfo tool implementation

//command-line argument parsing library
use clap::{CommandFactory, Parser, Subcommand};

// YAML serialization
use serde::Serialize;

//allows file reading
use std::fs;

//path handling
use std::path::Path;

//exit program with exit(0) or error codes
use std::process;

/*──────────────
Base Directories
───────────────*/
//Constants point to where data files are stored in the project
const UV_QUERY_DIR: &str = "/home/annmariyajojo/Documents/s390_tools_learning/s390-tools/uv/query";

const UV_FOLDER: &str = "/home/annmariyajojo/Documents/s390_tools_learning/s390-tools/uv";
const PVINFO_SRC: &str =
    "/home/annmariyajojo/Documents/s390_tools_learning/s390-tools/rust/pvinfo/src";

// Files in uv/query
// Each constant is the filename for a specific ultravisor query or description
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

/*──────────────
YAML structures
──────────────*/
// PvInfo holds all collected data

#[derive(Serialize, Default)]
struct PvInfo {
    se_status: Vec<String>,
    facilities: Vec<String>,
    feature_indications: Vec<String>,
    supported_plaintext_add_secret_flags: Vec<String>,
    supported_add_secret_request_versions: Vec<String>,
    supported_attestation_request_versions: Vec<String>,
    supported_plaintext_control_flags: Vec<String>,
    supported_se_header_versions: Vec<String>,
    supported_plaintext_attestation_flags: Vec<String>,
    supported_secret_types: Vec<String>,
    limits: Limits,
}

//Struct groups system limits into a YAML map.

#[derive(Serialize, Default)]
struct Limits {
    maximal_address: u64,
    maximal_number_of_associated_secrets: u64,
    maximal_number_of_cpus: u64,
    maximal_number_of_se_guests: u64,
    maximal_number_of_retrievable_secrets: u64,
    maximal_number_of_secrets: u64,
}

/*─────
CLI
──────*/
// Defines CLI arguments

#[derive(Parser, Debug)]
#[command(author, version, about = "Protected Virtualization info")]
struct Cli {
    #[arg(long)]
    se_status: bool,
    #[arg(long)]
    facilities: bool,
    #[arg(long)]
    feature_indications: bool,
    #[arg(long)]
    supported_plaintext_add_secret_flags: bool,
    #[arg(long)]
    supported_add_secret_request_versions: bool,
    #[arg(long)]
    supported_attestation_request_versions: bool,
    #[arg(long)]
    supported_plaintext_control_flags: bool,
    #[arg(long)]
    supported_se_header_versions: bool,
    #[arg(long)]
    supported_plaintext_attestation_flags: bool,
    #[arg(long)]
    supported_secret_types: bool,
    #[arg(long)]
    limits: bool,

    #[arg(long, default_value = "text")]
    format: String, // "text" or "yaml"

    #[command(subcommand)]
    command: Option<Commands>,
}

// Subcommands

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

/*────────────
Main
────────────*/
fn main() {
    // Special case: if user runs pvinfo --, just show help
    let raw_args: Vec<String> = std::env::args().collect();
    if raw_args.len() == 2 && raw_args[1] == "--" {
        Cli::command().print_help().unwrap();
        process::exit(1);
    }

    //Parse CLI args into args
    let args = Cli::parse();

    // Verify UV folder exists or not
    verify_uv_folder();
    let mut any = false;

    // Handling Subcommands
    match &args.command {
        Some(Commands::SupportedFlags {
            secret,
            attestation,
            header,
        }) => {
            if *secret {
                print_list("Supported Secret Types:", collect_secret_types());
                print_list(
                    "Supported Add Secret Request Versions:",
                    collect_add_secret_req_versions(),
                );
                print_list(
                    "Supported Plaintext Add Secret Flags:",
                    collect_add_secret_flags(),
                );
            }
            if *attestation {
                print_list(
                    "Supported Plaintext Attestation Flags:",
                    collect_attestation_flags(),
                );
                print_list(
                    "Supported Attestation Request Versions:",
                    collect_attestation_req_versions(),
                );
            }
            if *header {
                print_list(
                    "Supported SE Header Versions:",
                    collect_se_header_versions(),
                );
                print_list(
                    "Supported Plaintext Control Flags:",
                    collect_plaintext_control_flags(),
                );
            }
            if !*secret && !*attestation && !*header {
                // all three
                print_list("Supported Secret Types:", collect_secret_types());
                print_list(
                    "Supported Add Secret Request Versions:",
                    collect_add_secret_req_versions(),
                );
                print_list(
                    "Supported Plaintext Add Secret Flags:",
                    collect_add_secret_flags(),
                );
                print_list(
                    "Supported Plaintext Attestation Flags:",
                    collect_attestation_flags(),
                );
                print_list(
                    "Supported Attestation Request Versions:",
                    collect_attestation_req_versions(),
                );
                print_list(
                    "Supported SE Header Versions:",
                    collect_se_header_versions(),
                );
                print_list(
                    "Supported Plaintext Control Flags:",
                    collect_plaintext_control_flags(),
                );
            }
            return;
        }

        // If --format=yaml then collect everything and print in YAML
        None => {
            if args.format == "yaml" {
                let info = collect_all();
                println!("{}", serde_yaml::to_string(&info).unwrap());
                return;
            }

            if args.se_status {
                print_list("se_status:", vec![collect_se_status()]);
                any = true;
            }
            if args.facilities {
                print_list(
                    "Facilities: Installed Ultravisor Calls",
                    collect_facilities(),
                );
                any = true;
            }
            if args.feature_indications {
                print_list(
                    "Feature Indications: Ultravisor Features",
                    collect_feature_indications(),
                );
                any = true;
            }
            if args.supported_plaintext_add_secret_flags {
                print_list(
                    "Supported Plaintext Add Secret Flags:",
                    collect_add_secret_flags(),
                );
                any = true;
            }
            if args.supported_add_secret_request_versions {
                print_list(
                    "Supported Add Secret Request Versions:",
                    collect_add_secret_req_versions(),
                );
                any = true;
            }
            if args.supported_attestation_request_versions {
                print_list(
                    "Supported Attestation Request Versions:",
                    collect_attestation_req_versions(),
                );
                any = true;
            }
            if args.supported_plaintext_control_flags {
                print_list(
                    "Supported Plaintext Control Flags:",
                    collect_plaintext_control_flags(),
                );
                any = true;
            }
            if args.supported_se_header_versions {
                print_list(
                    "Supported SE Header Versions:",
                    collect_se_header_versions(),
                );
                any = true;
            }
            if args.supported_plaintext_attestation_flags {
                print_list(
                    "Supported Plaintext Attestation Flags:",
                    collect_attestation_flags(),
                );
                any = true;
            }
            if args.supported_secret_types {
                print_list("Supported Secret Types:", collect_secret_types());
                any = true;
            }
            if args.limits {
                print_limits(collect_limits());
                any = true;
            }

            // If no flag given print everything in text mode
            if !any {
                // default show all in text mode
                print_list("se_status:", vec![collect_se_status()]);
                print_list(
                    "\nFacilities: Installed Ultravisor Calls",
                    collect_facilities(),
                );
                print_list(
                    "\nFeature Indications: Ultravisor Features",
                    collect_feature_indications(),
                );
                print_list(
                    "\nSupported Plaintext Add Secret Flags:",
                    collect_add_secret_flags(),
                );
                print_list(
                    "\nSupported Add Secret Request Versions:",
                    collect_add_secret_req_versions(),
                );
                print_list(
                    "\nSupported Attestation Request Versions:",
                    collect_attestation_req_versions(),
                );
                print_list(
                    "\nSupported Plaintext Control Flags:",
                    collect_plaintext_control_flags(),
                );
                print_list(
                    "\nSupported SE Header Versions:",
                    collect_se_header_versions(),
                );
                print_list(
                    "\nSupported Plaintext Attestation Flags:",
                    collect_attestation_flags(),
                );
                print_list("\nSupported Secret Types:", collect_secret_types());
                println!();
                print_limits(collect_limits());
            }
        }
    }
}

/*──────────────
Collectors
──────────────*/

//Reads prot_virt_guest and prot_virt_host

fn collect_se_status() -> String {
    let guest_flag = read_flag_file(&Path::new(UV_FOLDER).join("prot_virt_guest"));
    let host_flag = read_flag_file(&Path::new(UV_FOLDER).join("prot_virt_host"));
    match (guest_flag, host_flag) {
        (true, false) => "Secure Execution Guest Mode".to_string(),
        (false, true) => "Secure Execution Host Mode".to_string(),
        (false, false) => "Secure Execution is disabled".to_string(),
        (true, true) => "Configuration error: both Guest and Host enabled".to_string(),
    }
}

fn collect_facilities() -> Vec<String> {
    read_hex_mask(&Path::new(UV_QUERY_DIR).join(FACILITIES_FILE))
        .map(|m| {
            collect_bitmask_with_desc(m, &Path::new(PVINFO_SRC).join(FACILITIES_DESC_FILE), &[10])
        })
        .unwrap_or_else(|| vec!["no active entries".into()])
}

fn collect_feature_indications() -> Vec<String> {
    read_hex_mask(&Path::new(UV_QUERY_DIR).join(FEATURE_BITS_FILE))
        .map(|m| {
            collect_bitmask_with_desc(
                m,
                &Path::new(PVINFO_SRC).join(FEATURE_TEXT_FILE),
                &[0, 2, 3],
            )
        })
        .unwrap_or_else(|| vec!["no active entries".into()])
}

fn collect_add_secret_flags() -> Vec<String> {
    if let Some(mask) = read_hex_mask(&Path::new(UV_QUERY_DIR).join(SUPP_ADD_SECRET_PCF_FILE)) {
        let mut out = Vec::new();
        if (mask & (1u64 << 0)) != 0 {
            out.push("Disable dumping".to_string());
        }
        if out.is_empty() {
            out.push("no active flags".to_string());
        }
        out
    } else {
        vec!["no active flags".into()]
    }
}

fn collect_add_secret_req_versions() -> Vec<String> {
    read_hex_mask(&Path::new(UV_QUERY_DIR).join(SUPP_ADD_SECRET_REQ_FILE))
        .map(collect_version_mask)
        .unwrap_or_else(|| vec!["no supported versions".into()])
}

fn collect_attestation_req_versions() -> Vec<String> {
    read_hex_mask(&Path::new(UV_QUERY_DIR).join(SUPP_ATTEST_REQ_VER_FILE))
        .map(collect_version_mask)
        .unwrap_or_else(|| vec!["no supported versions".into()])
}

fn collect_plaintext_control_flags() -> Vec<String> {
    read_hex_mask(&Path::new(UV_QUERY_DIR).join(SUPP_SE_HDR_PCF_FILE))
        .map(|m| {
            collect_bitmask_with_desc(
                m,
                &Path::new(PVINFO_SRC).join(SUPP_SE_HDR_PCF_DESC_FILE),
                &[],
            )
        })
        .unwrap_or_else(|| vec!["no active entries".into()])
}

fn collect_se_header_versions() -> Vec<String> {
    read_hex_mask(&Path::new(UV_QUERY_DIR).join(SUPP_SE_HDR_VER_FILE))
        .map(collect_version_mask)
        .unwrap_or_else(|| vec!["no supported versions".into()])
}

fn collect_attestation_flags() -> Vec<String> {
    read_hex_mask(&Path::new(UV_QUERY_DIR).join(SUPP_ATT_PFLAGS_FILE))
        .map(|m| {
            collect_bitmask_with_desc(
                m,
                &Path::new(PVINFO_SRC).join(SUPP_ATT_PFLAGS_DESC_FILE),
                &[],
            )
        })
        .unwrap_or_else(|| vec!["no active entries".into()])
}

fn collect_secret_types() -> Vec<String> {
    read_hex_mask(&Path::new(UV_QUERY_DIR).join(SUPP_SECRET_TYPES_FILE))
        .map(|m| {
            collect_bitmask_with_desc(
                m,
                &Path::new(PVINFO_SRC).join(SUPP_SECRET_TYPES_DESC_FILE),
                &[],
            )
        })
        .unwrap_or_else(|| vec!["no active entries".into()])
}

fn collect_limits() -> Limits {
    Limits {
        maximal_address: read_integer(&Path::new(UV_QUERY_DIR).join(MAX_ADDRESS_FILE)).unwrap_or(0),
        maximal_number_of_associated_secrets: read_integer(
            &Path::new(UV_QUERY_DIR).join(MAX_ASSOC_SECRETS_FILE),
        )
        .unwrap_or(0),
        maximal_number_of_cpus: read_integer(&Path::new(UV_QUERY_DIR).join(MAX_CPUS_FILE))
            .unwrap_or(0),
        maximal_number_of_se_guests: read_integer(&Path::new(UV_QUERY_DIR).join(MAX_GUESTS_FILE))
            .unwrap_or(0),
        maximal_number_of_retrievable_secrets: read_integer(
            &Path::new(UV_QUERY_DIR).join(MAX_RETR_SECRETS_FILE),
        )
        .unwrap_or(0),
        maximal_number_of_secrets: read_integer(&Path::new(UV_QUERY_DIR).join(MAX_SECRETS_FILE))
            .unwrap_or(0),
    }
}

fn collect_all() -> PvInfo {
    PvInfo {
        se_status: vec![collect_se_status()],
        facilities: collect_facilities(),
        feature_indications: collect_feature_indications(),
        supported_plaintext_add_secret_flags: collect_add_secret_flags(),
        supported_add_secret_request_versions: collect_add_secret_req_versions(),
        supported_attestation_request_versions: collect_attestation_req_versions(),
        supported_plaintext_control_flags: collect_plaintext_control_flags(),
        supported_se_header_versions: collect_se_header_versions(),
        supported_plaintext_attestation_flags: collect_attestation_flags(),
        supported_secret_types: collect_secret_types(),
        limits: collect_limits(),
    }
}

/*──────────────
Shared helpers
──────────────*/
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

fn read_integer(path: &Path) -> Option<u64> {
    let content = fs::read_to_string(path).ok()?;
    let first_line = content.lines().find(|l| !l.trim().is_empty())?.trim();
    first_line.parse::<u64>().ok()
}

fn collect_bitmask_with_desc(mask: u64, desc_file: &Path, reserved_bits: &[usize]) -> Vec<String> {
    let mut out = Vec::new();
    let content = fs::read_to_string(desc_file).unwrap_or_default();
    let lines: Vec<&str> = content.lines().collect();

    for (line_index, line) in lines.iter().enumerate() {
        let bit_position = 63 - line_index;

        if (mask & (1u64 << bit_position)) != 0 {
            if reserved_bits.contains(&line_index) {
                out.push(format!(
                    "Confidential - report as reserved Bit-{}",
                    line_index
                ));
            } else if line.trim() == "Reserved" {
                out.push(format!("Reserved Bit-{}", line_index));
            } else {
                out.push(line.to_string());
            }
        }
    }

    if out.is_empty() {
        out.push("no active entries".to_string());
    }
    out
}

fn collect_version_mask(mask: u64) -> Vec<String> {
    let mut out = Vec::new();
    for bit in 0..64 {
        let actual_bit = 63 - bit;
        if (mask & (1u64 << actual_bit)) != 0 {
            let version = (bit + 1) * 0x100;
            out.push(format!("version {:x} hex is supported", version));
        }
    }
    if out.is_empty() {
        out.push("no supported versions".to_string());
    }
    out
}

/*──────────────
Printers for text mode
──────────────*/
fn print_list(title: &str, items: Vec<String>) {
    println!("{}", title);
    for i in items {
        println!("{}", i);
    }
}

fn print_limits(lim: Limits) {
    println!("Limits:");
    println!("Maximal Address for a SE-Guest {}", lim.maximal_address);
    println!(
        "Maximal number of associated secrets {}",
        lim.maximal_number_of_associated_secrets
    );
    println!(
        "Maximal number of CPUs in one SE-Guest {}",
        lim.maximal_number_of_cpus
    );
    println!(
        "Maximal number of SE-Guests {}",
        lim.maximal_number_of_se_guests
    );
    println!(
        "Maximal number of retrievable secrets {}",
        lim.maximal_number_of_retrievable_secrets
    );
    println!(
        "Maximal number of secrets in the system {}",
        lim.maximal_number_of_secrets
    );
}
