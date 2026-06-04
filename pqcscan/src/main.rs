use anyhow::{anyhow, Result};
use chrono::prelude::*;
use clap::{crate_version, Arg, ArgAction, ArgMatches, Command};
use env_logger::Env;
use rust_embed::RustEmbed;
use serde::Serialize;
use std::collections::{BTreeSet, HashMap};
use std::convert::From;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;
use std::sync::Arc;
use tera::{Context, Tera};
use tokio::runtime::Runtime;

mod config;
mod scan;
mod ssh;
mod tls;
mod tlsconstants;
mod utils;

use crate::config::Config;
use crate::scan::{scan_runner, Scan, ScanOptions, ScanResult, ScanType};
use crate::utils::{parse_single_target, Target};

#[derive(RustEmbed)]
#[folder = "$CARGO_MANIFEST_DIR/support/templates/"]
struct EmbeddedResources;

const DEFAULT_NUM_THREADS: usize = 8;

fn output_args(file_type: &str, req: bool) -> Vec<clap::Arg> {
    vec![Arg::new("output")
        .short('o')
        .value_name("FILE")
        .long("output")
        .help(format!("{} file to write results to", file_type))
        .required(req)
        .action(ArgAction::Set)]
}

fn num_threads_arg() -> clap::Arg {
    Arg::new("num-threads")
        .long("num-threads")
        .default_value(format!("{}", DEFAULT_NUM_THREADS))
        .value_parser(clap::value_parser!(usize))
        .help("Number of scan threads to use")
}

fn target_args() -> Vec<clap::Arg> {
    vec![
        Arg::new("target")
            .short('t')
            .long("target")
            .value_name("HOST:PORT")
            .help("HOST:PORT")
            .conflicts_with("target-list")
            .action(ArgAction::Set),
        Arg::new("target-list")
            .short('T')
            .value_name("FILE")
            .long("target-list")
            .help("File listing HOST:PORT entries")
            .conflicts_with("target")
            .action(ArgAction::Set)
            .value_parser(clap::value_parser!(PathBuf)),
    ]
}

fn get_targets(matches: &ArgMatches, default_port: Option<u16>) -> Result<Vec<Target>> {
    match matches.get_one::<String>("target") {
        Some(t) => Ok(vec![parse_single_target(t, default_port)?]),
        None => {
            let f = matches.get_one::<PathBuf>("target-list");
            if f.is_none() {
                return Err(anyhow!("specify -t or -T"));
            }
            let file = File::open(f.unwrap())?;
            let reader = BufReader::new(file);
            let mut line_no = 0;
            let mut targets: Vec<Target> = Vec::new();

            for line in reader.lines() {
                let line = line?;

                line_no += 1;

                if line.is_empty() || line.starts_with('#') {
                    continue;
                }

                match parse_single_target(&line, default_port) {
                    Ok(t) => targets.push(t),
                    Err(e) => {
                        return Err(anyhow!("Parsing line {line_no} ({line}) failed. {e}"));
                    }
                }
            }
            Ok(targets)
        }
    }
}

#[derive(Serialize)]
struct ReportResults {
    tls_results: HashMap<String, Vec<ScanResult>>,
    tls_sorted_hosts: BTreeSet<String>,
    tls_success_count: usize,
    tls_fail_count: usize,
    tls_pqc_supported_count: usize,
    tls_total_count: usize,
    ssh_results: HashMap<String, Vec<ScanResult>>,
    ssh_sorted_hosts: BTreeSet<String>,
    ssh_success_count: usize,
    ssh_fail_count: usize,
    ssh_pqc_supported_count: usize,
    ssh_total_count: usize,
    scan_windows: Vec<ScanWindow>,
}

#[derive(Serialize)]
struct ScanWindow {
    start_time: DateTime<Utc>,
    end_time: DateTime<Utc>,
    scan_type: ScanType,
}

#[derive(Clone, Copy)]
enum ReportFormat {
    Html,
    Csv,
    Json,
    Xml,
}

impl From<&str> for ReportFormat {
    fn from(value: &str) -> Self {
        match value {
            "csv" => ReportFormat::Csv,
            "json" => ReportFormat::Json,
            "xml" => ReportFormat::Xml,
            _ => ReportFormat::Html,
        }
    }
}

fn create_report(
    output_file: &str,
    input_files: &Vec<&String>,
    report_format: ReportFormat,
) -> Result<()> {
    log::debug!("Initializing report data structures");
    let mut tls_map: HashMap<String, Vec<ScanResult>> = HashMap::new();
    let mut ssh_map: HashMap<String, Vec<ScanResult>> = HashMap::new();
    let mut tls_hosts: BTreeSet<String> = BTreeSet::new();
    let mut ssh_hosts: BTreeSet<String> = BTreeSet::new();
    let mut ssh_pqc_supported_count: usize = 0;
    let mut tls_pqc_supported_count: usize = 0;
    let mut ssh_success_count: usize = 0;
    let mut tls_success_count: usize = 0;
    let mut ssh_total_count: usize = 0;
    let mut tls_total_count: usize = 0;
    let mut scan_windows = Vec::new();

    for input_file in input_files {
        log::debug!("Opening and parsing {}", input_file);

        let file = File::open(input_file)?;
        let scan: Scan = serde_json::from_reader(file).expect("failed to open input file");

        if scan.version != crate_version!() {
            let err = format!(
                "Version mismatch: {} != {} in {}",
                scan.version,
                crate_version!(),
                input_file
            );
            log::warn!("{}", err);
            return Err(anyhow!(err));
        }

        let window = ScanWindow {
            start_time: scan.start_time,
            end_time: scan.end_time,
            scan_type: scan.scan_type,
        };
        scan_windows.push(window);

        for result in scan.results {
            match result {
                ScanResult::Ssh {
                    ref targetspec,
                    ref error,
                    pqc_supported,
                    ..
                } => {
                    ssh_hosts.insert(targetspec.host.clone());
                    let host = targetspec.host.clone();
                    if ssh_map.get(&host).is_none() {
                        ssh_map.insert(host.clone(), Vec::new());
                    }
                    let m = ssh_map.get_mut(&host).unwrap();
                    if error.is_none() {
                        ssh_success_count += 1;
                    }
                    if pqc_supported {
                        ssh_pqc_supported_count += 1;
                    }
                    ssh_total_count += 1;
                    m.push(result);
                }
                ScanResult::Tls {
                    ref targetspec,
                    ref error,
                    pqc_supported,
                    ..
                } => {
                    tls_hosts.insert(targetspec.host.clone());
                    let host = targetspec.host.clone();
                    if tls_map.get(&host).is_none() {
                        tls_map.insert(host.clone(), Vec::new());
                    }
                    let m = tls_map.get_mut(&host).unwrap();
                    if error.is_none() {
                        tls_success_count += 1;
                    }
                    if pqc_supported {
                        tls_pqc_supported_count += 1;
                    }
                    tls_total_count += 1;
                    m.push(result);
                }
                _ => {
                    panic!("Unexpected result type");
                }
            }
        }
    }

    log::debug!(
        "{} TLS results, {} SSH results",
        tls_map.len(),
        ssh_map.len()
    );

    let tls_fail_count = tls_total_count - tls_success_count;
    let ssh_fail_count = ssh_total_count - ssh_success_count;

    log::debug!(
        "TLS: {} successful, {} failed, {} PQC-enabled",
        tls_success_count,
        tls_fail_count,
        tls_pqc_supported_count
    );
    log::debug!(
        "SSH: {} successful, {} failed, {} PQC-enabled",
        ssh_success_count,
        ssh_fail_count,
        ssh_pqc_supported_count
    );

    let results: ReportResults = ReportResults {
        tls_results: tls_map,
        tls_sorted_hosts: tls_hosts,
        tls_success_count: tls_success_count,
        tls_pqc_supported_count: tls_pqc_supported_count,
        tls_fail_count: tls_fail_count,
        tls_total_count: tls_total_count,
        ssh_results: ssh_map,
        ssh_sorted_hosts: ssh_hosts,
        ssh_success_count: ssh_success_count,
        ssh_fail_count: ssh_fail_count,
        ssh_pqc_supported_count: ssh_pqc_supported_count,
        ssh_total_count: ssh_total_count,
        scan_windows: scan_windows,
    };

    match report_format {
        ReportFormat::Html => render_html_report(output_file, &results),
        ReportFormat::Csv => write_csv_report(output_file, &results),
        ReportFormat::Json => write_json_report(output_file, &results),
        ReportFormat::Xml => write_xml_report(output_file, &results),
    }
}

fn render_html_report(output_file: &str, results: &ReportResults) -> Result<()> {
    let templates = [
        "macros.html",
        "template.html",
        "ssh_results.html",
        "tls_results.html",
        "summary.html",
    ];
    let mut tera = Tera::default();

    log::debug!("Loading HTML templates");
    for template in templates {
        let html_file = EmbeddedResources::get(template).unwrap();
        let html_data = std::str::from_utf8(html_file.data.as_ref())?;
        tera.add_raw_template(template, html_data)?;
    }

    let mut ctx = Context::from_serialize(results)?;

    let dt = Utc::now().format("%Y-%m-%d %H:%M:%S %Z").to_string();
    ctx.insert("title", &dt);

    log::trace!("Tera Template: {:?}", ctx);

    log::debug!("Rendering HTML report to {}", output_file);
    let f = File::create(output_file)?;
    tera.render_to("template.html", &ctx, f)?;
    log::info!("HTML report written to {}", output_file);

    Ok(())
}

fn write_csv_report(output_file: &str, results: &ReportResults) -> Result<()> {
    log::debug!("Writing CSV report to {}", output_file);
    let f = File::create(output_file)?;
    let mut writer = BufWriter::new(f);
    write_csv_report_to_writer(&mut writer, results)?;
    writer.flush()?;
    log::info!("CSV report written to {}", output_file);
    Ok(())
}

fn write_json_report(output_file: &str, results: &ReportResults) -> Result<()> {
    log::debug!("Writing JSON report to {}", output_file);
    let f = File::create(output_file)?;
    let mut writer = BufWriter::new(f);
    serde_json::to_writer_pretty(&mut writer, results)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    log::info!("JSON report written to {}", output_file);
    Ok(())
}

fn write_xml_report(output_file: &str, results: &ReportResults) -> Result<()> {
    log::debug!("Writing XML report to {}", output_file);
    let f = File::create(output_file)?;
    let mut writer = BufWriter::new(f);
    write_xml_report_to_writer(&mut writer, results)?;
    writer.flush()?;
    log::info!("XML report written to {}", output_file);
    Ok(())
}

fn write_xml_report_to_writer<W: Write>(writer: &mut W, results: &ReportResults) -> Result<()> {
    writer.write_all(br#"<?xml version="1.0" encoding="UTF-8"?>"#)?;
    writer.write_all(b"\n<pqcscan_report>\n")?;
    writeln!(writer, "  <summary>")?;
    writeln!(
        writer,
        "    <ssh total=\"{}\" success=\"{}\" failed=\"{}\" pqc_supported=\"{}\" />",
        results.ssh_total_count,
        results.ssh_success_count,
        results.ssh_fail_count,
        results.ssh_pqc_supported_count
    )?;
    writeln!(
        writer,
        "    <tls total=\"{}\" success=\"{}\" failed=\"{}\" pqc_supported=\"{}\" />",
        results.tls_total_count,
        results.tls_success_count,
        results.tls_fail_count,
        results.tls_pqc_supported_count
    )?;
    writeln!(writer, "  </summary>")?;
    writeln!(writer, "  <scan_windows>")?;
    for window in &results.scan_windows {
        writeln!(
            writer,
            "    <scan_window type=\"{}\" start_time=\"{}\" end_time=\"{}\" />",
            scan_type_name(&window.scan_type),
            xml_escape(&window.start_time.to_rfc3339()),
            xml_escape(&window.end_time.to_rfc3339())
        )?;
    }
    writeln!(writer, "  </scan_windows>")?;
    writeln!(writer, "  <results>")?;

    for host in &results.ssh_sorted_hosts {
        if let Some(host_results) = results.ssh_results.get(host) {
            for result in host_results {
                if let ScanResult::Ssh {
                    targetspec,
                    addr,
                    error,
                    pqc_supported,
                    pqc_algos,
                    nonpqc_algos,
                } = result
                {
                    write_xml_result(
                        writer,
                        "ssh",
                        targetspec,
                        addr,
                        error,
                        *pqc_supported,
                        pqc_algos,
                        &None,
                        nonpqc_algos,
                    )?;
                }
            }
        }
    }

    for host in &results.tls_sorted_hosts {
        if let Some(host_results) = results.tls_results.get(host) {
            for result in host_results {
                if let ScanResult::Tls {
                    targetspec,
                    addr,
                    error,
                    pqc_supported,
                    pqc_algos,
                    hybrid_algos,
                    nonpqc_algos,
                } = result
                {
                    write_xml_result(
                        writer,
                        "tls",
                        targetspec,
                        addr,
                        error,
                        *pqc_supported,
                        pqc_algos,
                        hybrid_algos,
                        nonpqc_algos,
                    )?;
                }
            }
        }
    }

    writeln!(writer, "  </results>")?;
    writeln!(writer, "</pqcscan_report>")?;
    Ok(())
}

fn write_xml_result<W: Write>(
    writer: &mut W,
    scan_type: &str,
    targetspec: &Target,
    addr: &Option<String>,
    error: &Option<String>,
    pqc_supported: bool,
    pqc_algos: &Option<Vec<String>>,
    hybrid_algos: &Option<Vec<String>>,
    nonpqc_algos: &Option<Vec<String>>,
) -> Result<()> {
    writeln!(writer, "    <result scan_type=\"{}\">", scan_type)?;
    write_xml_text_element(writer, 6, "host", &targetspec.host)?;
    write_xml_text_element(writer, 6, "port", &targetspec.port.to_string())?;
    write_xml_text_element(writer, 6, "address", &addr.clone().unwrap_or_default())?;
    write_xml_text_element(writer, 6, "status", status(error))?;
    write_xml_text_element(writer, 6, "pqc_supported", &pqc_supported.to_string())?;
    write_xml_algorithm_list(writer, 6, "pqc_algorithms", pqc_algos)?;
    write_xml_algorithm_list(writer, 6, "hybrid_algorithms", hybrid_algos)?;
    write_xml_algorithm_list(writer, 6, "non_pqc_algorithms", nonpqc_algos)?;
    write_xml_text_element(writer, 6, "error", &error.clone().unwrap_or_default())?;
    writeln!(writer, "    </result>")?;
    Ok(())
}

fn write_xml_algorithm_list<W: Write>(
    writer: &mut W,
    indent: usize,
    name: &str,
    algorithms: &Option<Vec<String>>,
) -> Result<()> {
    writeln!(writer, "{:indent$}<{}>", "", name, indent = indent)?;
    if let Some(algorithms) = algorithms {
        for algorithm in algorithms {
            write_xml_text_element(writer, indent + 2, "algorithm", algorithm)?;
        }
    }
    writeln!(writer, "{:indent$}</{}>", "", name, indent = indent)?;
    Ok(())
}

fn write_xml_text_element<W: Write>(
    writer: &mut W,
    indent: usize,
    name: &str,
    value: &str,
) -> Result<()> {
    writeln!(
        writer,
        "{:indent$}<{}>{}</{}>",
        "",
        name,
        xml_escape(value),
        name,
        indent = indent
    )?;
    Ok(())
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn scan_type_name(scan_type: &ScanType) -> &'static str {
    match scan_type {
        ScanType::Ssh => "ssh",
        ScanType::Tls => "tls",
    }
}

fn write_csv_report_to_writer<W: Write>(writer: &mut W, results: &ReportResults) -> Result<()> {
    write_csv_record(
        writer,
        &[
            "scan_type",
            "host",
            "port",
            "address",
            "status",
            "pqc_supported",
            "pqc_algorithms",
            "hybrid_algorithms",
            "non_pqc_algorithms",
            "error",
        ],
    )?;

    for host in &results.ssh_sorted_hosts {
        if let Some(host_results) = results.ssh_results.get(host) {
            for result in host_results {
                if let ScanResult::Ssh {
                    targetspec,
                    addr,
                    error,
                    pqc_supported,
                    pqc_algos,
                    nonpqc_algos,
                } = result
                {
                    write_csv_record(
                        writer,
                        &[
                            "ssh".to_string(),
                            targetspec.host.clone(),
                            targetspec.port.to_string(),
                            addr.clone().unwrap_or_default(),
                            status(error).to_string(),
                            pqc_supported.to_string(),
                            join_algorithms(pqc_algos),
                            String::new(),
                            join_algorithms(nonpqc_algos),
                            error.clone().unwrap_or_default(),
                        ],
                    )?;
                }
            }
        }
    }

    for host in &results.tls_sorted_hosts {
        if let Some(host_results) = results.tls_results.get(host) {
            for result in host_results {
                if let ScanResult::Tls {
                    targetspec,
                    addr,
                    error,
                    pqc_supported,
                    pqc_algos,
                    hybrid_algos,
                    nonpqc_algos,
                } = result
                {
                    write_csv_record(
                        writer,
                        &[
                            "tls".to_string(),
                            targetspec.host.clone(),
                            targetspec.port.to_string(),
                            addr.clone().unwrap_or_default(),
                            status(error).to_string(),
                            pqc_supported.to_string(),
                            join_algorithms(pqc_algos),
                            join_algorithms(hybrid_algos),
                            join_algorithms(nonpqc_algos),
                            error.clone().unwrap_or_default(),
                        ],
                    )?;
                }
            }
        }
    }
    Ok(())
}

fn status(error: &Option<String>) -> &'static str {
    if error.is_some() {
        "error"
    } else {
        "success"
    }
}

fn join_algorithms(algorithms: &Option<Vec<String>>) -> String {
    algorithms
        .as_ref()
        .map(|items| items.join(";"))
        .unwrap_or_default()
}

fn write_csv_record<W: Write>(writer: &mut W, fields: &[impl AsRef<str>]) -> Result<()> {
    for (idx, field) in fields.iter().enumerate() {
        if idx > 0 {
            writer.write_all(b",")?;
        }
        write_csv_field(writer, field.as_ref())?;
    }
    writer.write_all(b"\n")?;
    Ok(())
}

fn write_csv_field<W: Write>(writer: &mut W, field: &str) -> Result<()> {
    if field.chars().any(|c| matches!(c, ',' | '"' | '\n' | '\r')) {
        writer.write_all(b"\"")?;
        writer.write_all(field.replace('"', "\"\"").as_bytes())?;
        writer.write_all(b"\"")?;
    } else {
        writer.write_all(field.as_bytes())?;
    }
    Ok(())
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    log::info!("PQCscan {} starting", crate_version!());

    let matches = Command::new("pqcscan")
        .version(crate_version!())
        .propagate_version(true)
        .subcommand_required(true)
        .arg_required_else_help(true)
        .about("Post-Quantum Cryptography Scanner - Scan SSH/TLS servers for PQC support")
        .after_help(
            "PQCscan is free BSD-licensed software by Anvil Secure Inc (https://anvilsecure.com).",
        )
        .flatten_help(true)
        .subcommand(
            Command::new("ssh-scan")
                .about("Scan SSH servers")
                .next_help_heading("Target")
                .args(target_args())
                .next_help_heading("Output")
                .args(output_args("JSON", false))
                .next_help_heading("Scan Options")
                .args(vec![num_threads_arg()])
                .disable_help_flag(true)
                .disable_version_flag(true),
        )
        .subcommand(
            Command::new("tls-scan")
                .about("Scan TLS servers")
                .next_help_heading("Target")
                .args(target_args())
                .next_help_heading("Output")
                .args(output_args("JSON", false))
                .next_help_heading("Scan Options")
                .args(vec![
                    num_threads_arg(),
                    Arg::new("only-hybrid-algos")
                        .long("only-hybrid-algos")
                        .required(false)
                        .action(ArgAction::SetTrue)
                        .help("Limit scan to PQC hybrid algorithms only"),
                    Arg::new("test-nonpqc-algos")
                        .long("test-nonpqc-algos")
                        .required(false)
                        .action(ArgAction::SetTrue)
                        .help("Test non-PQC algorithms in the scan"),
                ])
                .disable_help_flag(true)
                .disable_version_flag(true),
        )
        .subcommand(
            Command::new("create-report")
                .about("Convert JSON results to HTML or CSV report")
                .next_help_heading("Input")
                .args(vec![Arg::new("input")
                    .short('i')
                    .long("input")
                    .value_name("JSON file")
                    .help("JSON file(s) containing scan results ")
                    .num_args(0..)])
                .next_help_heading("Output")
                .args(output_args("report", true))
                .arg(
                    Arg::new("format")
                        .long("format")
                        .value_parser(["html", "csv", "json", "xml"])
                        .default_value("html")
                        .help("Report output format"),
                )
                .disable_help_flag(true)
                .disable_version_flag(true),
        )
        .get_matches();

    let config = Config::new();

    log::debug!(
        "Configuration loaded: connection_timeout={}s, read_timeout={}s",
        config.connection_timeout,
        config.read_timeout
    );

    let mut scan = ScanOptions {
        num_threads: DEFAULT_NUM_THREADS,
        targets: vec![],
        scan_type: None,
        scan_hybrid_algos_only: false,
        scan_nonpqc_algos: false,
    };

    let mut output_json_file: Option<&String> = None;

    match matches.subcommand() {
        Some(("tls-scan", sub_matches)) => {
            log::info!("Starting TLS scan");
            scan.targets = get_targets(sub_matches, Some(config.tls_config.default_port))?;
            log::info!("Loaded {} target(s) for TLS scan", scan.targets.len());
            scan.scan_type = Some(ScanType::Tls);
            scan.scan_hybrid_algos_only =
                *sub_matches.get_one::<bool>("only-hybrid-algos").unwrap();
            if scan.scan_hybrid_algos_only {
                log::info!("Scanning for hybrid algorithms only");
            }
            scan.scan_nonpqc_algos = *sub_matches.get_one::<bool>("test-nonpqc-algos").unwrap();
            if scan.scan_nonpqc_algos {
                log::info!("Including non-PQC algorithms in the scan");
            }
            scan.num_threads = *sub_matches.get_one::<usize>("num-threads").unwrap();
            log::info!("Using {} thread(s)", scan.num_threads);
            output_json_file = sub_matches.get_one::<String>("output");
        }
        Some(("ssh-scan", sub_matches)) => {
            log::info!("Starting SSH scan");
            scan.targets = get_targets(sub_matches, Some(config.ssh_config.default_port))?;
            log::info!("Loaded {} target(s) for SSH scan", scan.targets.len());
            scan.scan_type = Some(ScanType::Ssh);
            scan.num_threads = *sub_matches.get_one::<usize>("num-threads").unwrap();
            log::info!("Using {} thread(s)", scan.num_threads);
            output_json_file = sub_matches.get_one::<String>("output");
        }
        Some(("create-report", sub_matches)) => {
            let report_format =
                ReportFormat::from(sub_matches.get_one::<String>("format").unwrap().as_str());
            log::info!("Creating report from JSON results");
            let input_files: Vec<_> = sub_matches
                .get_many::<String>("input")
                .ok_or(anyhow!(
                    "Need at least one input JSON file to convert into a report"
                ))?
                .collect();
            log::info!("Processing {} input file(s)", input_files.len());
            create_report(
                sub_matches.get_one::<String>("output").unwrap(),
                &input_files,
                report_format,
            )?;
            log::info!("Report created successfully");
        }
        _ => unreachable!("somehow reached this"),
    }

    /* perform scan if requested */
    if scan.scan_type.is_some() {
        log::info!("Initializing async runtime");
        let rt = Runtime::new()?;

        log::info!("Starting scan execution");
        let results = rt.block_on(scan_runner(Arc::new(config), scan));
        rt.shutdown_background();

        log::info!("Scan completed. Total results: {}", results.results.len());
        log::info!(
            "Scan duration: {:.2}s",
            (results.end_time - results.start_time).num_milliseconds() as f64 / 1000.0
        );

        /* write results to JSON output if requested */
        if output_json_file.is_some() {
            let output_file = output_json_file.unwrap();
            log::info!("Writing results to {}", output_file);
            let f = File::create(output_file)?;
            let mut writer = BufWriter::new(f);
            serde_json::to_writer_pretty(&mut writer, &results)?;
            log::info!("Results written successfully");
        }
    }

    log::info!("PQCscan finished");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_csv_record_escapes_special_characters() {
        let mut output = Vec::new();

        write_csv_record(
            &mut output,
            &["plain", "with,comma", "with \"quote\"", "with\nnewline", ""],
        )
        .unwrap();

        assert_eq!(
            String::from_utf8(output).unwrap(),
            "plain,\"with,comma\",\"with \"\"quote\"\"\",\"with\nnewline\",\n"
        );
    }

    #[test]
    fn write_csv_report_includes_ssh_and_tls_rows() {
        let mut ssh_results = HashMap::new();
        ssh_results.insert(
            "ssh.example.com".to_string(),
            vec![ScanResult::Ssh {
                targetspec: Target {
                    host: "ssh.example.com".to_string(),
                    port: 22,
                },
                addr: Some("203.0.113.10:22".to_string()),
                error: None,
                pqc_supported: true,
                pqc_algos: Some(vec!["sntrup761x25519-sha512".to_string()]),
                nonpqc_algos: Some(vec!["curve25519-sha256".to_string()]),
            }],
        );

        let mut tls_results = HashMap::new();
        tls_results.insert(
            "tls.example.com".to_string(),
            vec![ScanResult::Tls {
                targetspec: Target {
                    host: "tls.example.com".to_string(),
                    port: 443,
                },
                addr: None,
                error: Some("timeout, retry later".to_string()),
                pqc_supported: false,
                pqc_algos: Some(vec![]),
                hybrid_algos: Some(vec!["X25519MLKEM768".to_string()]),
                nonpqc_algos: Some(vec!["x25519".to_string()]),
            }],
        );

        let results = ReportResults {
            tls_results,
            tls_sorted_hosts: BTreeSet::from(["tls.example.com".to_string()]),
            tls_success_count: 0,
            tls_fail_count: 1,
            tls_pqc_supported_count: 0,
            tls_total_count: 1,
            ssh_results,
            ssh_sorted_hosts: BTreeSet::from(["ssh.example.com".to_string()]),
            ssh_success_count: 1,
            ssh_fail_count: 0,
            ssh_pqc_supported_count: 1,
            ssh_total_count: 1,
            scan_windows: vec![],
        };

        let mut output = Vec::new();
        write_csv_report_to_writer(&mut output, &results).unwrap();

        assert_eq!(
            String::from_utf8(output).unwrap(),
            concat!(
                "scan_type,host,port,address,status,pqc_supported,pqc_algorithms,hybrid_algorithms,non_pqc_algorithms,error\n",
                "ssh,ssh.example.com,22,203.0.113.10:22,success,true,sntrup761x25519-sha512,,curve25519-sha256,\n",
                "tls,tls.example.com,443,,error,false,,X25519MLKEM768,x25519,\"timeout, retry later\"\n",
            )
        );
    }

    #[test]
    fn write_xml_report_escapes_values() {
        let mut ssh_results = HashMap::new();
        ssh_results.insert(
            "ssh.example.com".to_string(),
            vec![ScanResult::Ssh {
                targetspec: Target {
                    host: "ssh.example.com".to_string(),
                    port: 22,
                },
                addr: Some("203.0.113.10:22".to_string()),
                error: Some("bad \"quote\" & <tag>".to_string()),
                pqc_supported: false,
                pqc_algos: Some(vec!["sntrup761x25519-sha512".to_string()]),
                nonpqc_algos: Some(vec!["curve25519-sha256".to_string()]),
            }],
        );

        let results = ReportResults {
            tls_results: HashMap::new(),
            tls_sorted_hosts: BTreeSet::new(),
            tls_success_count: 0,
            tls_fail_count: 0,
            tls_pqc_supported_count: 0,
            tls_total_count: 0,
            ssh_results,
            ssh_sorted_hosts: BTreeSet::from(["ssh.example.com".to_string()]),
            ssh_success_count: 0,
            ssh_fail_count: 1,
            ssh_pqc_supported_count: 0,
            ssh_total_count: 1,
            scan_windows: vec![ScanWindow {
                start_time: Utc::now(),
                end_time: Utc::now(),
                scan_type: ScanType::Ssh,
            }],
        };

        let mut output = Vec::new();
        write_xml_report_to_writer(&mut output, &results).unwrap();
        let output = String::from_utf8(output).unwrap();

        assert!(output.contains(r#"<ssh total="1" success="0" failed="1" pqc_supported="0" />"#));
        assert!(output.contains(r#"<result scan_type="ssh">"#));
        assert!(output.contains("<algorithm>sntrup761x25519-sha512</algorithm>"));
        assert!(output.contains("<error>bad &quot;quote&quot; &amp; &lt;tag&gt;</error>"));
    }
}
