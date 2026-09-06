use pcap::{Capture, Linktype, Packet};
use etherparse::{SlicedPacket, TransportSlice};
use std::net::SocketAddr;
use std::collections::{BTreeSet, HashSet};
use std::{collections::HashMap, path::PathBuf};
use serde::{Serialize,Deserialize};
use rust_embed::RustEmbed;
use clap::Parser;
use crate::ssh::{FlowKey, SshSession, HostCapabilities};
use crate::tcp::{TcpReassembler, TcpFlowKey};
use crate::tls::TlsSessionKey;
use chrono::{DateTime, TimeZone, Utc};

mod ssh;
mod tls;
mod tcp;
mod report;

pub const PQC_SUPPORTED: &str = "PQC Supported";

#[derive(Parser, Debug)]
#[command(
    name = "pqcdump",
    author = "Anvil Secure Inc",
    version,
    about = "Post-Quantum Cryptography PCAP Scanner",
    long_about = "pqcdump analyzes PCAP files and identifies hosts and established \
sessions to determine whether Post-Quantum Cryptography (PQC) algorithms are used \
or supported in TLS and SSH handshakes.",
    after_help = "pqcdump is free BSD-licensed software by Anvil Secure Inc (https://anvilsecure.com)."
)]
struct Args {
    /// Input PCAP file to analyze
    ///
    /// The PCAP should contain TLS or SSH traffic to analyze for post-quantum cryptographic algorithm support.
    #[arg(
        value_name = "PCAP file"
    )]
    pcap: PathBuf,

    /// Output HTML results file
    ///
    /// The generated file will contain identified hosts, sessions, and detected PQC capabilities.
    #[arg(
        value_name = "Output file path",
        default_value = "results.html"
    )]
    output: PathBuf,
}

#[derive(RustEmbed)]
#[folder = "$CARGO_MANIFEST_DIR/../pqcscan/support"]
#[include = "kex_algos.json"]
#[include = "tls_groups.json"]
#[include = "tls_cipher_suites.json"]
struct EmbeddedResources;

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct KexAlgo {
    pqc: bool,
    broken: bool,
    hybrid: Option<bool>,
    desc: Option<String>,
    href: Option<String>
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct TlsGroup {
    #[serde(skip)]
    name: String,
    group_id: u16,
    pqc: bool,
    hybrid: bool,
    #[allow(dead_code)] // currently not used
    obsolete: bool,
    #[allow(dead_code)] // currently not used
    insecure: bool,
    #[allow(dead_code)] // currently not used
    desc: String,
    #[allow(dead_code)] // currently not used
    href: String,
}

#[derive(Debug, Deserialize)]
pub struct TlsCipherSuite {
    #[serde(skip)]
    pub name: String,

    pub cipher_suite_id: u16,

    #[allow(dead_code)]
    pub obsolete: bool,

    #[allow(dead_code)]
    pub insecure: bool,

    #[allow(dead_code)]
    pub desc: String,

    #[allow(dead_code)]
    pub href: String,
}

fn load_kex_algos() -> HashMap<String, KexAlgo> {
    let json_file = EmbeddedResources::get("kex_algos.json").unwrap();
    let json_data = std::str::from_utf8(json_file.data.as_ref()).unwrap();
    serde_json::from_str(&json_data).unwrap()
}

fn load_groups() -> HashMap<u16, TlsGroup> {
    let json_file = EmbeddedResources::get("tls_groups.json").unwrap();
    let json_data = std::str::from_utf8(json_file.data.as_ref()).unwrap();

    let groups_by_name: HashMap<String, TlsGroup> =
        serde_json::from_str(json_data).unwrap();

    let mut groups_by_id = HashMap::new();

    for (name, mut group) in groups_by_name {
        group.name = name;
        groups_by_id.insert(group.group_id, group);
    }

    groups_by_id
}

fn load_cipher_suites() -> HashMap<u16, TlsCipherSuite> {
    let json_file = EmbeddedResources::get("tls_cipher_suites.json").unwrap();
    let json_data = std::str::from_utf8(json_file.data.as_ref()).unwrap();

    let suites_by_name: HashMap<String, TlsCipherSuite> =
        serde_json::from_str(json_data).unwrap();

    let mut suites_by_id = HashMap::new();

    for (name, mut suite) in suites_by_name {
        suite.name = name;
        suites_by_id.insert(suite.cipher_suite_id, suite);
    }

    suites_by_id
}

fn main() {
    env_logger::init();
    
    let args = Args::parse();

    let file_path = &args.pcap;

    let mut cap = match Capture::from_file(file_path) {
        Ok(cap) => cap,
        Err(e) => {
            eprintln!("Failed to open pcap file '{}': {}", file_path.display(), e);
            std::process::exit(1);
        }
    };
    let linktype = cap.get_datalink();
    if linktype == Linktype::LINUX_SLL2 {
        eprintln!("Unsupported link type: Linux cooked capture v2 (SLL2) is not supported");
        std::process::exit(1);
    }

    let mut ssh_sessions: HashMap<FlowKey, SshSession> = HashMap::new();
    let mut host_caps: HashMap<String, HostCapabilities> = HashMap::new();
    let mut tls_ciphers: HashMap<String, HashSet<u16>> = HashMap::new();
	let mut keyshare_groups: HashMap<String, HashSet<u16>> = HashMap::new();
	let mut tls_sessions: HashMap<TlsSessionKey, u16> = HashMap::new();
    let mut reassembler = TcpReassembler::new();

    let mut packet_count = 0;
    let mut start_time: Option<DateTime<Utc>> = None;
    let mut end_time: DateTime<Utc> = Utc::now();


    while let Ok(packet) = cap.next_packet() {
        packet_count += 1;
        log::debug!("{}", packet_count);
        process_packet(&packet, linktype, &mut reassembler, &mut ssh_sessions, &mut host_caps, &mut tls_ciphers, &mut keyshare_groups, &mut tls_sessions);
        let ts = Utc.timestamp_opt(packet.header.ts.tv_sec.into(), (packet.header.ts.tv_usec * 1000).try_into().unwrap()).unwrap();
        if start_time.is_none() { start_time = Some(ts); }
        end_time = ts;
    }

    let kex_algos = load_kex_algos();
    let groups = load_groups();
    let cipher_suites = load_cipher_suites();

    let mut ssh_hosts = BTreeSet::<String>::new();
    let mut ssh_hosts_pqc = HashMap::<String, String>::new();
    
    let mut ssh_hosts_pqc_algos = HashMap::<String, BTreeSet::<AlgorithmDetails>>::new();
    let mut ssh_sessions_results = HashMap::<String, HashSet::<SessionResult>>::new();

    let mut hosts = BTreeSet::<String>::new();
    let mut pqc_hosts = BTreeSet::<String>::new();

    log::info!("\n=== Host Capabilities ===");
    for (host, caps) in &host_caps {
        log::info!("{}", host);
        ssh_hosts.insert(host.to_string());
        hosts.insert(host.to_string());
        let mut pqc_supported = false;
        ssh_hosts_pqc_algos
            .entry(host.clone())
            .or_default();
        for alg in caps.supported_kex() {
            log::info!("  {}", alg);
            if let Some(algo) =  kex_algos.get(alg) {
                log::info!("{} {}", alg, algo.pqc);
                if algo.pqc || algo.hybrid.unwrap_or(false) {
                    pqc_supported = true;
                } 
                let description;
                    if algo.hybrid.unwrap_or(false) {
                        description = "Hybrid"
                    } else if algo.pqc {
                        description = PQC_SUPPORTED;
                    } else {
                        description = "Not PQC Safe";
                    }
                    if let Some(set) = ssh_hosts_pqc_algos.get_mut(host) {
                         let algo = AlgorithmDetails::new(
                            alg.to_string(),
                            algo.desc.clone().unwrap_or("-".to_string()),
                            description.to_string(),
                            algo.href.clone().unwrap_or("-".to_string())
                        );
                        set.insert(algo);
                    }
            } else {
                log::debug!("Algorithm not found ({})", alg);
            }
        }
        let pqc_support;
        if pqc_supported {
            pqc_support = PQC_SUPPORTED.to_string();
            pqc_hosts.insert(host.to_string());
        } else {
            pqc_support = "No Support".to_string();
        }
        ssh_hosts_pqc.insert(host.to_string(), pqc_support);
    }

    log::info!("\n=== Negotiated Sessions ===");
    let mut ssh_pqc_supported_count = 0;
    for (flow, session) in &ssh_sessions {
        if let Some(neg) = &session.negotiated() {
            let src: SocketAddr = flow.src().parse().expect("invalid socket address");
            let (source_ip, source_port) = (src.ip().to_string(), src.port());
            let dst: SocketAddr = flow.dst().parse().expect("invalid socket address");
            let (destination_ip, destination_port) = (dst.ip().to_string(), dst.port());
            
            ssh_sessions_results.entry(source_ip.clone()).or_default();
            log::info!("{} -> {} : {}", flow.src(), flow.dst(), neg.kex());
            if let Some(algo) =  kex_algos.get(neg.kex()) {
                log::info!("{} {}", neg.kex(), algo.pqc);
                let description;
                if algo.pqc {
                    log::info!("{}", PQC_SUPPORTED);
                    ssh_pqc_supported_count += 1;
                    description = PQC_SUPPORTED;
                } else if algo.hybrid.unwrap_or(false) {
                    log::info!("Hybrid");
                    description = "Hybrid";
                } else {
                    log::info!("NOT Supported");
                    description = "NOT Supported";
                } 
                if let Some(set) = ssh_sessions_results.get_mut(&source_ip) {
                    let session_result = SessionResult::new(
                        source_ip,
                        source_port,
                        destination_ip,
                        destination_port,
                        neg.kex().to_string(),
                        description.to_string(),
                    );
                    set.insert(session_result);
                }
            } else {
                log::debug!("Algorithm not found ({})", &neg.kex());
            }
        }
    }

    let mut tls_hosts = BTreeSet::<String>::new();
    let mut tls_hosts_pqc = HashMap::<String, String>::new();
    let mut tls_hosts_ciphers = HashMap::<String, BTreeSet::<String>>::new();
    let mut tls_host_capabilities = HashMap::<String, BTreeSet::<AlgorithmDetails>>::new();
    let mut tls_sessions_results = HashMap::<String, HashSet::<SessionResult>>::new();

    
    if !tls_ciphers.is_empty() {
        log::info!("\n=== TLS CIPHERS Map ===");
        for (key, values) in &tls_ciphers {
            log::info!("{}:", key);
            
            let source_ip = key.parse::<SocketAddr>().expect("invalid socket address").ip().to_string();
            tls_hosts.insert(source_ip.to_string());
            let cipher_set = tls_hosts_ciphers.entry(source_ip.clone()).or_default();
            for id in values {
                if let Some(cipher) = cipher_suites.get(id) {
                    log::info!("  {}", cipher.name);
                    cipher_set.insert(cipher.name.clone());
                } else {
                    log::info!("  {} -> UNKNOWN", id);
                    cipher_set.insert(id.to_string());
                }
            }
        }
    }
	
    if !keyshare_groups.is_empty() {
        log::info!("\n=== KeyShare Groups Map ===");
        for (key, values) in &keyshare_groups {
            let source_ip = key.parse::<SocketAddr>().expect("invalid socket address").ip().to_string();            
            hosts.insert(source_ip.to_string());
            let mut pqc_supported = false;
            tls_host_capabilities
                .entry(source_ip.clone())
                .or_default();
            for value in values {
                if let Some(group) = groups.get(value) {
                    let description;
                    if group.hybrid {
                        description = "Hybrid";
                        pqc_supported = true;
                    } else if group.pqc {
                        description = "Pure PQC";
                        pqc_supported = true;
                    } else {
                        description = "Not PQC safe";
                    }
                    log::info!("{}", description);
                    if let Some(set) = tls_host_capabilities.get_mut(&source_ip) {
                        let algo = AlgorithmDetails::new(
                            group.name.clone(),
                            group.desc.clone(),
                            description.to_string(),
                            group.href.clone()
                        );
                        set.insert(algo);
                    }
                }
            }
            
            let pqc_support;
            if pqc_supported {
                pqc_support = PQC_SUPPORTED.to_string();
                pqc_hosts.insert(source_ip.to_string());
            } else {
                pqc_support = "No Support".to_string();
            }
            tls_hosts_pqc.insert(source_ip.to_string(), pqc_support);
        }
    }

    for host in &tls_hosts {
        tls_hosts_pqc.entry(host.clone()).or_insert_with(|| "TLS 1.2".to_string());
    }

    let mut tls_pqc_supported_count = 0;
    if !tls_sessions.is_empty() {
        log::info!("\n=== Negotiated TLS Sessions ===");
        for (key, value) in &tls_sessions {
            log::info!("{}", key);
            let source_ip = key.src_ip;
            let source_port = key.src_port;
            let destination_ip = key.dst_ip;
            let destination_port = key.dst_port;
            tls_sessions_results
                .entry(source_ip.to_string())
                .or_default();
            if let Some(group) = groups.get(value) {
                log::info!("{} -> {}", key, group.name);
                let description;
                if group.hybrid {
                    description = "Hybrid";
                    tls_pqc_supported_count += 1;
                } else if group.pqc {
                    description = "Pure PQC";
                    tls_pqc_supported_count += 1;
                } else {
                    description = "NOT Supported";
                }
                log::info!("{}", description);
                if let Some(set) = tls_sessions_results.get_mut(&source_ip.to_string()) {
                    let key = SessionResult::new(
                        source_ip.to_string(),
                        source_port,
                        destination_ip.to_string(),
                        destination_port,
                        group.name.clone(),
                        description.to_string(),
                    );
                    set.insert(key);
                }
            }
        }
    }

    let results: ReportResults = ReportResults {
        filename: file_path.file_name().map(|s| s.to_string_lossy().into_owned()).expect("filename error"),
        total_count: hosts.len(),
        pqc_count: pqc_hosts.len(),
        ssh_hosts_count: ssh_hosts.len(),
        ssh_sessions_count: ssh_sessions.len(),
        ssh_pqc_supported_count,
        tls_hosts_count: tls_hosts.len(),
        tls_sessions_count: tls_sessions.len(),
        tls_pqc_supported_count,
        packet_count,
        start_time: start_time.unwrap_or(Utc::now()),
        end_time,
        ssh_host_capabilities: ssh_hosts_pqc_algos,
        ssh_hosts,
        ssh_hosts_pqc,
        ssh_sessions_results,
        tls_hosts,
        tls_hosts_pqc,
        tls_host_capabilities,
        tls_sessions_results,
    };

    if let Err(e) = report::generate_report(&args.output, results) {
        eprintln!("Error generating report: {:#}", e);
    }    
}

#[derive(Serialize)]
struct ReportResults {
    filename: String,
    total_count: usize,
    pqc_count: usize,
    ssh_hosts_count: usize,
    ssh_sessions_count: usize,
    ssh_pqc_supported_count: usize,
    tls_hosts_count: usize,
    tls_sessions_count: usize,
    tls_pqc_supported_count: usize,
    packet_count: usize,
    start_time: DateTime<Utc>,
    end_time: DateTime<Utc>,
    ssh_host_capabilities: HashMap<String, BTreeSet::<AlgorithmDetails>>,
    ssh_hosts: BTreeSet<String>,
    ssh_hosts_pqc: HashMap<String, String>,
    ssh_sessions_results: HashMap::<String, HashSet::<SessionResult>>,
    tls_hosts: BTreeSet<String>,
    tls_hosts_pqc: HashMap<String, String>,
    tls_host_capabilities: HashMap::<String, BTreeSet::<AlgorithmDetails>>,
    tls_sessions_results: HashMap::<String, HashSet::<SessionResult>>,
}

#[derive(Serialize, Ord, PartialOrd, Eq, PartialEq, Hash)]
struct SessionResult {
    source: String,
    source_port: u16,
    destination: String,
    destination_port: u16,
    algorithm: String,
    pqc_status: String,
}

impl SessionResult {
    pub fn new(source: String, source_port: u16, destination: String, port: u16, algorithm: String, pqc_status: String ) -> Self {
        Self { source, source_port, destination_port: port, destination, algorithm, pqc_status }
    }
}
#[derive(Serialize, Ord, PartialOrd, Eq, PartialEq, Hash)]
struct AlgorithmDetails {
    name: String,
    description: String,
    pqc_status: String,
    link: String
}

impl AlgorithmDetails {
    pub fn new(name: String, description: String, pqc_status: String, link: String) -> Self {
        Self { name, description, pqc_status, link }
    }
}

fn process_packet(packet: &Packet,
    linktype: Linktype,
    reassembler: &mut TcpReassembler,
    sessions: &mut HashMap<FlowKey, SshSession>,
    ssh_host_caps: &mut HashMap<String, HostCapabilities>,
    tls_ciphers: &mut HashMap<String, HashSet<u16>>,
    keyshare_groups: &mut HashMap<String, HashSet<u16>>,
    tls_sessions: &mut HashMap<TlsSessionKey, u16>) {
    let sliced_result = match linktype {
        Linktype::LINUX_SLL => SlicedPacket::from_linux_sll(&packet),
        _ => SlicedPacket::from_ethernet(&packet),
    };
    match sliced_result {
	    Err(sliced) => log::debug!("Err {:?}", sliced),
	    Ok(sliced) => {
			log::debug!("link: {:?}", sliced.link);
			log::debug!("link_exts: {:?}", sliced.link_exts); // contains vlan & macsec
			log::debug!("net: {:?}", sliced.net); // contains ip & arp
			log::debug!("transport: {:?}", sliced.transport);			

            let (src_ip, dst_ip) = match sliced.net {
                Some(etherparse::NetSlice::Ipv4(ref ipv4)) => (
                    ipv4.header().source_addr().to_string(),
                    ipv4.header().destination_addr().to_string(),
                ),
                Some(etherparse::NetSlice::Ipv6(ref ipv6)) => (
                    ipv6.header().source_addr().to_string(),
                    ipv6.header().destination_addr().to_string(),
                ),
                _ => return,
            };

            let tcp = match sliced.transport {
                Some(TransportSlice::Tcp(ref t)) => t,
                _ => return,
            };

            let key = TcpFlowKey::new(
                src_ip,
                dst_ip,
                tcp.source_port(),
                tcp.destination_port()
            );
            
            let payload = tcp.payload();
            if payload.len() < 6 {
                return;
            }

            process_packet_helper(&sliced, &payload, sessions, ssh_host_caps, &tcp, tls_ciphers, keyshare_groups, tls_sessions);

            // Try a reassembled packet
            if let Some(data) = reassembler.push(key, tcp.sequence_number(), tcp.payload()) {
                process_packet_helper(&sliced, &data, sessions, ssh_host_caps, &tcp, tls_ciphers, keyshare_groups, tls_sessions);
            }   
        }
    }	
}

fn process_packet_helper(sliced: &SlicedPacket, 
        payload: &[u8], 
        ssh_sessions: &mut HashMap<FlowKey, SshSession>,
        ssh_host_capabilities: &mut HashMap<String, HostCapabilities>,
        tcp: &etherparse::TcpSlice<'_>,
        tls_ciphers: &mut HashMap<String, HashSet<u16>>, 
        keyshare_groups: &mut HashMap<String, HashSet<u16>>,
        tls_sessions: &mut HashMap<TlsSessionKey, u16>){
    if payload[5] == ssh::SSH_MSG_KEXINIT {
        log::debug!("This may be an SSH_MSG_KEXINIT message");
        ssh::process_ssh(&sliced, &payload, ssh_sessions, ssh_host_capabilities);
    }

    // Check SSLv3+ ClientHello
    if payload.len() > 5
        && payload[0] == 0x16
        && payload[1] == 0x03
        && (0x00..=0x04).contains(&payload[2])
    {
        tls::process_ssl_hello(&sliced, &payload, &tcp, tls_ciphers, keyshare_groups, tls_sessions);
    }
}