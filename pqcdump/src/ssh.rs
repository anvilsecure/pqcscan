use etherparse::SlicedPacket;
use std::collections::HashMap;
use serde::{Serialize,Deserialize};

#[derive(Hash, Eq, PartialEq, Clone, Debug, Serialize)]
pub struct FlowKey {
    src: String,
    dst: String,
}

impl FlowKey {
    pub fn src(&self) -> &str {
        &self.src
    }

    pub fn dst(&self) -> &str {
        &self.dst
    }
}

#[derive(Debug, Default, Serialize)]
pub struct SshSession {
    client_kexinit: Option<KexInit>,
    server_kexinit: Option<KexInit>,
    negotiated: Option<NegotiatedAlgorithms>,
}

impl SshSession {
    pub fn negotiated(&self) -> Option<&NegotiatedAlgorithms> {
        self.negotiated.as_ref()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct KexInit {
    kex_algorithms: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct NegotiatedAlgorithms {
    kex: String,
}

impl NegotiatedAlgorithms {
    pub fn kex(&self) -> &str {
        &self.kex
    }
}

#[derive(Default, Serialize, Deserialize, Clone)]
pub struct HostCapabilities {
    supported_kex: linked_hash_set::LinkedHashSet<String>,
}

impl HostCapabilities {
    pub fn supported_kex(&self) -> &linked_hash_set::LinkedHashSet<String> {
        &self.supported_kex
    }
}

fn format_socket_addr(ip: &str, port: u16) -> String {
    if ip.contains(':') {
        format!("[{}]:{}", ip, port)
    } else {
        format!("{}:{}", ip, port)
    }
}

pub fn process_ssh(sliced: &SlicedPacket, payload: &[u8], sessions: &mut HashMap<FlowKey, SshSession>,
    host_caps: &mut HashMap<String, HostCapabilities>){
    let kex = match parse_ssh_kexinit(payload) {
        Some(k) => k,
        None => return,
    };

    let tcp = match sliced.transport {
        Some(etherparse::TransportSlice::Tcp(ref tcp)) => tcp,
        _ => return,
    };

    let (src_ip, dst_ip) = match &sliced.net {
        Some(etherparse::NetSlice::Ipv4(ipv4)) => (
            ipv4.header().source_addr().to_string(),
            ipv4.header().destination_addr().to_string(),
        ),
        Some(etherparse::NetSlice::Ipv6(ipv6)) => (
            ipv6.header().source_addr().to_string(),
            ipv6.header().destination_addr().to_string(),
        ),
        _ => return,
    };

    let flow = FlowKey {
        src: format_socket_addr(&src_ip, tcp.source_port()),
        dst: format_socket_addr(&dst_ip, tcp.destination_port()),
    };

    let reverse_flow = FlowKey {
        src: flow.dst.clone(),
        dst: flow.src.clone(),
    };

    // Determine if session already exists in forward or reverse direction
    let (session, is_forward) = if let Some(s) = sessions.get_mut(&flow) {
        (s, true)
    } else if let Some(s) = sessions.get_mut(&reverse_flow) {
        (s, false)
    } else {
        let s = sessions.entry(flow.clone()).or_default();
        (s, true)
    };

    if is_forward && session.client_kexinit.is_none() {
        update_host_caps(host_caps, &src_ip, &kex);
        session.client_kexinit = Some(kex);
    } else if !is_forward && session.server_kexinit.is_none() {
        update_host_caps(host_caps, &src_ip, &kex);
        session.server_kexinit = Some(kex);
    }

    if session.negotiated.is_none() {
        if let (Some(client), Some(server)) = (session.client_kexinit.as_ref(), session.server_kexinit.as_ref()) {
            if let Some(neg) = negotiate(&client.kex_algorithms, &server.kex_algorithms) {
                session.negotiated = Some(NegotiatedAlgorithms { kex: neg });
            }
        }
    }
}

fn negotiate(client: &[String], server: &[String]) -> Option<String> {
    for alg in client {
        if server.contains(alg) {
            return Some(alg.clone());
        }
    }
    None
}

fn update_host_caps(
    host_caps: &mut HashMap<String, HostCapabilities>,
    host: &str,
    kex: &KexInit,
) {
    let entry = host_caps.entry(host.to_string()).or_default();

    for alg in &kex.kex_algorithms {
        entry.supported_kex.insert(alg.clone());
    }
}

pub const SSH_MSG_KEXINIT: u8 = 20;

fn parse_ssh_kexinit(payload: &[u8]) -> Option<KexInit> {
    if payload.len() < 6 || payload[5] != SSH_MSG_KEXINIT {
        return None;
    }

    let mut data = &payload[6..];

    data.get(..16)?;
    data = &data[16..];

    let kex_algorithms = read_name_list_owned(&mut data)?;

    // Skip remaining 9 name-lists
    for _ in 0..9 {
        read_name_list_owned(&mut data)?;
    }

    Some(KexInit {
        kex_algorithms,
    })
}

fn read_name_list_owned(data: &mut &[u8]) -> Option<Vec<String>> {
    let len = read_u32(data)? as usize;

    if data.len() < len {
        return None;
    }

    let list_bytes = &data[..len];
    *data = &data[len..];

    let list_str = std::str::from_utf8(list_bytes).ok()?;

    Some(list_str.split(',').map(|s| s.to_string()).collect())
}

fn read_u32(data: &mut &[u8]) -> Option<u32> {
    if data.len() < 4 {
        return None;
    }
    let val = u32::from_be_bytes(data[..4].try_into().unwrap());
    *data = &data[4..];
    Some(val)
}