use etherparse::SlicedPacket;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

pub fn process_ssl_hello(sliced: &SlicedPacket<'_>, 
    payload: &[u8], 
    tcp: &etherparse::TcpSlice<'_>,
    tls_ciphers: &mut HashMap<String, HashSet<u16>>, 
    keyshare_groups: &mut HashMap<String, HashSet<u16>>,
    tls_sessions: &mut HashMap<TlsSessionKey, u16>) {
    // Handshake type at payload[5]
    let handshake_type = payload[5];

    let key = match &sliced.net {
            Some(etherparse::NetSlice::Ipv4(ipv4)) => {
                format!("{}:{}",
                    ipv4.header().source_addr(),
                    tcp.source_port())
            }
            Some(etherparse::NetSlice::Ipv6(ipv6)) => {
                format!("{}:{}",
                    ipv6.header().source_addr(),
                    tcp.source_port()
                )
            }
            _ => "unknown:0".to_string(),
        };

    if handshake_type == 0x01 {
        log::debug!("ClientHello v3 ???");

        match parse_ssl_v3_client_hello(payload){
            Ok(result) => {
            for val in result.ciphers.iter() {
                tls_ciphers
                    .entry(key.clone())
                    .or_default()
                    .insert(*val);
                }
            for val in result.keyshare_groups.iter() {
                keyshare_groups
                    .entry(key.clone())
                    .or_default()
                    .insert(*val);
            }}
            Err(e) => {log::debug!("Error: {}", e); }
        }
      } else if handshake_type == 0x02 {
        log::debug!("ServerHello v3 ???");

        let session_key = match &sliced.net {
            Some(etherparse::NetSlice::Ipv4(ipv4)) => Some(TlsSessionKey {
                src_ip: IpAddr::V4(ipv4.header().destination_addr()),
                src_port: tcp.destination_port(),
                dst_ip: IpAddr::V4(ipv4.header().source_addr()),
                dst_port: tcp.source_port(),
            }),
            Some(etherparse::NetSlice::Ipv6(ipv6)) => Some(TlsSessionKey {
                src_ip: IpAddr::V6(ipv6.header().destination_addr()),
                src_port: tcp.destination_port(),
                dst_ip: IpAddr::V6(ipv6.header().source_addr()),
                dst_port: tcp.source_port(),
            }),
            _ => None,
        };

        match parse_server_hello_v3(payload){
            Ok(result) => {
                tls_sessions.insert(session_key.expect("Key parsing failed"), result.keyshare);
                keyshare_groups
                    .entry(key.clone())
                    .or_default()
                    .insert(result.keyshare);
                for val in result.ciphers.iter() {
                    tls_ciphers
                        .entry(key.clone())
                        .or_default()
                        .insert(*val);
                    }
            }
            Err(e) => {log::debug!("Error: {}", e); }
        }
    }
}


fn parse_ssl_v3_client_hello(data: &[u8]) -> Result<CryptoConfig, String> {
	let mut offset = 9;
	
    // Step 1: Skip ProtocolVersion (2 bytes) + Random (32 bytes)
    if data.len() < 34 {
        return Err("Data too short for ProtocolVersion and Random".to_string());
    }
    offset += 34;

    // Step 2: SessionID
    if offset >= data.len() {
        return Err("Data too short for SessionID length".to_string());
    }
    let session_id_len = data[offset] as usize;
    offset += 1;
	
    if offset + session_id_len > data.len() {
        return Err("Data too short for SessionID".to_string());
    }
    offset += session_id_len;

    // Step 3: CipherSuites length (2 bytes)
    if offset + 2 > data.len() {
        return Err("Data too short for CipherSuites length".to_string());
    }
    let cipher_suites_len = ((data[offset] as usize) << 8) | data[offset + 1] as usize;
    offset += 2;

    if offset + cipher_suites_len > data.len() {
        return Err("Data too short for CipherSuites data".to_string());
    }

    // Step 4: Parse cipher suites (each 2 bytes)
    let mut cipher_suites = Vec::new();
    for _i in (0..cipher_suites_len).step_by(2) {
        let cs = ((data[offset] as u16) << 8) | data[offset + 1] as u16;
		log::debug!("Cipher Suite {}", cs);
        cipher_suites.push(cs);	
		offset += 2;
    }
	
	// Step 5: Compression methods
    if offset >= data.len() {
        return Err("Data too short for compression methods length".to_string());
    }
    let comp_len = data[offset] as usize;
    offset += 1 + comp_len; // skip compression methods
    // Step 6: Extensions
    if offset + 2 > data.len() {
        return Err("Data too short for extensions length".to_string());
    }
    let extensions_len = ((data[offset] as usize) << 8) | data[offset + 1] as usize;
    offset += 2;

    if offset + extensions_len > data.len() {
        return Err("Data too short for extensions data".to_string());
    }

	let mut keyshare_groups: Vec<u16> = Vec::new();
    let extensions_end = offset + extensions_len;
    while offset + 4 <= extensions_end {
        let ext_type = ((data[offset] as u16) << 8) | data[offset + 1] as u16;
        let ext_len = ((data[offset + 2] as usize) << 8) | data[offset + 3] as usize;
        offset += 4;

        if offset + ext_len > extensions_end {
            return Err("Extension length goes beyond extensions block".to_string());
        }
        if ext_type == 0x0033 {
            // KeyShare extension

            if ext_len < 2 {
                return Err("KeyShare extension too short".to_string());
            }
            let mut ks_offset = offset + 2;

            while ks_offset + 4 <= offset + ext_len {
                let group = ((data[ks_offset] as u16) << 8) | data[ks_offset + 1] as u16;
                let key_exchange_len =
                    ((data[ks_offset + 2] as usize) << 8) | data[ks_offset + 3] as usize;
                ks_offset += 4;

                if ks_offset + key_exchange_len > offset + ext_len {
                    return Err("KeyShare key_exchange data too short".to_string());
                }

				keyshare_groups.push(group);
                ks_offset += key_exchange_len;
            }
        }

        offset += ext_len;
    }

    Ok(CryptoConfig{ciphers: cipher_suites, keyshare_groups:keyshare_groups})
}

fn parse_server_hello_v3(payload: &[u8]) -> Result<SessionConfig, &'static str> {
	log::debug!("Parsing ServerHello {}", payload.len());
    // Basic sanity check
    if payload.len() < 5 + 4 + 38 { // header + handshake header + fixed fields up to session id length
        return Err("Payload too short for ServerHello");
    }

    // TLS Record header (5 bytes)
    // Handshake header (4 bytes)
    let handshake_start = 5;
    let handshake_type = payload[handshake_start];
    if handshake_type != 0x02 {
        return Err("Not a ServerHello handshake");
    }



    // Handshake length (3 bytes) - not strictly needed here, but could validate

    // Position after handshake header
    let mut pos = handshake_start + 4;

    // Version (2 bytes)
    pos += 2;

    // Random (32 bytes)
    pos += 32;

    // Session ID length (1 byte)
    let session_id_len = payload[pos] as usize;
    pos += 1;

    // Session ID (variable)
    if payload.len() < pos + session_id_len + 3 {
        return Err("Payload too short for Session ID");
    }
    pos += session_id_len;

    // Cipher Suite (2 bytes)
    let cipher_suite = &payload[pos..pos+2];	
    pos += 2;
	
	// Print cipher suite
	let cipher_code = u16::from_be_bytes([cipher_suite[0], cipher_suite[1]]);
	log::debug!("Cipher Suite: 0x{:04x}", cipher_code);

    // Compression method (1 byte)
    pos += 1;

	// Extensions length (2 bytes)
    if payload.len() < pos + 2 {
        log::debug!("Payload too short for extensions length");
        //return;
    }
    let extensions_len = u16::from_be_bytes([payload[pos], payload[pos+1]]) as usize;
    pos += 2;

    let mut keyshare: Option<u16> = None;

    if payload.len() < pos + extensions_len {
        log::debug!("Payload too short for extensions");
    } else {
        let extensions = &payload[pos..pos + extensions_len];

        let key_share_entries = parse_extensions(extensions);

        match key_share_entries.as_slice() {
            [] => {
                // no keyshare entries
            }
            [entry] => {
                let ks = entry.group;
                keyshare = Some(ks);
            }
            _ => {
                log::warn!(
                    "expected at most one KeyShareEntry, got {}",
                    key_share_entries.len()
                );
            }
        }
    }
    Ok(SessionConfig {
        ciphers: vec![cipher_code],
        keyshare: keyshare.unwrap_or_else(|| {
            log::debug!("Warning: missing keyshare");
            0
        }),
    })
}

struct CryptoConfig {
    ciphers: Vec<u16>,
    keyshare_groups: Vec<u16>,
}

struct SessionConfig {
    ciphers: Vec<u16>,
    keyshare: u16,
}

fn parse_extensions(extensions: &[u8]) -> Vec<KeyShareEntry>{
    let mut pos = 0;
    let mut key_share_entries: Vec<KeyShareEntry> = Vec::new();
    while pos + 4 <= extensions.len() {
		
        // Each extension: type (2 bytes), length (2 bytes)
        let ext_type = u16::from_be_bytes([extensions[pos], extensions[pos+1]]);
        let ext_len = u16::from_be_bytes([extensions[pos+2], extensions[pos+3]]) as usize;
        pos += 4;

        if pos + ext_len > extensions.len() {
            log::debug!("Invalid extension length");
            //return key_share_entries;
        }

        if ext_type == 0x0033 { // key share extension type?
            key_share_entries = parse_key_share(&extensions[pos..pos+ext_len]);
        }
		
		if ext_type == 0x000d { // signature_algorithms extension type
            parse_signature_algorithms(&extensions[pos..pos+ext_len]);
        }
        pos += ext_len;
    }

    key_share_entries
}

fn parse_signature_algorithms(data: &[u8]) {
	log::debug!("parse sig");
    if data.len() < 2 {
        log::debug!("Signature algorithms data too short");
        return;
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + list_len {
        log::debug!("Signature algorithms list length mismatch");
        return;
    }

    let mut pos = 2;
    log::debug!("Signature Algorithms:");
    while pos + 2 <= 2 + list_len {
        let sig_alg = u16::from_be_bytes([data[pos], data[pos+1]]);
		let name = signature_scheme_name(sig_alg);
        log::debug!("  0x{:04x} ({})", sig_alg, name);
        pos += 2;
    }
}

fn parse_key_share(data: &[u8]) -> Vec<KeyShareEntry> {
	log::debug!("parse key share");
	let mut entries = Vec::new();
    if data.len() < 2 {
        log::debug!("key share data too short");
        return entries;
    }

	let mut offset = 0;
    while offset + 4 <= data.len() {
        let group = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let key_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
        offset += 4;

        if offset + key_len > data.len() {
            break;
        }

        let key_exchange = data[offset..offset + key_len].to_vec();
        entries.push(KeyShareEntry { group, key_exchange });

        offset += key_len;
    }
	for entry in &entries {
        log::debug!("Key share entry: {} => {:?}", entry.group, entry.key_exchange);
    }

    entries
}

#[derive(Debug)]
struct KeyShareEntry {
    group: u16,
    key_exchange: Vec<u8>,
}

fn signature_scheme_name(code: u16) -> &'static str {
    match code {
        0x0201 => "rsa_pkcs1_sha1",
        0x0203 => "ecdsa_sha1",
        0x0401 => "rsa_pkcs1_sha256",
        0x0403 => "ecdsa_secp256r1_sha256",
        0x0501 => "rsa_pkcs1_sha384",
        0x0503 => "ecdsa_secp384r1_sha384",
        0x0601 => "rsa_pkcs1_sha512",
        0x0603 => "ecdsa_secp521r1_sha512",
        0x0804 => "rsa_pss_pss_sha256",
        0x0805 => "rsa_pss_pss_sha384",
        0x0806 => "rsa_pss_pss_sha512",
        0x0807 => "ed25519",
        0x0808 => "ed448",
        0x0809 => "rsa_pss_rsae_sha256",
        0x080a => "rsa_pss_rsae_sha384",
        0x080b => "rsa_pss_rsae_sha512",
        0x080c => "ecdsa_brainpoolP256r1tls13_sha256",
        0x080d => "ecdsa_brainpoolP384r1tls13_sha384",
        0x080e => "ecdsa_brainpoolP512r1tls13_sha512",
        0x081a => "dilithium2",
        0x081b => "dilithium3",
        0x081c => "dilithium5",
        0x081d => "falcon512",
        0x081e => "falcon1024",
        0x2a2a => "private_use",  // reserved for private use
        _ => "unknown",
    }
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct TlsSessionKey {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
}
use std::fmt;

impl fmt::Display for TlsSessionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}->{}:{}",
            self.dst_ip, self.dst_port,
            self.src_ip, self.src_port
        )
    }
}