use std::sync::Arc;

use crate::config::Config;
use crate::scan::ScanResult;
use crate::utils::Target;

use anyhow::{anyhow, Result};
use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use rand::{rng, Rng};
use rust_embed::RustEmbed;
use serde::Deserialize;
use std::collections::HashMap;
use std::io::{Cursor, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::tlsconstants::TlsAlerts;
use crate::utils::socket_create_and_connect;

#[derive(RustEmbed)]
#[folder = "$CARGO_MANIFEST_DIR/support"]
#[include = "tls_groups.json"]
#[include = "tls_cipher_suites.json"]
#[include = "tls_sig_schemes.json"]
struct EmbeddedResources;

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct TlsGroup {
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

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct TlsCipherSuite {
    pub cipher_suite_id: u16,
    #[allow(dead_code)] // currently not used
    obsolete: bool,
    #[allow(dead_code)] // currently not used
    insecure: bool,
    #[allow(dead_code)] // currently not used
    desc: String,
    #[allow(dead_code)] // currently not used
    href: String,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct TlsSigScheme {
    pub sig_scheme_id: u16,
    #[allow(dead_code)] // currently not used
    obsolete: bool,
    #[allow(dead_code)] // currently not used
    insecure: bool,
    #[allow(dead_code)] // currently not used
    desc: String,
    #[allow(dead_code)] // currently not used
    href: String,
}

struct Extension {
    pub ext_type: u16,
    pub ext_len: u16,
    pub payload: Vec<u8>,
}

struct KeyShareEntry {
    group: u16,
    exchange_len: u16,
    exchange: Vec<u8>,
}

pub struct TlsConfig {
    pub default_port: u16,
    pub groups: HashMap<String, TlsGroup>,
    #[allow(dead_code)] // will be used in future
    pub cipher_suites: HashMap<String, TlsCipherSuite>,
    #[allow(dead_code)] // will be used in future
    pub sig_schemes: HashMap<String, TlsSigScheme>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsConfig {
    pub fn new() -> TlsConfig {
        TlsConfig {
            default_port: 443,
            groups: Self::load_groups(),
            cipher_suites: Self::load_cipher_suites(),
            sig_schemes: Self::load_sig_schemes(),
        }
    }

    fn load_groups() -> HashMap<String, TlsGroup> {
        let json_file = EmbeddedResources::get("tls_groups.json").unwrap();
        let json_data = std::str::from_utf8(json_file.data.as_ref()).unwrap();
        let groups = serde_json::from_str(&json_data).unwrap();
        return groups;
    }

    fn load_cipher_suites() -> HashMap<String, TlsCipherSuite> {
        let json_file = EmbeddedResources::get("tls_cipher_suites.json").unwrap();
        let json_data = std::str::from_utf8(json_file.data.as_ref()).unwrap();
        let cipher_suites = serde_json::from_str(&json_data).unwrap();
        return cipher_suites;
    }

    fn load_sig_schemes() -> HashMap<String, TlsSigScheme> {
        let json_file = EmbeddedResources::get("tls_sig_schemes.json").unwrap();
        let json_data = std::str::from_utf8(json_file.data.as_ref()).unwrap();
        let sig_schemes = serde_json::from_str(&json_data).unwrap();
        return sig_schemes;
    }
}

impl KeyShareEntry {
    #![allow(dead_code)]
    pub fn new(group: u16, exchange: Vec<u8>) -> KeyShareEntry {
        KeyShareEntry {
            group: group,
            exchange_len: exchange.len() as u16,
            exchange: exchange,
        }
    }
}

impl Extension {
    fn server_name(hostname: &str) -> Result<Extension> {
        let mut buf: Vec<u8> = vec![];

        let hb = hostname.as_bytes();
        let hblen: u16 = hb.len().try_into()?;

        buf.write_u16::<NetworkEndian>(hblen + 3)?;
        buf.write_u8(0)?;
        buf.write_u16::<NetworkEndian>(hblen)?;
        buf.write(&hb)?;

        Ok(Extension {
            ext_type: 0,
            ext_len: buf.len().try_into()?,
            payload: buf,
        })
    }

    fn supported_versions() -> Result<Extension> {
        let mut buf: Vec<u8> = vec![];
        buf.write_u8(2)?;
        buf.write_u16::<NetworkEndian>(0x0304)?; /* TLS 1.3 */
        Ok(Extension {
            ext_type: 43,
            ext_len: 3,
            payload: buf,
        })
    }

    fn record_size_limit(limit: u16) -> Result<Extension> {
        let mut buf: Vec<u8> = vec![];
        buf.write_u16::<NetworkEndian>(limit)?;
        Ok(Extension {
            ext_type: 28,
            ext_len: 2,
            payload: buf,
        })
    }

    fn supported_groups(groups: Vec<u16>) -> Result<Extension> {
        let mut buf: Vec<u8> = vec![];
        let g_len: u16 = (groups.len() * 2).try_into()?;
        buf.write_u16::<NetworkEndian>(g_len)?;
        for group in groups {
            buf.write_u16::<NetworkEndian>(group)?;
        }
        Ok(Extension {
            ext_type: 10,
            ext_len: buf.len().try_into()?,
            payload: buf,
        })
    }

    fn signature_algorithms(algos: Vec<u16>) -> Result<Extension> {
        let mut buf: Vec<u8> = vec![];
        let ha_len: u16 = (algos.len() * 2).try_into()?;
        buf.write_u16::<NetworkEndian>(ha_len)?;
        for algo in algos {
            buf.write_u16::<NetworkEndian>(algo)?;
        }
        Ok(Extension {
            ext_type: 13,
            ext_len: buf.len().try_into()?,
            payload: buf,
        })
    }

    fn empty_extension(ext_type: u16) -> Result<Extension> {
        let buf: Vec<u8> = vec![];
        Ok(Extension {
            ext_type: ext_type,
            ext_len: 0,
            payload: buf,
        })
    }

    fn signed_certificate_timestamp() -> Result<Extension> {
        Self::empty_extension(18)
    }

    fn extended_master_secret() -> Result<Extension> {
        Self::empty_extension(23)
    }

    fn compress_certificate() -> Result<Extension> {
        let mut buf: Vec<u8> = vec![];
        buf.write_u8(6)?;
        buf.write_u16::<NetworkEndian>(0x1)?; /* zlib */
        buf.write_u16::<NetworkEndian>(0x2)?; /* brotli */
        buf.write_u16::<NetworkEndian>(0x3)?; /* zstd */

        Ok(Extension {
            ext_type: 27,
            ext_len: buf.len().try_into()?,
            payload: buf,
        })
    }

    fn renegotiation_info() -> Result<Extension> {
        let mut buf: Vec<u8> = vec![];
        buf.write_u8(0)?;

        Ok(Extension {
            ext_type: 65281,
            ext_len: buf.len().try_into()?,
            payload: buf,
        })
    }

    fn ec_point_formats() -> Result<Extension> {
        let mut buf: Vec<u8> = vec![];
        buf.write_u8(1)?;
        buf.write_u8(0)?;

        Ok(Extension {
            ext_type: 11,
            ext_len: buf.len().try_into()?,
            payload: buf,
        })
    }

    fn status_request() -> Result<Extension> {
        /*
         * Default is to ask for status_request of:
         * - OCSP certificate status: OCSP (1)
         * - Responder ID list length: 0
         * - Request Extensions Length: 0
         */
        Ok(Extension {
            ext_type: 5,
            ext_len: 5,
            payload: vec![1, 0, 0, 0, 0],
        })
    }

    fn key_share(keyshares: &Vec<KeyShareEntry>) -> Result<Extension> {
        let mut buf: Vec<u8> = vec![];

        let mut keyshare_len: u16 = 0;
        for keyshare in keyshares {
            keyshare_len = keyshare_len + keyshare.exchange_len + 4;
        }

        buf.write_u16::<NetworkEndian>(keyshare_len)?;
        for keyshare in keyshares {
            buf.write_u16::<NetworkEndian>(keyshare.group)?;
            buf.write_u16::<NetworkEndian>(keyshare.exchange_len)?;
            buf.write(&keyshare.exchange)?;
        }

        Ok(Extension {
            ext_type: 51,
            ext_len: buf.len().try_into()?,
            payload: buf,
        })
    }
}

pub struct ClientHelloBuilder {
    legacy_version: u16,
    random: [u8; 32],
    session_id: Vec<u8>,
    cipher_suites: Vec<u16>,
    compression_methods: Vec<u8>,
    extensions_len: u16,
    extensions: Vec<Extension>,
}

impl ClientHelloBuilder {
    fn new() -> ClientHelloBuilder {
        let mut random: [u8; 32] = [0; 32];
        rng().fill(&mut random[..]);

        /*
          generate 32 bytes of random session id data. In TLS 1.3 session
          resume works via PSK (pre-shared keys), but this keeps some annoying middleware
          kboxes of our back as it will "disguise" 1.3 sessions as resumed 1.2 sessions.
        */
        const SESSION_ID_LEN: usize = 32;
        let mut session_id: [u8; SESSION_ID_LEN] = [0; SESSION_ID_LEN];
        rng().fill(&mut session_id);

        ClientHelloBuilder {
            legacy_version: 0x0303,
            random: random,
            session_id: session_id.to_vec(),
            cipher_suites: Vec::<u16>::new(),
            compression_methods: Vec::<u8>::new(),
            extensions_len: 0,
            extensions: Vec::<Extension>::new(),
        }
    }

    fn into_buf(&self) -> Result<Vec<u8>> {
        let mut buf: Vec<u8> = vec![];

        buf.write_u16::<NetworkEndian>(self.legacy_version)?;
        buf.write(&self.random)?;
        buf.write_u8(self.session_id.len().try_into()?)?;
        buf.write(&self.session_id)?;

        let cslen: u16 = (self.cipher_suites.len() * 2).try_into()?;
        buf.write_u16::<NetworkEndian>(cslen)?;
        for cs in &self.cipher_suites {
            buf.write_u16::<NetworkEndian>(*cs)?;
        }

        buf.write_u8(self.compression_methods.len().try_into()?)?;
        for cm in &self.compression_methods {
            buf.write_u8(*cm)?;
        }

        buf.write_u16::<NetworkEndian>(self.extensions_len)?;
        for ext in &self.extensions {
            buf.write_u16::<NetworkEndian>(ext.ext_type)?;
            buf.write_u16::<NetworkEndian>(ext.ext_len)?;
            buf.write(&ext.payload)?;
        }

        let buflen: u16 = buf.len().try_into()?;

        /* now setup the record layer header */

        // XXX: this is another copy of the Vec, maybe we can use a slice
        // above or otherwise a Cursor to not have to do this copy

        let mut preamble: Vec<u8> = vec![];
        preamble.write_u8(22)?;
        preamble.write_u16::<NetworkEndian>(0x0301)?;
        preamble.write_u16::<NetworkEndian>(buflen + 4)?;
        preamble.write_u8(1)?; /* Client Hello */
        preamble.write_u8(0)?;
        preamble.write_u16::<NetworkEndian>(buflen)?;
        preamble.write(&buf)?;

        Ok(preamble.to_vec())
    }

    fn add_extension(&mut self, extension: Extension) {
        self.extensions_len = self.extensions_len + extension.ext_len + 4;
        self.extensions.push(extension);
    }

    fn add_compression_method(&mut self, method: u8) {
        self.compression_methods.push(method);
    }

    fn add_cipher_suite(&mut self, cipher_suite: u16) {
        self.cipher_suites.push(cipher_suite);
    }
}

fn tls_connect_with_group(
    stream: &mut TcpStream,
    host: &str,
    group: u16,
    group_name: &str,
    config: &Arc<Config>,
) -> Result<()> {
    log::trace!("TLS: attempting handshake with group {}", group_name);

    // Load cipher suites from JSON configuration
    let ciphers: Vec<u16> = config
        .tls_config
        .cipher_suites
        .values()
        .map(|cs| cs.cipher_suite_id)
        .collect();

    let groups = vec![group];

    // Load signature schemes from JSON configuration
    let sigschemes: Vec<u16> = config
        .tls_config
        .sig_schemes
        .values()
        .map(|ss| ss.sig_scheme_id)
        .collect();

    let keyshares: Vec<KeyShareEntry> = vec![];

    let mut chb = ClientHelloBuilder::new();
    for cipher in ciphers {
        chb.add_cipher_suite(cipher);
    }
    chb.add_compression_method(0);
    chb.add_extension(Extension::server_name(host)?);
    chb.add_extension(Extension::supported_versions()?);
    chb.add_extension(Extension::signature_algorithms(sigschemes)?);
    chb.add_extension(Extension::status_request()?);
    chb.add_extension(Extension::supported_groups(groups)?);
    chb.add_extension(Extension::key_share(&keyshares)?);
    chb.add_extension(Extension::record_size_limit(16385)?);
    chb.add_extension(Extension::signed_certificate_timestamp()?);
    chb.add_extension(Extension::extended_master_secret()?);
    chb.add_extension(Extension::compress_certificate()?);
    chb.add_extension(Extension::renegotiation_info()?);
    chb.add_extension(Extension::ec_point_formats()?);

    log::trace!("TLS: sending ClientHello");
    stream.write(&chb.into_buf()?)?;
    let mut buf: [u8; 5000] = [0; 5000];

    log::trace!("TLS: waiting for ServerHello");
    let read = stream.read(&mut buf)?;
    log::trace!("TLS: received {} bytes", read);
    let mut cursor = Cursor::new(buf);

    let content_type = cursor.read_u8()?;

    if content_type == 0x16 {
        /* TLS Handshake message received */
        if read < 5 {
            return Err(anyhow!("Too short TLS Handshake record received"));
        }
        let version = cursor.read_u16::<NetworkEndian>()?;
        if version != 0x0303 {
            return Err(anyhow!("Expected TLS 1.2 (0x0303) version number"));
        }
        let record_length = cursor.read_u16::<NetworkEndian>()?;
        let handshake_type = cursor.read_u8()?;
        if handshake_type != 0x2 {
            return Err(anyhow!("Expected Server Hello as first record"));
        }
        let handshake_length = cursor.read_u24::<NetworkEndian>()?;
        if handshake_length + 4 != record_length as u32 {
            return Err(anyhow!("record length != handshake length + 4"));
        }
        let version = cursor.read_u16::<NetworkEndian>()?;
        if version != 0x0303 {
            return Err(anyhow!("Expected TLS 1.2 (0x0303) version number"));
        }
        log::trace!("TLS: ServerHello handshake successful");
        return Ok(());
    } else if content_type == 0x15 {
        log::trace!("TLS: received Alert message");
        /* TLS Alert record received*/
        if read < 5 {
            return Err(anyhow!("Too short TLS Alert record received"));
        }
        let version = cursor.read_u16::<NetworkEndian>()?;
        if version != 0x0303 {
            return Err(anyhow!("Expected TLS 1.2 (0x0303) version number"));
        }
        let length = cursor.read_u16::<NetworkEndian>()?;
        if length != 0x2 {
            return Err(anyhow!("Expected TLS Alert record length of 2"));
        }
        let level = cursor.read_u8()?;
        if level != 0x2 {
            return Err(anyhow!("TLS Alert record received with non-FATAL level"));
        }
        let desc = cursor.read_u8()?;
        if TlsAlerts.contains_key(&desc) {
            return Err(anyhow!("{}", TlsAlerts[&desc]));
        }
        return Err(anyhow!("Unknown TLS Alert code: {:#02x}", desc));
    } else {
        return Err(anyhow!("Unexpected TLS content type != [0x15, 0x16]"));
    }
}

pub async fn tls_scan_target(
    config: &Arc<Config>,
    target: &Target,
    hybrid_algos_only: bool,
    scan_nonpqc_algos: bool,
) -> ScanResult {
    log::debug!("TLS scan: starting scan of {}", target);

    let mut pqc_supported = false;
    let mut pqc_algos: Vec<String> = vec![];
    let mut hybrid_algos: Vec<String> = vec![];
    let mut nonpqc_algos: Vec<String> = vec![];

    // Build list of groups to test from the configuration
    let mut groups_to_test: Vec<(String, &TlsGroup)> = vec![];

    for (name, group) in &config.tls_config.groups {
        // If hybrid_algos_only is set, only test hybrid algorithms
        if hybrid_algos_only && !group.hybrid {
            continue;
        }
        // Only test PQC algorithms
        if group.pqc {
            groups_to_test.push((name.clone(), group));
        } else if scan_nonpqc_algos {
            // If scan_nonpqc_algos is set, also test non-PQC algorithms
            groups_to_test.push((name.clone(), group));
        }
    }

    log::debug!(
        "TLS scan: testing {} group(s) on {}",
        groups_to_test.len(),
        target
    );

    let mut addr: Option<String> = None;

    for (group_name, group_info) in groups_to_test {
        log::trace!("TLS scan: testing group {} on {}", group_name, target);
        let ret = socket_create_and_connect(&target, config.connection_timeout).await;
        if ret.is_err() {
            let err = ret.unwrap_err();
            let err_msg = err.to_string();
            log::warn!("TLS scan: connection failed for {} - {}", target, err_msg);
            return ScanResult::Tls {
                targetspec: target.clone(),
                addr: None,
                error: Some(err_msg),
                pqc_supported: false,
                pqc_algos: None,
                hybrid_algos: None,
                nonpqc_algos: None,
            };
        }
        let (_addr, stream) = ret.unwrap();
        if addr.is_none() {
            addr = Some(_addr.to_string());
            log::debug!("TLS scan: connected to {} ({})", target, _addr);
        }
        let mut stream = stream.into_std().unwrap();
        stream.set_nonblocking(false).unwrap();
        let res = stream.set_read_timeout(Some(Duration::from_secs(config.read_timeout)));
        if res.is_err() {
            log::warn!(
                "Error while setting read timeout for socket to {0}s",
                config.read_timeout
            );
        } else {
            log::trace!("Set read timeout for socket to {0}s", config.read_timeout);
        }

        let ret = tls_connect_with_group(
            &mut stream,
            &target.host,
            group_info.group_id,
            &group_name,
            config,
        );
        match ret {
            Ok(_) => {
                if group_info.pqc && !group_info.hybrid {
                    log::info!(
                        "TLS scan: {} supports PQC algorithm: {}",
                        target,
                        group_name
                    );
                    pqc_supported = true;
                    pqc_algos.push(group_name.clone());
                } else if group_info.pqc {
                    log::info!(
                        "TLS scan: {} supports hybrid PQC algorithm: {}",
                        target,
                        group_name
                    );
                    pqc_supported = true;
                    hybrid_algos.push(group_name.clone());
                } else {
                    log::info!(
                        "TLS scan: {} supports non-PQC algorithm: {}",
                        target,
                        group_name
                    );
                    nonpqc_algos.push(group_name.clone());
                }
            }
            Err(e) => {
                log::trace!(
                    "TLS scan: {} does not support {} - {}",
                    target,
                    group_name,
                    e
                );
            }
        }
    }

    log::debug!(
        "TLS scan: finished scanning {} (PQC supported: {})",
        target,
        pqc_supported
    );
    let ret = ScanResult::Tls {
        targetspec: target.clone(),
        addr: addr,
        error: None,
        pqc_supported: pqc_supported,
        pqc_algos: Some(pqc_algos),
        hybrid_algos: Some(hybrid_algos),
        nonpqc_algos: Some(nonpqc_algos),
    };
    return ret;
}
