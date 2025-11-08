#![allow(unused)]

use crate::scan::{Scan, ScanResult};
use crate::utils::Target;
use crate::Config;
use anyhow::{anyhow, Result};
use byteorder::{BigEndian, ReadBytesExt};
use chrono::prelude::*;
use rust_embed::RustEmbed;
use serde::Deserialize;
use std::collections::HashMap;
use std::io::{Cursor, Read};
use std::io::{ErrorKind, Seek, SeekFrom};
use std::net::ToSocketAddrs;
use std::sync::Arc;
use tokio::net::{TcpSocket, TcpStream};

use crate::utils::socket_create_and_connect;

#[derive(RustEmbed)]
#[folder = "$CARGO_MANIFEST_DIR/support"]
#[include = "kex_algos.json"]
struct EmbeddedResources;

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct KexAlgo {
    pqc: bool,
    broken: bool,
    hybrid: Option<bool>,
    desc: Option<String>,
    href: Option<String>,
}

#[derive(Default)]
pub struct SshConfig {
    kex_algos: HashMap<String, KexAlgo>,
    pub default_port: u16,
}

impl SshConfig {
    pub fn new() -> SshConfig {
        SshConfig {
            kex_algos: Self::load_kex_algos(),
            default_port: 22,
        }
    }

    fn load_kex_algos() -> HashMap<String, KexAlgo> {
        let json_file = EmbeddedResources::get("kex_algos.json").unwrap();
        let json_data = std::str::from_utf8(json_file.data.as_ref()).unwrap();
        let kex_algos = serde_json::from_str(&json_data).unwrap();
        return kex_algos;
    }
}

struct KexInitMsg {
    kex_algos: Vec<String>,
    host_key_algos: Vec<String>,
}

fn find_pqs_algos(kex_algos: &Vec<String>, kexinit: &KexInitMsg) {
    for kex_algo in &kexinit.kex_algos {
        if kex_algos.contains(&kex_algo) {
            log::debug!("Found PQC algorithm {}", kex_algo);
        }
    }
}

fn parse_ssh_name_list(c: &mut Cursor<&Vec<u8>>) -> Result<Vec<String>> {
    let sz: usize = c.read_u32::<BigEndian>().unwrap().try_into()?;

    let mut buf = vec![0u8; sz];
    c.read_exact(&mut buf)?;
    let algo_str = String::from_utf8(buf)?;

    let mut algos: Vec<String> = vec![];
    for algo in algo_str.split(',').collect::<Vec<_>>() {
        algos.push(algo.to_string());
    }

    Ok(algos)
}

fn parse_ssh_msg_kexinit(buf: &Vec<u8>) -> Result<KexInitMsg> {
    let bl: u32 = buf.len() as u32;
    if bl < 4 {
        return Err(anyhow!("less than 4 bytes in kexinit buf"));
    }
    let mut c = Cursor::new(buf);
    let pkt_size = c.read_u32::<BigEndian>()?;
    if bl - 4 < pkt_size {
        return Err(anyhow!("invalid packet length in kexinit buf"));
    }

    let padding_len: u64 = c.read_u8()?.into();

    /* check if SSH_MSG_KEXINIT (20) */
    let msg_type = c.read_u8()?;
    if msg_type != 20 {
        return Err(anyhow!("invalid SSH packet type"));
    }
    c.seek(SeekFrom::Current(16))?;

    let kex_algos = parse_ssh_name_list(&mut c)?;
    let srv_host_key_algos = parse_ssh_name_list(&mut c)?;
    let enc_algos_c2s = parse_ssh_name_list(&mut c)?;
    let enc_algos_s2c = parse_ssh_name_list(&mut c)?;
    let mac_algos_c2s = parse_ssh_name_list(&mut c)?;
    let mac_algos_s2c = parse_ssh_name_list(&mut c)?;
    let compress_algos_c2s = parse_ssh_name_list(&mut c)?;
    let compress_algos_s2c = parse_ssh_name_list(&mut c)?;
    let lang_c2s = parse_ssh_name_list(&mut c)?;
    let lang_s2c = parse_ssh_name_list(&mut c)?;

    let end_of_pkt = c.position() + padding_len + 5;
    if bl as u64 != end_of_pkt {
        return Err(anyhow!("invalid SSH_KEXINIT packet"));
    }

    Ok(KexInitMsg {
        kex_algos: kex_algos,
        host_key_algos: srv_host_key_algos,
    })
}

async fn ssh_recv_kexinit(stream: &TcpStream) -> Result<KexInitMsg> {
    use tokio::time::{timeout, Duration};

    log::trace!("Receiving SSH_MSG_KEXINIT");

    let read_timeout = Duration::from_secs(10);

    let result = timeout(read_timeout, async {
        let mut buf = [0; 4096];
        loop {
            // Wait for the stream to become readable
            stream
                .readable()
                .await
                .map_err(|e| anyhow!("Stream not readable: {}", e))?;

            match stream.try_read(&mut buf) {
                Ok(0) => {
                    log::trace!("Zero bytes read. Connection closed.");
                    return Err(anyhow!("Connection closed"));
                }
                Ok(n) => {
                    log::trace!("Received {} bytes for KEXINIT", n);
                    return parse_ssh_msg_kexinit(&buf[0..n].to_vec());
                }
                /* try again if we get EAGAIN */
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    log::trace!("WouldBlock - will retry");
                    continue;
                }
                Err(e) => {
                    log::trace!("Error while trying to read kexinit: {}", e);
                    return Err(anyhow!("Read error: {}", e));
                }
            }
        }
    })
    .await;

    match result {
        Ok(Ok(msg)) => Ok(msg),
        Ok(Err(e)) => Err(e),
        Err(_) => {
            log::debug!("Timeout waiting for SSH_MSG_KEXINIT");
            Err(anyhow!("Timeout waiting for SSH_MSG_KEXINIT"))
        }
    }
}

async fn ssh_echoback_idstring(stream: &TcpStream) -> Result<()> {
    /* read SSH identification string and just echo it back to the server so we are always
     * considered compatible. SSH servers MUST send an identification string starting with
     * "SSH-" as per RFC 4253 */

    use tokio::time::{timeout, Duration};

    let read_timeout = Duration::from_secs(5);

    let result = timeout(read_timeout, async {
        loop {
            let readable = stream.readable().await;
            if readable.is_err() {
                log::trace!("Stream not readable");
                return Err(anyhow!("Stream not readable"));
            }

            let mut buf = [0; 4096];
            match stream.try_read(&mut buf) {
                Ok(0) => {
                    log::trace!("Connection closed by peer");
                    return Err(anyhow!("Connection closed"));
                }
                Ok(n) => {
                    log::trace!("SSH: received {} bytes for ID string", n);

                    // Validate that this looks like an SSH server
                    // SSH identification string must start with "SSH-" (RFC 4253)
                    if n < 4 || !buf.starts_with(b"SSH-") {
                        let preview = String::from_utf8_lossy(&buf[0..n.min(50)]);
                        log::debug!("Not an SSH server - received: {:?}", preview);
                        return Err(anyhow!(
                            "Not an SSH server - identification string does not start with 'SSH-'"
                        ));
                    }

                    log::trace!("SSH: validated identification string starts with 'SSH-'");

                    stream
                        .writable()
                        .await
                        .map_err(|e| anyhow!("Stream not writable: {}", e))?;
                    let written = stream
                        .try_write(&buf[0..n])
                        .map_err(|e| anyhow!("Write failed: {}", e))?;
                    log::trace!("SSH: echoed back {} bytes", written);
                    return Ok(());
                }
                /* try again if we get EAGAIN */
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    continue;
                }
                Err(e) => {
                    log::trace!("Error reading ID string: {}", e);
                    return Err(anyhow!("Read error: {}", e));
                }
            }
        }
    })
    .await;

    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(_) => {
            log::debug!("Timeout waiting for SSH ID string");
            Err(anyhow!("Timeout waiting for SSH identification string"))
        }
    }
}

pub async fn ssh_scan_target(config: &Arc<Config>, target: &Target) -> ScanResult {
    log::debug!("SSH scan: connecting to {}", target);

    let ret = socket_create_and_connect(&target, config.connection_timeout).await;
    if ret.is_err() {
        let err = ret.unwrap_err();
        let err_msg = err.to_string();
        log::warn!("SSH scan: connection failed for {} - {}", target, err_msg);
        return ScanResult::Ssh {
            targetspec: target.clone(),
            addr: None,
            error: Some(err_msg),
            pqc_supported: false,
            pqc_algos: None,
            nonpqc_algos: None,
        };
    }
    let (addr, stream) = ret.unwrap();
    log::debug!("SSH scan: connected to {} ({})", target, addr);

    match ssh_echoback_idstring(&stream).await {
        Ok(_) => {
            log::trace!("SSH scan: ID string exchanged with {}", target);
        }
        Err(e) => {
            log::warn!(
                "SSH scan: failed to exchange ID string with {} - {}",
                target,
                e
            );
            return ScanResult::Ssh {
                targetspec: target.clone(),
                addr: Some(addr.to_string()),
                error: Some(format!("Failed to exchange SSH ID string: {}", e)),
                pqc_supported: false,
                pqc_algos: None,
                nonpqc_algos: None,
            };
        }
    }

    let mut pqc_supported = false;
    let mut pqc_algos: Vec<String> = vec![];
    let mut nonpqc_algos: Vec<String> = vec![];

    match ssh_recv_kexinit(&stream).await {
        Err(e) => {
            log::warn!("SSH scan: unexpected response from {} - {}", target, e);
        }
        Ok(ki) => {
            log::debug!(
                "SSH scan: received KEXINIT from {}, {} algorithms advertised",
                target,
                ki.kex_algos.len()
            );
            let kex_algos = &config.ssh_config.kex_algos;

            for k in ki.kex_algos {
                match kex_algos.get(&k) {
                    None => {
                        log::warn!("Unknown SSH algorithm {} found on {}", k, target);
                    }
                    Some(a) => {
                        if a.pqc {
                            log::info!("SSH scan: {} supports PQC algorithm: {}", target, k);
                            pqc_supported = true;
                            pqc_algos.push(k);
                        } else {
                            log::trace!("SSH scan: {} supports non-PQC algorithm: {}", target, k);
                            nonpqc_algos.push(k);
                        }
                    }
                }
            }
        }
    }

    log::debug!(
        "SSH scan: finished scanning {} (PQC supported: {})",
        target,
        pqc_supported
    );
    let ret = ScanResult::Ssh {
        targetspec: target.clone(),
        addr: Some(addr.to_string()),
        error: None,
        pqc_supported: pqc_supported,
        pqc_algos: Some(pqc_algos),
        nonpqc_algos: Some(nonpqc_algos),
    };
    return ret;
}
