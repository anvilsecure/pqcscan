use crate::ssh::SshConfig;
use crate::tls::TlsConfig;

#[derive(Default)]
pub struct Config {
    pub ssh_config: SshConfig,
    pub tls_config: TlsConfig,

    /* connection timeout in seconds */
    pub connection_timeout: u64,
    /* read timeout in seconds */
    pub read_timeout: u64
}

impl Config {
    pub fn new() -> Config {
        let cfg = Config {
            ssh_config: SshConfig::new(),
            tls_config: TlsConfig::new(),
            connection_timeout: 5,
            read_timeout: 10,
        };

        return cfg;
    }
}
