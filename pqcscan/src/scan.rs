use crate::Target;
use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::ssh::ssh_scan_target;
use crate::tls::tls_scan_target;
use crate::Config;

#[derive(Serialize, Deserialize, Clone)]
pub enum ScanResult {
    Ssh {
        targetspec: Target,
        addr: Option<String>,
        error: Option<String>,
        pqc_supported: bool,
        pqc_algos: Option<Vec<String>>,
        nonpqc_algos: Option<Vec<String>>,
    },
    Tls {
        targetspec: Target,
        addr: Option<String>,
        error: Option<String>,
        pqc_supported: bool,
        pqc_algos: Option<Vec<String>>,
        hybrid_algos: Option<Vec<String>>,
        nonpqc_algos: Option<Vec<String>>,
    },
    Done,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Scan {
    pub results: Vec<ScanResult>,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub version: String,
    pub scan_type: ScanType,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
pub enum ScanType {
    Ssh,
    Tls,
}

pub struct ScanOptions {
    pub num_threads: usize,
    pub targets: Vec<Target>,
    pub scan_type: Option<ScanType>,
    pub scan_hybrid_algos_only: bool,
    pub scan_nonpqc_algos: bool,
}

pub async fn scan_runner(config: Arc<Config>, scan: ScanOptions) -> Scan {
    log::debug!("Scan runner initialized");
    let (tx, rx_orig) = async_channel::unbounded();
    let (results_tx_orig, results_rx) = async_channel::unbounded();
    let targets_cnt = scan.targets.len();

    /* no need to have more threads than targets */
    let mut num_threads = scan.num_threads;
    if num_threads > targets_cnt {
        num_threads = targets_cnt;
        log::debug!(
            "Adjusted thread count to {} (matching target count)",
            num_threads
        );
    }

    let start_time = Utc::now();
    log::info!(
        "Scan started at {}",
        start_time.format("%Y-%m-%d %H:%M:%S UTC")
    );

    /* send all targets into the channel and end with
     * empty targets as a signal for the tasks to exit
     * cleanly. */
    log::debug!("Queuing {} targets for scanning", targets_cnt);
    for target in scan.targets {
        log::trace!("Sending {}", target);
        if let Err(_) = tx.send(target).await {
            log::error!("thread dropped");
        }
    }
    for _ in 0..num_threads {
        if let Err(_) = tx
            .send(Target {
                host: "".to_string(),
                port: 0,
            })
            .await
        {
            log::error!("Thread dropped");
        }
    }

    log::debug!("Spawning {} scan threads", num_threads);
    for no in 1..num_threads + 1 {
        log::trace!("Spawning Scan Thread {}", no);

        let rx = rx_orig.clone();
        let results_tx = results_tx_orig.clone();
        let config = config.clone();
        tokio::spawn(async move {
            loop {
                while let Ok(target) = rx.recv().await {
                    /* empty host for a Target means we are asked to quit */
                    if target.host.len() == 0 {
                        log::trace!("Exit requested for Scan Thread {}", no);
                        let _ = results_tx.send(ScanResult::Done).await;
                        break;
                    }

                    log::debug!("Thread {} scanning target: {}", no, target);
                    let scan_type = scan.scan_type.clone().unwrap();
                    let result = match scan_type {
                        ScanType::Tls => {
                            tls_scan_target(
                                &config,
                                &target,
                                scan.scan_hybrid_algos_only,
                                scan.scan_nonpqc_algos,
                            )
                            .await
                        }
                        ScanType::Ssh => ssh_scan_target(&config, &target).await,
                    };
                    let _ = results_tx.send(result).await;
                }

                log::trace!("Exiting Scan Thread {}", no);
                break;
            }
        });
    }

    log::debug!("Collecting scan results from all threads");
    let mut results: Vec<ScanResult> = vec![];
    let mut completed_scans = 0;

    while let Ok(result) = results_rx.recv().await {
        match result {
            ScanResult::Done => {
                num_threads -= 1;
                log::debug!("Thread completed. {} thread(s) remaining", num_threads);
                if num_threads == 0 {
                    break;
                }
            }
            _ => {
                completed_scans += 1;
                if completed_scans % 10 == 0 {
                    log::info!("Progress: {} scans completed", completed_scans);
                }
                results.push(result);
            }
        }
    }

    let end_time = Utc::now();
    log::info!(
        "Scan finished at {}",
        end_time.format("%Y-%m-%d %H:%M:%S UTC")
    );
    log::info!("Total scans completed: {}", completed_scans);

    let scan = Scan {
        results: results,
        start_time: start_time,
        end_time: Utc::now(),
        version: clap::crate_version!().to_string(),
        scan_type: scan.scan_type.unwrap(),
    };

    log::info!("Done scanning. All threads exited.");

    return scan;
}
