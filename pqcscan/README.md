# pqcscan - Post-Quantum Cryptography Scanner

*Scan SSH/TLS servers for PQC support*

# Overview

**pqcscan** is a small utility, written in Rust, that allows users to scan SSH and TLS servers for their stated support of Post-Quantum Cryptography algorithms. Scan results are written to JSON files. One or more of these result files can be converted into an easily digestible HTML report that can be viewed with a web browser. For sample screenshots look below in this README.

It might help system administrators and infosec practitioners with identifying those assets in their networks that do not support Post-Quantum Cryptography yet. The [USA](https://www.keyfactor.com/blog/nist-drops-new-deadline-for-pqc-transition/), [EU](https://digital-strategy.ec.europa.eu/en/library/recommendation-coordinated-implementation-roadmap-transition-post-quantum-cryptography) and [UK](https://www.ncsc.gov.uk/news/pqc-migration-roadmap-unveiled) have all set deadlines for phasing out non-PQC algorithms completely in between 2030-2035. A great overview about PQC for Engineers is being [drafted](https://www.ietf.org/archive/id/draft-ietf-pquip-pqc-engineers-12.html) by the IETF. It is our hope this initial version of pqcscan can help. Other scanners might, or already have, integrated such support too but having a dedicated tool focussed on one task might be more desirable at times.

To scan simply provide a list of hostnames/IPs and port numbers and chose the type of scan (SSH or TLS). Regarding the supported algorithms that can be identified:

- The list of SSH KEX (key exchange) PQC algorithms was manually put together based on [OpenSSH](https://www.openssh.com/), as well as [OQS-OpenSSH](https://github.com/open-quantum-safe/openssh). A lot of those algorithms are experimental algorithms and will hopefully never be encountered in production but they are useful for testing the tool and seeing if someone is deploying experimental algorithms in production in practice somewhere.
 
- For TLS the tool can identify all common and standardized PQC-hybrid and PQC algorithms. Experimental algorithms are right now not supported due to the increase in scanning time. These might be added in the future.
 
## Bugs, comments, suggestions
The code should be somewhat idiomatic Rust, but there will be tons of ways to improve it. From the way the HTML files are now built up and generated to other smaller issues. For more information see the `TODO` file in the repository. All input is welcome! Just send in direct pull requests or bugs/issues via GitHub. You are also welcome to directly email the principal author and maintainer, Vincent Berg, at *gvb@anvilsecure.com*.
 
# Installation

## Binary Releases
There are binary releases for Linux, MacOS and Windows on common architectures on the [releases](https://github.com/anvilsecure/pqcscan/releases) page. Download the files, unzip to your desired location, and run the extracted binary from your shell.

## Building from source
The implementation is straight forward Rust. You can download a tagged version's source distribution from the [releases](https://github.com/anvilsecure/pqcscan/releases) page. Or simply clone the git repository and then run:

```
git clone https://github.com/anvilsecure/pqcscan.git
cd pqcscan
cargo build --release
./target/release/pqcscan --help
```

# Usage

To TLS scan two hosts and combine it in one report do something like the following:

```
pqcscan tls-scan -t gmail.com:443 -o gmail.json
pqcscan tls-scan -t pq.cloudflareresearch.com:443 -o cloudflare.json
pqcscan create-report -i gmail.json cloudflare.json -o report.html
```

You can also create a target list in a file and supply it via `-T`. This works for both `tls-scan` and `ssh-scan`.

```
echo github.com > targets
echo 100.126.128.144 >> targets
pqcscan ssh-scan -T targets -o ssh.json
pqcscan create-report -i ssh.json -o report.html
```

To get more feedback what is going on just the Rust [loglevels](https://docs.rs/env_logger/latest/env_logger/).

```
RUST_LOG=debug pqcscan ssh-scan -T targets -o ssh.json
[2025-06-20T07:49:35Z DEBUG pqcscan::ssh] Started SSH scanning github.com:22
[2025-06-20T07:49:35Z DEBUG pqcscan::ssh] Started SSH scanning 100.126.128.144:22
[2025-06-20T07:49:35Z DEBUG pqcscan::ssh] PQC Algorithm supported: sntrup761x25519-sha512
[2025-06-20T07:49:35Z DEBUG pqcscan::ssh] PQC Algorithm supported: sntrup761x25519-sha512@openssh.com
[2025-06-20T07:49:35Z DEBUG pqcscan::ssh] Non-PQC Algorithm supported: curve25519-sha256
[2025-06-20T07:49:35Z DEBUG pqcscan::ssh] Non-PQC Algorithm supported: curve25519-sha256@libssh.org
...
[2025-06-20T07:49:35Z INFO  pqcscan::scan] Done scanning. All threads exited.
```

For configuring the number of scan threads and other options just use `--help`. 


# Screenshots

## Main Scan Results Overview

![Example Scan Results Main Overview](/doc/pqcscan_results_sample1.png)

## SSH Scan Results Sample

![SSH Scan Results Sample](/doc/sshscan_results_sample1.png)

## TLS Scan Results Sample

![TLS Scan Results Sample](/doc/tlsscan_results_sample1.png)
