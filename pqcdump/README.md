# pqcdump - Post-Quantum Cryptography PCAP Scanner

*Analyze PCAP files for PQC support in SSH and TLS traffic*

# Overview

**pqcdump** is a small utility, written in Rust, that analyzes PCAP capture files to identify hosts and established sessions, determining whether Post-Quantum Cryptography (PQC) algorithms are used or supported in TLS and SSH handshakes. Results are written to a self-contained HTML report that can be viewed in any web browser.

It complements active scanning tools like [pqcscan](https://github.com/anvilsecure/pqcscan) by working passively on existing captures — useful when you already have network traffic and want to audit PQC adoption without sending any probes. It might help system administrators and infosec practitioners identify assets in their networks that do not yet support Post-Quantum Cryptography. The [USA](https://www.keyfactor.com/blog/nist-drops-new-deadline-for-pqc-transition/), [EU](https://digital-strategy.ec.europa.eu/en/library/recommendation-coordinated-implementation-roadmap-transition-post-quantum-cryptography) and [UK](https://www.ncsc.gov.uk/news/pqc-migration-roadmap-unveiled) have all set deadlines for phasing out non-PQC algorithms completely between 2030–2035. A great overview about PQC for engineers is being [drafted](https://www.ietf.org/archive/id/draft-ietf-pquip-pqc-engineers-12.html) by the IETF.

Regarding supported algorithms:

- **SSH**: KEX (key exchange) PQC algorithms are identified based on [OpenSSH](https://www.openssh.com/) and [OQS-OpenSSH](https://github.com/open-quantum-safe/openssh), including hybrid and experimental algorithms.

- **TLS**: All common and standardized PQC-hybrid and pure PQC key share groups are identified, along with TLS cipher suites. TLS 1.2 sessions are noted separately.

## Bugs, comments, suggestions

The code should be somewhat idiomatic Rust, but there will be plenty of ways to improve it. All input is welcome — send pull requests or file bugs/issues via GitHub. You are also welcome to directly email the principal author and maintainer, Nicholas O'Shea, at *nicholas.oshea@anvilsecure.com*.

# Installation

## Binary Releases

There are binary releases for Linux, macOS and Windows on common architectures on the [releases](https://github.com/anvilsecure/pqcutils/releases) page. Download the archive, unzip to your desired location, and run the extracted binary from your shell.

## Building from source

The implementation is straightforward Rust. Clone the git repository and then run:

```
git clone https://github.com/anvilsecure/pqcutils.git
cd pqcutils/pqcdump
cargo build --release
./target/release/pqcdump --help
```

# Usage

Provide a PCAP file to analyze and an optional output path for the HTML report (defaults to `results.html`):

```
pqcdump capture.pcapng
pqcdump capture.pcapng -o report.html
```

The report includes:

- A summary of all observed hosts and their PQC support status
- SSH host capabilities (advertised KEX algorithms)
- SSH negotiated sessions and the algorithm actually used
- TLS host capabilities (advertised key share groups)
- TLS negotiated sessions and the group actually used

To get more verbose output, use the Rust [log levels](https://docs.rs/env_logger/latest/env_logger/):

```
RUST_LOG=debug pqcdump capture.pcapng
[DEBUG pqcdump] link: ...
[DEBUG pqcdump] This may be an SSH_MSG_KEXINIT message
...
[INFO  pqcdump] === Host Capabilities ===
[INFO  pqcdump] 192.168.1.1
[INFO  pqcdump]   sntrup761x25519-sha512@openssh.com true
...
```
