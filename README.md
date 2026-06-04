# pqcutils - Post-Quantum Cryptography Utilities

A collection of tools for auditing Post-Quantum Cryptography (PQC) support in SSH and TLS traffic, written in Rust by [Anvil Secure](https://anvilsecure.com).

The [USA](https://www.keyfactor.com/blog/nist-drops-new-deadline-for-pqc-transition/), [EU](https://digital-strategy.ec.europa.eu/en/library/recommendation-coordinated-implementation-roadmap-transition-post-quantum-cryptography) and [UK](https://www.ncsc.gov.uk/news/pqc-migration-roadmap-unveiled) have all set deadlines for phasing out non-PQC algorithms completely between 2030–2035. These tools help system administrators and infosec practitioners identify assets in their networks that do not yet support Post-Quantum Cryptography. A great overview about PQC for engineers is being [drafted](https://www.ietf.org/archive/id/draft-ietf-pquip-pqc-engineers-12.html) by the IETF.

---

## Tools

### [pqcscan](pqcscan/) — Active Scanner

**pqcscan** actively connects to SSH and TLS servers and queries their advertised PQC support. Provide a list of hostnames or IPs and choose the scan type; results are written to JSON and can be combined into an HTML report.

```
pqcscan tls-scan -t gmail.com:443 -o gmail.json
pqcscan ssh-scan -T targets.txt -o ssh.json
pqcscan create-report -i gmail.json ssh.json -o report.html
```

Use pqcscan when you want to probe live hosts across your network.

### [pqcdump](pqcdump/) — Passive PCAP Analyzer

**pqcdump** analyzes existing PCAP capture files and identifies all observed hosts and sessions, determining whether PQC algorithms were used or supported in their SSH and TLS handshakes. Output is a self-contained HTML report.
=======
To generate CSV, JSON or XML output for spreadsheet import, asset inventory or
automation workflows, set the report format explicitly:

```
pqcscan create-report -i gmail.json cloudflare.json --format csv -o report.csv
pqcscan create-report -i gmail.json cloudflare.json --format json -o report.json
pqcscan create-report -i gmail.json cloudflare.json --format xml -o report.xml
```

You can also create a target list in a file and supply it via `-T`. This works for both `tls-scan` and `ssh-scan`.

```
pqcdump capture.pcapng
pqcdump capture.pcapng -o report.html
```

Use pqcdump when you already have captured traffic and want to audit PQC adoption without sending any probes.

---

## Building

Both tools are standard Rust crates. Clone the repository and build the one you need:

```
git clone https://github.com/anvilsecure/pqcutils.git
cd pqcutils/pqcscan && cargo build --release
cd pqcutils/pqcdump && cargo build --release
```

Binary releases for Linux, macOS, and Windows are available on the [releases](https://github.com/anvilsecure/pqcutils/releases) page.

## License

BSD — see [LICENSE](LICENSE).

## Contact

All input is welcome via GitHub issues and pull requests. You can also email the principal authors and maintainer, Vincent Berg, at *gvb@anvilsecure.com* and Nicholas O'Shea at *nicholas.oshea@anvilsecure.com*.
