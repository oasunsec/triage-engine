<div align="center">

# Log Parser v4

### Windows Event Log Threat Hunting Engine

**CrowdStrike-inspired behavioral IOA detection with kill-chain correlation,
multi-source threat intelligence, SIGMA/YARA integration, and CVE correlation.**

[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-9%20Tactics-red.svg)](https://attack.mitre.org/)
[![Lines of Code](https://img.shields.io/badge/lines-5%2C506-informational.svg)]()

</div>

---

Point it at EVTX files. Get a prioritized, intel-enriched threat report with MITRE ATT&CK context -- the same workflow CrowdStrike and Elastic use, but as a single standalone Python file you own.

```bash
python log_parser.py ./logs/ --output artifacts/output --html report.html --enrich --sigma-rules ./sigma/ --triage
```

Generated reports default to `artifacts/output/`. The TAXII cache is kept in
`artifacts/runtime/cache/`; use `--output` to select another explicit output
directory when needed.

---

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Usage](#usage)
- [MITRE ATT&CK Coverage](#mitre-attck-coverage)
- [Architecture](#architecture)
- [Optional Features](#optional-features)
- [Output Formats](#output-formats)
- [Test Data Sources](#test-data-sources)
- [Contributing](#contributing)
- [License](#license)

---

## Features

**Core Detection Engine**
- 48+ behavioral detection rules across 9 MITRE ATT&CK tactics
- 102 Windows Event IDs parsed (Security, Sysmon, PowerShell, WMI, Task Scheduler)
- 56 LOLBin detections from the LOLBAS project
- 40+ suspicious command-line pattern signatures
- 8 APT tooling signature families (Cobalt Strike, Mimikatz, Impacket, BloodHound, Rubeus, SharpHound, Sliver, Mythic)

**Kill-Chain Correlation**
- CrowdStrike-style behavioral IOA engine reconstructs multi-stage attack chains
- Temporal correlation with configurable time windows
- Host-scoped chain tracking across event sources

**Threat Intelligence Enrichment**
- 4 sources: AlienVault OTX, VirusTotal, AbuseIPDB, Shodan
- SQLite-backed cache with configurable TTL (no redundant API calls)
- Rate limiting per source to respect API quotas

**Detection Rule Frameworks**
- SIGMA rule evaluator -- load 15,000+ community rules from SigmaHQ
- YARA scanner for file artifact analysis with auto VT hash submission
- CVE correlation against CISA Known Exploited Vulnerabilities catalog + Shodan CVEDB
- TAXII 2.1 feed client for ingesting STIX indicators with incremental polling

**Scoring and Triage**
- Composite scoring engine (6 weighted factors) produces analyst-ready triage queue
- Triage levels: CRITICAL / HIGH / MEDIUM / LOW with one-line action items
- Sortable priority queue so analysts start with what matters

**Reporting**
- Interactive HTML dashboard with MITRE ATT&CK heatmap, threat intel panels, triage queue
- CSV, JSON, and IOC export (STIX 2.1 compatible)

---

## Quick Start

```bash
# 1. Clone and set up
git clone https://github.com/YOUR_USER/log-parser.git
cd log-parser

# 2. Install the one required dependency
pip install python-evtx

# 3. Run it
python log_parser.py Security.evtx --html report.html
```

Open `report.html` in your browser. That's it.

---

## Installation

### Requirements

- Python 3.8+
- One required package: `python-evtx`
- Everything else is optional and stdlib-based

### Recommended Setup

```bash
# Create a virtual environment
python3 -m venv venv
source venv/bin/activate        # macOS / Linux
# venv\Scripts\activate          # Windows

# Install required dependency
pip install python-evtx

# (Optional) Install SIGMA + YARA support
pip install pyyaml yara-python
```

### Dependencies

| Package | Required | Purpose |
|---------|----------|---------|
| `python-evtx` | Yes | EVTX file parsing |
| `pyyaml` | No | SIGMA rule loading |
| `yara-python` | No | YARA file scanning |

All threat intel integrations (OTX, VirusTotal, AbuseIPDB, Shodan), TAXII feed ingestion, CVE correlation, and the SQLite cache use Python's standard library (`urllib.request`, `sqlite3`, `json`) -- no extra packages needed.

---

## Usage

### Basic Analysis

```bash
# Single EVTX file
python log_parser.py Security.evtx --html report.html

# Directory of EVTX files
python log_parser.py ./logs/ --html report.html

# Filter by severity
python log_parser.py ./logs/ --html report.html --severity high
```

### Threat Intelligence Enrichment

```bash
# Set API keys (optional -- each source works independently)
export OTX_API_KEY="your-key"
export VT_API_KEY="your-key"
export ABUSEIPDB_API_KEY="your-key"
export SHODAN_API_KEY="your-key"

# Run with enrichment
python log_parser.py ./logs/ --html report.html --enrich
```

### SIGMA + YARA Rules

```bash
# Clone SigmaHQ community rules
git clone https://github.com/SigmaHQ/sigma.git

# Run with SIGMA detection
python log_parser.py ./logs/ --sigma-rules ./sigma/rules/windows/ --html report.html

# Add YARA scanning
python log_parser.py ./logs/ --sigma-rules ./sigma/rules/windows/ \
  --yara-rules ./yara-rules/ --html report.html
```

### CVE Correlation + TAXII Feeds

```bash
# Enable CVE lookup (uses free Shodan CVEDB + CISA KEV -- no API key needed)
python log_parser.py ./logs/ --cve-check --html report.html

# Ingest threat intel from TAXII feeds
python log_parser.py ./logs/ --taxii-url https://otx.alienvault.com/taxii/ \
  --taxii-collection system.Default --html report.html
```

### Full Threat Hunting Mode

```bash
python log_parser.py ./logs/ --html report.html --severity medium \
  --sigma-rules ./sigma/rules/windows/ \
  --yara-rules ./yara-rules/ \
  --enrich --cve-check \
  --taxii-url https://otx.alienvault.com/taxii/ \
  --taxii-collection system.Default \
  --triage
```

### Export Formats

```bash
# CSV export
python log_parser.py ./logs/ --csv findings.csv

# JSON export
python log_parser.py ./logs/ --json findings.json

# IOC extraction (IP, domain, hash, URL, email)
python log_parser.py ./logs/ --ioc-export iocs.json

# Triage queue to console
python log_parser.py ./logs/ --triage
```

### CLI Reference

| Flag | Description |
|------|-------------|
| `INPUT` | EVTX file or directory (positional) |
| `--html FILE` | Generate interactive HTML report |
| `--csv FILE` | Export findings as CSV |
| `--json FILE` | Export findings as JSON |
| `--ioc-export FILE` | Export extracted IOCs |
| `--severity LEVEL` | Filter: `info`, `low`, `medium`, `high`, `critical` |
| `--enrich` | Enable live threat intel enrichment |
| `--otx-key KEY` | AlienVault OTX API key (or `$OTX_API_KEY`) |
| `--vt-key KEY` | VirusTotal API key (or `$VT_API_KEY`) |
| `--abuseipdb-key KEY` | AbuseIPDB API key (or `$ABUSEIPDB_API_KEY`) |
| `--shodan-key KEY` | Shodan API key (or `$SHODAN_API_KEY`) |
| `--sigma-rules DIR` | Path to SIGMA rule YAML files |
| `--yara-rules DIR` | Path to YARA rule files |
| `--cve-check` | Enable CVE correlation |
| `--taxii-url URL` | TAXII 2.1 server URL |
| `--taxii-collection ID` | TAXII collection to poll |
| `--triage` | Output prioritized analyst queue |
| `--output DIR` | Output directory for generated files |
| `--stix` | Export IOCs in STIX 2.1 bundle format |
| `--no-cache` | Disable SQLite threat intel cache |
| `-v`, `--verbose` | Increase logging verbosity |

---

## MITRE ATT&CK Coverage

9 tactics with 48+ detection rules:

| Tactic | ID | Detector | Rules | Techniques |
|--------|----|----------|-------|------------|
| **Execution** | TA0002 | CommandLineAnalyzer | 40+ | Suspicious CLI patterns, LOLBin abuse, PowerShell cradles |
| **Persistence** | TA0003 | PersistenceDetector | 8 | Scheduled tasks, services, registry run keys, WMI subscriptions, startup folders, DLL hijacking |
| **Privilege Escalation** | TA0004 | PersistenceDetector | (shared) | Service creation with SYSTEM, token manipulation |
| **Defense Evasion** | TA0005 | DefenseEvasionDetector | 8 | Log clearing, timestomping, AV tampering, process hollowing, AMSI bypass, ETW patching |
| **Credential Access** | TA0006 | CredentialAccessDetector | 6 | LSASS access, SAM dump, DCSync, Kerberoasting, credential file access, DPAPI abuse |
| **Discovery** | TA0007 | DiscoveryDetector | 4 | Sysinfo bursts, network recon, domain trust enumeration, security software hunting |
| **Lateral Movement** | TA0008 | LateralMovementDetector | 10 | PsExec, WMI remote, WinRM, DCOM, RDP, SMB, service deployment, pass-the-hash |
| **Exfiltration** | TA0010 | ExfiltrationDetector | 4 | Archive staging, DNS exfil (entropy analysis), cloud upload tools, large transfers |
| **Command and Control** | TA0011 | CommandAndControlDetector | 5 | Beaconing (jitter analysis), DNS tunneling, C2 framework signatures, PowerShell cradles, LOLBin network |
| **Impact** | TA0040 | ImpactDetector | 3 | Ransomware indicators, mass encryption, service destruction |

Additional detection layers: SIGMA rules (15,000+ community rules), YARA file scanning, CVE correlation against CISA KEV.

---

## Architecture

Single file, 23 sections, 29 classes, 5,506 lines.

```
log_parser.py
|
|-- SECTION 1:  Core Data Structures         Constants, event ID maps, LOLBin lists
|-- SECTION 2:  Data Classes                 ParsedEvent, Alert, IOC, AttackChain
|-- SECTION 3:  Event Parser                 EventParser -- EVTX XML extraction
|-- SECTION 4:  Base Threat Detector         ThreatDetector -- abstract base class
|-- SECTION 5:  Command-Line Analyzer        CommandLineAnalyzer -- CLI pattern + LOLBin detection
|-- SECTION 6:  Persistence Detector         PersistenceDetector -- 8 rules (TA0003)
|-- SECTION 7:  Lateral Movement Detector    LateralMovementDetector -- 10 rules (TA0008)
|-- SECTION 8:  Defense Evasion Detector     DefenseEvasionDetector -- 8 rules (TA0005)
|-- SECTION 9:  Credential Access Detector   CredentialAccessDetector -- 6 rules (TA0006)
|-- SECTION 10: Attack Chain Correlator      AttackChainCorrelator -- behavioral IOA engine
|-- SECTION 11: IOC Extractor                IOCExtractor -- IP, domain, hash, URL, email
|-- SECTION 14: Threat Intelligence Engine   ThreatIntelEngine -- OTX, VT, AbuseIPDB, Shodan + cache
|-- SECTION 15: SIGMA Rule Evaluator         SIGMAEvaluator -- YAML rule loading + event matching
|-- SECTION 16: YARA Scanner                 YARAScanner -- file artifact scanning
|-- SECTION 17: Discovery Detector           DiscoveryDetector -- 4 rules (TA0007)
|-- SECTION 18: Exfiltration Detector        ExfiltrationDetector -- 4 rules (TA0010)
|-- SECTION 19: C2 Detector                  CommandAndControlDetector -- 5 rules (TA0011)
|-- SECTION 20: Impact Detector              ImpactDetector -- 3 rules (TA0040)
|-- SECTION 21: CVE Correlator               CVECorrelator -- CISA KEV + Shodan CVEDB
|-- SECTION 22: TAXII Feed Client            TAXIIFeedClient -- STIX 2.1 indicator ingestion
|-- SECTION 23: Composite Scorer             CompositeScorer -- weighted scoring + triage queue
|-- SECTION 12: HTML Report Generator        HTMLReportGenerator -- full interactive dashboard
|-- SECTION 13: Main Engine + CLI            main() -- orchestration, argument parsing, export
```

### Class Map (29 classes)

| Class | Section | Role |
|-------|---------|------|
| `ParsedEvent` | S2 | Normalized event data class |
| `Alert` | S2 | Detection finding data class |
| `IOC` | S2 | Indicator of compromise data class |
| `AttackChain` | S2 | Kill-chain sequence data class |
| `EventParser` | S3 | EVTX XML parsing and field extraction |
| `ThreatDetector` | S4 | Abstract base for all detectors |
| `CommandLineAnalyzer` | S5 | CLI patterns + LOLBin abuse detection |
| `PersistenceDetector` | S6 | Scheduled tasks, services, registry, WMI |
| `LateralMovementDetector` | S7 | PsExec, WMI, WinRM, DCOM, RDP, SMB |
| `DefenseEvasionDetector` | S8 | Log clearing, timestomp, AV tamper, AMSI |
| `CredentialAccessDetector` | S9 | LSASS, SAM, DCSync, Kerberoast, DPAPI |
| `AttackChainCorrelator` | S10 | Behavioral IOA correlation engine |
| `IOCExtractor` | S11 | Regex-based IOC extraction + dedup |
| `ThreatIntelResult` | S14 | Normalized TI lookup result |
| `ThreatIntelCache` | S14 | SQLite cache with TTL management |
| `ThreatIntelEngine` | S14 | Multi-source enrichment orchestrator |
| `SIGMARule` | S15 | Parsed SIGMA rule representation |
| `SIGMAEvaluator` | S15 | YAML loader + event evaluation engine |
| `YARAMatch` | S16 | YARA match result data class |
| `YARAScanner` | S16 | File scanning with compiled YARA rules |
| `DiscoveryDetector` | S17 | Sysinfo bursts, net recon, trust enum |
| `ExfiltrationDetector` | S18 | Archive staging, DNS exfil, cloud tools |
| `CommandAndControlDetector` | S19 | Beaconing, DNS tunnel, C2 signatures |
| `ImpactDetector` | S20 | Ransomware, mass encryption, service kill |
| `CVEResult` | S21 | CVE lookup result data class |
| `CVECorrelator` | S21 | CISA KEV + Shodan CVEDB correlation |
| `TAXIIFeedClient` | S22 | STIX 2.1 indicator polling + SQLite store |
| `CompositeScorer` | S23 | Weighted scoring + triage prioritization |
| `HTMLReportGenerator` | S12 | Interactive HTML dashboard generator |

---

## Optional Features

All optional features degrade gracefully -- if a dependency is not installed or an API key is not set, the tool skips that module and logs a warning. No crashes.

| Feature | Requires | Install | API Key |
|---------|----------|---------|---------|
| Core detection | `python-evtx` | `pip install python-evtx` | None |
| SIGMA rules | `pyyaml` | `pip install pyyaml` | None |
| YARA scanning | `yara-python` | `pip install yara-python` | None |
| AlienVault OTX | stdlib | -- | `OTX_API_KEY` |
| VirusTotal | stdlib | -- | `VT_API_KEY` |
| AbuseIPDB | stdlib | -- | `ABUSEIPDB_API_KEY` |
| Shodan | stdlib | -- | `SHODAN_API_KEY` |
| CVE correlation | stdlib | -- | None (free APIs) |
| TAXII feeds | stdlib | -- | None (public feeds) |

---

## Output Formats

### HTML Report

The interactive HTML report includes:
- **Triage Queue** -- composite-scored findings sorted by analyst priority
- **MITRE ATT&CK Heatmap** -- 9-tactic coverage visualization
- **Detection Timeline** -- chronological event scatter plot
- **Threat Intel Panel** -- enrichment results with source badges (OTX/VT/AbuseIPDB/Shodan)
- **SIGMA Match Summary** -- matched rules with metadata and MITRE mappings
- **YARA Hit Table** -- file artifact matches with rule names
- **CVE Correlation Table** -- CVSS scores and CISA KEV flags
- **Attack Chain Viewer** -- reconstructed kill-chain sequences
- **IOC Summary** -- extracted indicators by type

### CSV / JSON

Flat export of all alerts with fields: timestamp, rule_name, severity, mitre_tactic, mitre_technique, description, source_event_id, host, and enrichment data.

### IOC Export

JSON array of extracted IOCs: IP addresses, domains, file hashes (MD5/SHA1/SHA256), URLs, and email addresses -- compatible with STIX 2.1 indicator format.

---

## Test Data Sources

No EVTX files handy? These public repos contain real attack samples:

| Repository | Description |
|------------|-------------|
| [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) | Real ATT&CK technique samples -- best for testing |
| [hayabusa-sample-evtx](https://github.com/Yamato-Security/hayabusa-sample-evtx) | Curated samples from the Hayabusa project |
| [mordor](https://github.com/OTRF/mordor) | Pre-recorded security datasets (EVTX + JSON) |
| [atomic-red-team](https://github.com/redcanaryco/atomic-red-team) | Generate your own test logs with Atomic tests |

```bash
# Quick test with real attack samples
git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git
python log_parser.py ./EVTX-ATTACK-SAMPLES/ --html test_report.html --triage
```

---

## Contributing

Contributions are welcome. To add a new detector:

1. Create a class that inherits from `ThreatDetector`
2. Implement `analyze(self, event: ParsedEvent)`
3. Register it in `main()` alongside the existing detectors
4. Add detection rules with MITRE ATT&CK technique IDs

For SIGMA rules, add YAML files to your rules directory -- the evaluator loads them automatically.

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

<div align="center">

**Built for defenders. One file. Zero cloud dependencies. Full kill-chain visibility.**

</div>
