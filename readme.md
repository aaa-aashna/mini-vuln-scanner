# Mini Vulnerability Scanner

A lightweight Python-based network vulnerability scanner that performs concurrent TCP port discovery, basic service/banner identification, and version-based vulnerability matching against a structured local vulnerability database.

The project explores the fundamentals of automated security assessment — from discovering exposed services to transforming detected software versions into structured vulnerability findings.

## Features

* Concurrent TCP port scanning
* Configurable port ranges
* Basic service identification
* Service/banner detection
* Version-based vulnerability matching
* CVE identification
* Severity classification
* Structured security findings
* JSON report generation
* Command-line interface
* Unit tests

## Architecture

```text
                    ┌──────────────┐
                    │    Target    │
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────────┐
                    │ Port Scanner │
                    └──────┬───────┘
                           │
                           ▼
                  ┌──────────────────┐
                  │ Open Port        │
                  │ Detection        │
                  └────────┬─────────┘
                           │
                           ▼
                 ┌────────────────────┐
                 │ Service / Banner   │
                 │ Detection          │
                 └─────────┬──────────┘
                           │
                           ▼
                ┌─────────────────────┐
                │ Version             │
                │ Identification      │
                └──────────┬──────────┘
                           │
                           ▼
                ┌─────────────────────┐
                │ Vulnerability       │
                │ Matcher             │
                └──────────┬──────────┘
                           │
                           ▼
                 ┌───────────────────┐
                 │ Structured        │
                 │ Findings          │
                 └─────────┬─────────┘
                           │
                    ┌──────┴──────┐
                    ▼             ▼
             Terminal Report   JSON Report
```

## Project Structure

```text
mini-vuln-scanner/
│
├── scanner.py
├── vuln_db.json
├── requirements.txt
├── README.md
│
└── tests/
    ├── __init__.py
    └── test_scanner.py
```

## Requirements

* Python 3.9+
* `pytest` for running tests

The scanner itself primarily uses Python's standard library.

## Installation

Clone the repository:

```bash
git clone https://github.com/aaa-aashna/mini-vuln-scanner.git
cd mini-vuln-scanner
```

Install the testing dependency:

```bash
pip install -r requirements.txt
```

## Usage

### Scan the default port range

```bash
python scanner.py --target 127.0.0.1
```

By default, ports `1-1024` are scanned.

### Scan a specific port range

```bash
python scanner.py --target 127.0.0.1 --ports 1-1024
```

### Scan selected ports

```bash
python scanner.py --target 127.0.0.1 --ports 22,80,443
```

### Generate a JSON report

```bash
python scanner.py --target 127.0.0.1 --ports 1-1024 --output report.json
```

### Configure concurrent workers

```bash
python scanner.py --target 127.0.0.1 --workers 50
```

### View available options

```bash
python scanner.py --help
```

## Example Output

```text
================================================
           MINI VULNERABILITY SCANNER
================================================

Target: 192.168.1.10
Ports scanned: 1024

OPEN PORTS
------------------------------------------------
22     ssh       OpenSSH 7.2
80     http      Apache 2.4.49

VULNERABILITIES
------------------------------------------------
[CRITICAL] CVE-2021-41773
Port:        80
Service:     http
Version:     Apache 2.4.49
Description: Path traversal vulnerability

SCAN SUMMARY
------------------------------------------------
Open ports:          2
Vulnerabilities:     1
Critical:            1
High:                0
Medium:              0
Low:                 0
Unknown:              0
```

Actual results depend on the services exposed by the target and the banners returned by those services.

## JSON Reporting

The scanner can generate machine-readable JSON reports for further processing.

Example:

```json
{
  "target": "192.168.1.10",
  "ports_scanned": 1024,
  "open_ports": [
    {
      "port": 80,
      "protocol": "tcp",
      "service": "http",
      "banner": "Apache 2.4.49"
    }
  ],
  "findings": [
    {
      "target": "192.168.1.10",
      "port": 80,
      "protocol": "tcp",
      "service": "http",
      "version": "Apache 2.4.49",
      "cve": "CVE-2021-41773",
      "severity": "CRITICAL",
      "description": "Path traversal vulnerability"
    }
  ],
  "summary": {
    "critical": 1,
    "high": 0,
    "medium": 0,
    "low": 0,
    "unknown": 0
  }
}
```

## Vulnerability Database

Vulnerability information is maintained separately in `vuln_db.json`.

Each entry associates a detected service/version with relevant vulnerability information:

```text
Service
   ↓
Software / Version
   ↓
CVE
   ↓
Severity
   ↓
Description
```

Keeping the vulnerability data separate from the scanning logic allows the database to be updated without changing the core scanning implementation.

## Testing

Run the complete test suite with:

```bash
python -m pytest
```

The tests cover:

* Port specification parsing
* Port range validation
* Vulnerability database loading
* Vulnerability matching
* Structured finding generation
* JSON report generation
* Invalid input handling

The test suite does not require scanning external systems.

## Limitations

This project is an educational and experimental security scanning tool and is not intended to replace mature vulnerability assessment platforms.

Current limitations include:

* Service identification primarily relies on known ports and banners.
* Some services may not expose a readable banner.
* Vulnerability matching depends on the local vulnerability database.
* Version-based matching can produce incomplete results when software does not disclose its version.
* The scanner does not perform exploit execution or active vulnerability verification.
* The vulnerability database is manually maintained.

## Future Improvements

Potential future improvements include:

* richer vulnerability data sources
* improved service fingerprinting
* additional protocol-specific checks
* additional report formats
* automated vulnerability database updates
* improved result visualization
* expanded test coverage

## Responsible Use

Only scan systems and networks that you own or have explicit permission to test.

This project is intended for security education, authorized security testing, and experimentation.

## License

This project is licensed under the terms of the repository's license.
