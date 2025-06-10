# Network Security Scanner

A comprehensive cybersecurity tool for scanning networks, identifying vulnerabilities, and gathering security-related information about target systems.

![Python Version](https://img.shields.io/badge/python-3.6+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## Features

- **Port Scanning**: Detect open ports and running services on target systems
- **Banner Grabbing**: Identify service versions for vulnerability assessment
- **SSL/TLS Analysis**: Validate certificates and check for secure configurations
- **DNS Information Gathering**: Collect DNS records for domain intelligence
- **HTTP Security Headers**: Analyze security headers on web servers
- **Vulnerability Detection**: Identify potential security issues based on service versions
- **Multi-threaded Scanning**: Fast, efficient scanning with adjustable thread count
- **Colorized Output**: Clear, readable results with color-coded severity levels
- **JSON Export**: Save scan results for further analysis or reporting

## Installation

### Prerequisites

- Python 3.6 or higher
- pip (Python package installer)

### Setup

1. Clone this repository:

```bash
git clone https://github.com/secretwriter/netsec_scanner.git
cd netsec_scanner
cd cybersec_scanner
```

2. Install required dependencies:

```bash
pip install -r requirements.txt
```

Or install dependencies manually:

```bash
pip install dnspython requests colorama
```

## Usage

### Basic Usage

Scan a target with default settings:

```bash
python netsec_scanner.py example.com
```

### Advanced Options

```bash
python netsec_scanner.py [target] [options]
```

Options:

- `-p, --ports`: Specify port range (e.g., `1-1000`)
- `-t, --threads`: Number of threads for concurrent scanning (default: 10)
- `-o, --output`: Save results to JSON file
- `-v, --verbose`: Enable verbose output
- `--timeout`: Set connection timeout in seconds (default: 2.0)

### Examples

Scan specific port range with 5 threads:

```bash
python netsec_scanner.py example.com -p 1-100 -t 5
```

Save scan results to a file:

```bash
python netsec_scanner.py example.com -o results.json
```

Verbose scan with custom timeout:

```bash
python netsec_scanner.py example.com -v --timeout 5.0
```

## Sample Output

```
============================================================
SCAN RESULTS FOR example.com (93.184.216.34)
============================================================
[*] Scan completed in 8.45 seconds
[*] Found 2 open ports

OPEN PORTS AND SERVICES:
------------------------------------------------------------
PORT      SERVICE        BANNER
------------------------------------------------------------
80        HTTP           HTTP/1.1 200 OK
443       HTTPS          N/A

SSL/TLS INFORMATION:
------------------------------------------------------------
Port 443 (HTTPS):
  Version: TLSv1.2
  Valid: True
  Expires: Aug 24 23:59:59 2025 GMT
  Issuer: DigiCert TLS RSA SHA256 2020 CA1

DNS INFORMATION:
------------------------------------------------------------
A Records: 93.184.216.34
MX Records: 0 example.org.
NS Records: a.iana-servers.net., b.iana-servers.net.
TXT Records:
  "v=spf1 -all"
  "docusign=05958488-4752-4ef2-95eb-aa7ba8a3bd0e"

HTTP SECURITY HEADERS (PORT 80):
------------------------------------------------------------
Strict-Transport-Security: max-age=31536000
Content-Security-Policy: Not set
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: Not set
Referrer-Policy: Not set
Permissions-Policy: Not set
Server: ECS (dcb/7F84)
============================================================
Note: This is a basic security scan. For comprehensive security assessment, consider professional penetration testing.
============================================================
```

## Security and Ethical Use

This tool is designed for security professionals, system administrators, and ethical hackers to assess the security of systems they own or have explicit permission to test.

**Important**: Unauthorized scanning of networks and systems is illegal in many jurisdictions and unethical. Always ensure you have proper authorization before scanning any target.

## Limitations

- This is a basic security scanning tool and does not replace comprehensive penetration testing
- False positives may occur in vulnerability detection
- Some network configurations may block or rate-limit scanning attempts
- The tool does not exploit vulnerabilities, only identifies potential issues

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [Python-Nmap](https://pypi.org/project/python-nmap/) for inspiration on port scanning techniques
- [OWASP](https://owasp.org/) for security best practices and vulnerability information
- [DNSPython](https://www.dnspython.org/) for DNS resolution capabilities

---

Created by [Prayojan Ghimire] - [my LinkedIn Profile](https://www.linkedin.com/in/prayojan-ghimire-09175733b/)
