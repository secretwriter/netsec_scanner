#!/usr/bin/env python3
"""
Network Security Scanner

A comprehensive cybersecurity tool for scanning networks, identifying vulnerabilities,
and gathering security-related information about target systems.

Features:
- Port scanning with service detection
- SSL/TLS certificate validation
- DNS information gathering
- Banner grabbing for service identification
- Basic vulnerability checking

Author: Your Name
GitHub: Your GitHub Username
LinkedIn: Your LinkedIn Profile
"""

import socket
import ssl
import argparse
import sys
import time
import dns.resolver
import requests
import json
import concurrent.futures
import ipaddress
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama for cross-platform colored terminal output
init()

# Global variables
timeout = 2.0
user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
verbose = False

# Common ports and their associated services
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    115: "SFTP",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    194: "IRC",
    443: "HTTPS",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt"
}

# Known vulnerabilities (simplified for demonstration)
KNOWN_VULNERABILITIES = {
    "SSH-2.0-OpenSSH_7.": "OpenSSH 7.x may be vulnerable to user enumeration (CVE-2018-15473)",
    "SSH-2.0-OpenSSH_8.0": "OpenSSH 8.0 may be vulnerable to authentication bypass (CVE-2020-14145)",
    "Apache/2.4.49": "Apache 2.4.49 is vulnerable to path traversal and RCE (CVE-2021-41773, CVE-2021-42013)",
    "nginx/1.18.0": "Nginx 1.18.0 may be vulnerable to HTTP request smuggling",
    "Microsoft-IIS/7.5": "IIS 7.5 may be vulnerable to various attacks if not patched",
    "MySQL 5.7": "MySQL 5.7 may have multiple vulnerabilities if not updated",
    "ProFTPD 1.3.5": "ProFTPD 1.3.5 has a critical RCE vulnerability (CVE-2015-3306)"
}

class NetworkScanner:
    """Main class for network scanning operations"""
    
    def __init__(self, target, port_range=None, threads=10):
        """
        Initialize the scanner with target and options
        
        Args:
            target (str): Target IP address or hostname
            port_range (str, optional): Range of ports to scan (e.g., '1-1000')
            threads (int, optional): Number of threads for concurrent scanning
        """
        self.target = target
        self.threads = threads
        self.open_ports = []
        self.vulnerabilities = []
        self.scan_results = {}
        
        # Resolve target to IP if it's a hostname
        try:
            self.ip = socket.gethostbyname(target)
            print(f"{Fore.GREEN}[+] Target {target} resolves to {self.ip}{Style.RESET_ALL}")
        except socket.gaierror:
            print(f"{Fore.RED}[!] Error: Could not resolve hostname {target}{Style.RESET_ALL}")
            sys.exit(1)
        
        # Parse port range
        if port_range:
            try:
                start, end = map(int, port_range.split('-'))
                self.port_range = range(start, end + 1)
            except ValueError:
                print(f"{Fore.RED}[!] Error: Invalid port range format. Use start-end (e.g., 1-1000){Style.RESET_ALL}")
                sys.exit(1)
        else:
            # Default to common ports if no range specified
            self.port_range = COMMON_PORTS.keys()
    
    def scan_port(self, port):
        """
        Scan a single port and gather information if open
        
        Args:
            port (int): Port number to scan
            
        Returns:
            dict: Information about the port if open, None otherwise
        """
        try:
            # Create socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            
            # Attempt to connect
            result = s.connect_ex((self.ip, port))
            
            # If port is open
            if result == 0:
                service = COMMON_PORTS.get(port, "Unknown")
                
                # Try to get banner
                banner = self.grab_banner(port)
                
                # Check for SSL/TLS
                ssl_info = None
                if port == 443 or service == "HTTPS" or port == 8443:
                    ssl_info = self.check_ssl(port)
                
                # Check for vulnerabilities
                vulns = self.check_vulnerabilities(banner)
                if vulns:
                    self.vulnerabilities.extend(vulns)
                
                port_info = {
                    "port": port,
                    "service": service,
                    "banner": banner,
                    "ssl_info": ssl_info,
                    "vulnerabilities": vulns
                }
                
                self.open_ports.append(port)
                return port_info
            
            s.close()
            return None
            
        except socket.error:
            if verbose:
                print(f"{Fore.YELLOW}[!] Could not connect to port {port}{Style.RESET_ALL}")
            return None
    
    def grab_banner(self, port):
        """
        Attempt to grab service banner from the specified port
        
        Args:
            port (int): Port number
            
        Returns:
            str: Service banner if available, None otherwise
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((self.ip, port))
            
            # Send appropriate request based on likely protocol
            if port == 80 or port == 8080:
                s.send(f"GET / HTTP/1.1\r\nHost: {self.target}\r\nUser-Agent: {user_agent}\r\n\r\n".encode())
            elif port == 443 or port == 8443:
                # HTTPS requires SSL/TLS, handled separately
                return None
            elif port == 21:
                # FTP usually sends banner automatically
                pass
            elif port == 22:
                # SSH usually sends banner automatically
                pass
            elif port == 25 or port == 587:
                # SMTP
                s.send(b"EHLO netsec_scanner\r\n")
            else:
                # Generic request for other services
                s.send(b"\r\n")
            
            # Receive response
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            s.close()
            return banner
            
        except (socket.timeout, socket.error):
            return None
    
    def check_ssl(self, port):
        """
        Check SSL/TLS certificate information
        
        Args:
            port (int): Port number (usually 443)
            
        Returns:
            dict: SSL/TLS certificate information
        """
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.ip, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    if not cert:
                        cert = ssock.getpeercert(binary_form=True)
                        return {"valid": False, "error": "Could not parse certificate"}
                    
                    # Extract certificate information
                    ssl_info = {
                        "valid": True,
                        "version": ssock.version(),
                        "cipher": ssock.cipher(),
                        "issuer": dict(x[0] for x in cert.get('issuer', [])),
                        "subject": dict(x[0] for x in cert.get('subject', [])),
                        "expiry": cert.get('notAfter', 'Unknown')
                    }
                    
                    # Check if certificate is expired
                    if 'notAfter' in cert:
                        expiry_date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                        if expiry_date < datetime.now():
                            ssl_info["valid"] = False
                            ssl_info["error"] = "Certificate expired"
                    
                    return ssl_info
                    
        except (socket.error, ssl.SSLError, ssl.CertificateError) as e:
            return {"valid": False, "error": str(e)}
    
    def check_vulnerabilities(self, banner):
        """
        Check for known vulnerabilities based on service banner
        
        Args:
            banner (str): Service banner
            
        Returns:
            list: List of potential vulnerabilities
        """
        if not banner:
            return []
        
        found_vulns = []
        for signature, vuln_info in KNOWN_VULNERABILITIES.items():
            if signature in banner:
                found_vulns.append({
                    "signature": signature,
                    "description": vuln_info
                })
        
        return found_vulns
    
    def gather_dns_info(self):
        """
        Gather DNS information about the target
        
        Returns:
            dict: DNS records information
        """
        dns_info = {}
        
        # Only perform DNS lookups if target is a hostname, not an IP
        if not self.is_ip_address(self.target):
            try:
                # A records
                try:
                    answers = dns.resolver.resolve(self.target, 'A')
                    dns_info['A'] = [answer.to_text() for answer in answers]
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    dns_info['A'] = []
                
                # MX records
                try:
                    answers = dns.resolver.resolve(self.target, 'MX')
                    dns_info['MX'] = [answer.to_text() for answer in answers]
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    dns_info['MX'] = []
                
                # NS records
                try:
                    answers = dns.resolver.resolve(self.target, 'NS')
                    dns_info['NS'] = [answer.to_text() for answer in answers]
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    dns_info['NS'] = []
                
                # TXT records
                try:
                    answers = dns.resolver.resolve(self.target, 'TXT')
                    dns_info['TXT'] = [answer.to_text() for answer in answers]
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    dns_info['TXT'] = []
                
            except dns.exception.DNSException as e:
                print(f"{Fore.RED}[!] DNS lookup error: {str(e)}{Style.RESET_ALL}")
                dns_info['error'] = str(e)
        
        return dns_info
    
    def is_ip_address(self, address):
        """
        Check if the given address is an IP address
        
        Args:
            address (str): Address to check
            
        Returns:
            bool: True if address is an IP address, False otherwise
        """
        try:
            ipaddress.ip_address(address)
            return True
        except ValueError:
            return False
    
    def check_http_security_headers(self, port=80, use_ssl=False):
        """
        Check for security headers on HTTP/HTTPS services
        
        Args:
            port (int): Port number
            use_ssl (bool): Whether to use HTTPS
            
        Returns:
            dict: Security headers information
        """
        protocol = "https" if use_ssl else "http"
        url = f"{protocol}://{self.target}:{port}"
        
        try:
            response = requests.get(url, timeout=timeout, verify=False, 
                                   headers={"User-Agent": user_agent})
            
            # Check for security headers
            headers = response.headers
            security_headers = {
                "Strict-Transport-Security": headers.get("Strict-Transport-Security", "Not set"),
                "Content-Security-Policy": headers.get("Content-Security-Policy", "Not set"),
                "X-Content-Type-Options": headers.get("X-Content-Type-Options", "Not set"),
                "X-Frame-Options": headers.get("X-Frame-Options", "Not set"),
                "X-XSS-Protection": headers.get("X-XSS-Protection", "Not set"),
                "Referrer-Policy": headers.get("Referrer-Policy", "Not set"),
                "Permissions-Policy": headers.get("Permissions-Policy", "Not set"),
                "Server": headers.get("Server", "Not disclosed")
            }
            
            return {
                "status_code": response.status_code,
                "security_headers": security_headers
            }
            
        except requests.exceptions.RequestException:
            return None
    
    def run_scan(self):
        """
        Run the full network scan
        
        Returns:
            dict: Complete scan results
        """
        print(f"{Fore.BLUE}[*] Starting scan on {self.target} ({self.ip}){Style.RESET_ALL}")
        print(f"{Fore.BLUE}[*] Scanning {len(self.port_range)} ports with {self.threads} threads{Style.RESET_ALL}")
        
        start_time = time.time()
        
        # Scan ports using thread pool
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            port_results = list(filter(None, executor.map(self.scan_port, self.port_range)))
        
        # Gather DNS information
        dns_info = self.gather_dns_info()
        
        # Check HTTP security headers if web ports are open
        http_security = None
        https_security = None
        
        if 80 in self.open_ports:
            http_security = self.check_http_security_headers(port=80)
        
        if 443 in self.open_ports:
            https_security = self.check_http_security_headers(port=443, use_ssl=True)
        
        # Compile results
        self.scan_results = {
            "target": self.target,
            "ip": self.ip,
            "scan_time": time.time() - start_time,
            "open_ports": len(self.open_ports),
            "ports": port_results,
            "dns_info": dns_info,
            "http_security": http_security,
            "https_security": https_security,
            "vulnerabilities": self.vulnerabilities
        }
        
        return self.scan_results
    
    def print_results(self):
        """Print scan results in a formatted way"""
        if not self.scan_results:
            print(f"{Fore.RED}[!] No scan results available. Run scan first.{Style.RESET_ALL}")
            return
        
        print("\n" + "=" * 60)
        print(f"{Fore.GREEN}SCAN RESULTS FOR {self.target} ({self.ip}){Style.RESET_ALL}")
        print("=" * 60)
        
        # Print scan summary
        print(f"\n{Fore.BLUE}[*] Scan completed in {self.scan_results['scan_time']:.2f} seconds{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[*] Found {self.scan_results['open_ports']} open ports{Style.RESET_ALL}")
        
        # Print open ports and services
        if self.scan_results['ports']:
            print(f"\n{Fore.GREEN}OPEN PORTS AND SERVICES:{Style.RESET_ALL}")
            print("-" * 60)
            print(f"{'PORT':<10}{'SERVICE':<15}{'BANNER':<35}")
            print("-" * 60)
            
            for port_info in self.scan_results['ports']:
                port = port_info['port']
                service = port_info['service']
                banner = port_info['banner']
                
                if banner:
                    # Truncate banner if too long
                    banner = banner[:32] + "..." if len(banner) > 35 else banner
                else:
                    banner = "N/A"
                
                print(f"{port:<10}{service:<15}{banner:<35}")
        
        # Print SSL/TLS information
        ssl_ports = [p for p in self.scan_results['ports'] if p.get('ssl_info')]
        if ssl_ports:
            print(f"\n{Fore.GREEN}SSL/TLS INFORMATION:{Style.RESET_ALL}")
            print("-" * 60)
            
            for port_info in ssl_ports:
                port = port_info['port']
                ssl_info = port_info['ssl_info']
                
                print(f"Port {port} ({port_info['service']}):")
                print(f"  Version: {ssl_info.get('version', 'Unknown')}")
                print(f"  Valid: {ssl_info.get('valid', False)}")
                
                if not ssl_info.get('valid', False):
                    print(f"  Error: {ssl_info.get('error', 'Unknown error')}")
                
                if 'expiry' in ssl_info:
                    print(f"  Expires: {ssl_info['expiry']}")
                
                if 'issuer' in ssl_info and ssl_info['issuer']:
                    issuer_cn = ssl_info['issuer'].get('commonName', 'Unknown')
                    print(f"  Issuer: {issuer_cn}")
                
                print()
        
        # Print DNS information
        if self.scan_results['dns_info'] and not self.is_ip_address(self.target):
            print(f"\n{Fore.GREEN}DNS INFORMATION:{Style.RESET_ALL}")
            print("-" * 60)
            
            dns_info = self.scan_results['dns_info']
            
            if 'A' in dns_info and dns_info['A']:
                print(f"A Records: {', '.join(dns_info['A'])}")
            
            if 'MX' in dns_info and dns_info['MX']:
                print(f"MX Records: {', '.join(dns_info['MX'])}")
            
            if 'NS' in dns_info and dns_info['NS']:
                print(f"NS Records: {', '.join(dns_info['NS'])}")
            
            if 'TXT' in dns_info and dns_info['TXT']:
                print("TXT Records:")
                for txt in dns_info['TXT']:
                    print(f"  {txt}")
        
        # Print HTTP security headers
        if self.scan_results['http_security']:
            print(f"\n{Fore.GREEN}HTTP SECURITY HEADERS (PORT 80):{Style.RESET_ALL}")
            print("-" * 60)
            
            headers = self.scan_results['http_security']['security_headers']
            for header, value in headers.items():
                print(f"{header}: {value}")
        
        if self.scan_results['https_security']:
            print(f"\n{Fore.GREEN}HTTPS SECURITY HEADERS (PORT 443):{Style.RESET_ALL}")
            print("-" * 60)
            
            headers = self.scan_results['https_security']['security_headers']
            for header, value in headers.items():
                print(f"{header}: {value}")
        
        # Print vulnerabilities
        if self.scan_results['vulnerabilities']:
            print(f"\n{Fore.RED}POTENTIAL VULNERABILITIES:{Style.RESET_ALL}")
            print("-" * 60)
            
            for vuln in self.scan_results['vulnerabilities']:
                print(f"Signature: {vuln['signature']}")
                print(f"Description: {vuln['description']}")
                print()
        
        print("=" * 60)
        print(f"{Fore.YELLOW}Note: This is a basic security scan. For comprehensive security assessment, consider professional penetration testing.{Style.RESET_ALL}")
        print("=" * 60 + "\n")
    
    def save_results(self, filename):
        """
        Save scan results to a JSON file
        
        Args:
            filename (str): Output filename
        """
        if not self.scan_results:
            print(f"{Fore.RED}[!] No scan results available. Run scan first.{Style.RESET_ALL}")
            return
        
        try:
            with open(filename, 'w') as f:
                json.dump(self.scan_results, f, indent=4)
            
            print(f"{Fore.GREEN}[+] Results saved to {filename}{Style.RESET_ALL}")
            
        except IOError as e:
            print(f"{Fore.RED}[!] Error saving results: {str(e)}{Style.RESET_ALL}")


def main():
    """Main function to parse arguments and run the scanner"""
    parser = argparse.ArgumentParser(description="Network Security Scanner")
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("-p", "--ports", help="Port range to scan (e.g., 1-1000)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("-o", "--output", help="Save results to JSON file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--timeout", type=float, default=2.0, help="Timeout in seconds (default: 2.0)")
    
    args = parser.parse_args()
    
    # Set global variables
    global timeout, verbose
    timeout = args.timeout
    verbose = args.verbose
    
    try:
        # Create and run scanner
        scanner = NetworkScanner(args.target, args.ports, args.threads)
        scanner.run_scan()
        scanner.print_results()
        
        # Save results if output file specified
        if args.output:
            scanner.save_results(args.output)
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Fore.RED}[!] An error occurred: {str(e)}{Style.RESET_ALL}")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
