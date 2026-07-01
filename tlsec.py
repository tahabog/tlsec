#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  ████████╗██╗     ███████╗███████╗ ██████╗                     ║
║  ╚══██╔══╝██║     ██╔════╝██╔════╝██╔════╝                     ║
║     ██║   ██║     █████╗  ███████╗██║                          ║
║     ██║   ██║     ██╔══╝  ╚════██║██║                          ║
║     ██║   ███████╗███████╗███████║╚██████╗                    ║
║     ╚═╝   ╚══════╝╚══════╝╚══════╝ ╚═════╝                    ║
║  ███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗██╗   ██╗
║  ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝
║  ███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║    ╚████╔╝ 
║  ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║     ╚██╔╝  
║  ███████║███████╗╚██████╗╚██████╔╝██║  ██║██║   ██║      ██║   
║  ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝   
║  Advanced HTTPS Security Auditor – v4.0.0                      ║
║  "The tool that makes professionals fear your insight."       ║
╚══════════════════════════════════════════════════════════════════╝
"""
import sys
import os
import time
import json
import socket
import ssl
import threading
import queue
import re
import subprocess
from datetime import datetime
from urllib.parse import urlparse
from colorama import init, Fore, Style
import requests

init(autoreset=True)

VERSION = "4.0.0"

# ---- Vulnerability database ----
VULNERABILITIES = {
    "SSLv3": {"risk": "CRITICAL", "exploit": "POODLE", "cve": "CVE-2014-3566", "fix": "Disable SSLv3"},
    "TLSv1.0": {"risk": "HIGH", "exploit": "BEAST", "cve": "CVE-2011-3389", "fix": "Enable TLS 1.2+ only"},
    "TLSv1.1": {"risk": "MEDIUM", "exploit": "POODLE (TLS)", "cve": "CVE-2014-8730", "fix": "Enable TLS 1.2+ only"},
    "CIPHER_NULL": {"risk": "CRITICAL", "exploit": "Eavesdropping", "cve": "N/A", "fix": "Remove NULL ciphers"},
    "CIPHER_EXPORT": {"risk": "HIGH", "exploit": "FREAK", "cve": "CVE-2015-0204", "fix": "Remove export ciphers"},
    "CIPHER_WEAK": {"risk": "MEDIUM", "exploit": "Lucky13", "cve": "CVE-2013-0169", "fix": "Use AEAD ciphers"},
    "CERT_EXPIRED": {"risk": "HIGH", "exploit": "MitM", "cve": "N/A", "fix": "Renew certificate"},
    "CERT_WEAK_SIG": {"risk": "MEDIUM", "exploit": "Forgery", "cve": "CVE-2016-2107", "fix": "Use SHA-256+ signatures"},
    "HSTS_MISSING": {"risk": "MEDIUM", "exploit": "SSL Stripping", "cve": "N/A", "fix": "Add HSTS header"},
}

class TLSScanner:
    def __init__(self, target, threads=10, timeout=10, use_proxy=False, tor=False):
        self.target = target
        self.threads = threads
        self.timeout = timeout
        self.use_proxy = use_proxy
        self.tor = tor
        self.host, self.port = self._parse_target()
        self.results = {}
        self.vulnerabilities = []
        self.cert_info = {}
        self.ciphers = []
        self.start_time = None
        self.queue = queue.Queue()
        self.lock = threading.Lock()
        self.checked = 0
        self.total = 0
        self.risk_score = 0

    def _parse_target(self):
        """Extract hostname and port from URL."""
        if '://' not in self.target:
            self.target = f"https://{self.target}"
        parsed = urlparse(self.target)
        host = parsed.hostname
        port = parsed.port or 443
        return host, port

    def _banner(self):
        print(f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════╗
║  {Fore.GREEN}████████╗██╗     ███████╗███████╗ ██████╗                     {Fore.CYAN}║
║  {Fore.GREEN}╚══██╔══╝██║     ██╔════╝██╔════╝██╔════╝                     {Fore.CYAN}║
║  {Fore.GREEN}   ██║   ██║     █████╗  ███████╗██║                          {Fore.CYAN}║
║  {Fore.GREEN}   ██║   ██║     ██╔══╝  ╚════██║██║                          {Fore.CYAN}║
║  {Fore.GREEN}   ██║   ███████╗███████╗███████║╚██████╗                     {Fore.CYAN}║
║  {Fore.GREEN}   ╚═╝   ╚══════╝╚══════╝╚══════╝ ╚═════╝                     {Fore.CYAN}║
║  {Fore.YELLOW}Advanced HTTPS Security Auditor v{VERSION}                     {Fore.CYAN}║
║  {Fore.YELLOW}"The tool that makes professionals fear your insight."        {Fore.CYAN}║
╚══════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}""")

    def scan(self):
        """Main scanning orchestration."""
        self._banner()
        print(f"{Fore.CYAN}[*] Scanning {self.host}:{self.port}")
        print(f"    Threads: {self.threads}")
        print(f"    Timeout: {self.timeout}s")
        if self.tor:
            print("    Tor: ON")
        if self.use_proxy:
            print("    Proxy rotation: ON")
        self.start_time = datetime.now()

        print(f"\n{Fore.YELLOW}[*] Phase 1: Certificate Analysis")
        self._analyze_certificate()

        print(f"\n{Fore.YELLOW}[*] Phase 2: Cipher Suite Enumeration")
        self._enumerate_ciphers()

        print(f"\n{Fore.YELLOW}[*] Phase 3: Protocol Vulnerability Detection")
        self._detect_protocols()

        print(f"\n{Fore.YELLOW}[*] Phase 4: Security Headers Check")
        self._check_headers()

        print(f"\n{Fore.YELLOW}[*] Phase 5: Risk Assessment")
        self._calculate_risk_score()

        print(f"\n{Fore.YELLOW}[*] Phase 6: Report Generation")
        self._generate_report()

    def _analyze_certificate(self):
        """Fetch and analyze the SSL/TLS certificate."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                    cert = ssock.getpeercert()
                    self.cert_info = {
                        "subject": dict(x[0] for x in cert.get("subject", [])),
                        "issuer": dict(x[0] for x in cert.get("issuer", [])),
                        "not_before": cert.get("notBefore"),
                        "not_after": cert.get("notAfter"),
                        "serial": cert.get("serialNumber"),
                        "version": cert.get("version"),
                        "san": cert.get("subjectAltName", [])
                    }
                    print(f"{Fore.GREEN}[+] Certificate fetched successfully")
                    
                    # Check expiration
                    exp = datetime.strptime(self.cert_info["not_after"], "%b %d %H:%M:%S %Y %Z")
                    days_remaining = (exp - datetime.now()).days
                    
                    if days_remaining < 0:
                        self.vulnerabilities.append(("CERT_EXPIRED", f"Certificate expired {abs(days_remaining)} days ago"))
                        print(f"{Fore.RED}[-] Certificate expired!")
                    elif days_remaining < 30:
                        self.vulnerabilities.append(("CERT_EXPIRING_SOON", f"Certificate expires in {days_remaining} days"))
                        print(f"{Fore.YELLOW}[-] Certificate expires in {days_remaining} days")
                    else:
                        print(f"{Fore.GREEN}[+] Certificate valid for {days_remaining} more days")
                    
        except Exception as e:
            self.vulnerabilities.append(("CERT_UNREACHABLE", f"Cannot fetch cert: {str(e)[:50]}"))
            print(f"{Fore.RED}[-] Failed to fetch certificate")

    def _enumerate_ciphers(self):
        """Test ciphers using modern TLS."""
        cipher_list = [
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "AES256-GCM-SHA384",
            "AES128-GCM-SHA256",
            "ECDHE-RSA-AES256-SHA384",
            "ECDHE-RSA-AES128-SHA256",
            "ECDHE-RSA-AES256-SHA",
            "ECDHE-RSA-AES128-SHA",
            "AES256-SHA",
            "AES128-SHA",
            "DES-CBC3-SHA",
            "RC4-SHA",
            "RC4-MD5",
            "EXP-RC4-MD5",
            "EXP-DES-CBC-SHA",
            "NULL-SHA",
            "NULL-MD5"
        ]
        
        print(f"{Fore.CYAN}[*] Testing {len(cipher_list)} cipher suites...")
        supported = []
        
        for cipher in cipher_list:
            try:
                context = ssl.create_default_context()
                context.set_ciphers(cipher)
                context.check_hostname = False
                with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                        supported.append(cipher)
                        if "NULL" in cipher or "RC4" in cipher or "EXP" in cipher:
                            self.vulnerabilities.append(("CIPHER_WEAK", f"Weak cipher supported: {cipher}"))
                            print(f"{Fore.RED}[-] Weak cipher found: {cipher}")
                        elif "DES" in cipher:
                            self.vulnerabilities.append(("CIPHER_WEAK", f"DES cipher supported: {cipher}"))
                            print(f"{Fore.YELLOW}[-] DES cipher found: {cipher}")
            except:
                pass
        
        self.ciphers = supported
        print(f"{Fore.GREEN}[+] Supported ciphers: {len(supported)}")
        if len(supported) > 0:
            print(f"{Fore.CYAN}    Strongest: {supported[0]}")
        else:
            print(f"{Fore.YELLOW}[-] No modern ciphers detected (likely a bug or compatibility issue)")

    def _detect_protocols(self):
        """Check for insecure protocols."""
        # Use the new SSL context methods
        protocol_tests = {
            "SSLv3": ssl.PROTOCOL_SSLv23,  # This includes SSLv3 but we'll test specifically
            "TLSv1.0": ssl.PROTOCOL_TLSv1,
            "TLSv1.1": ssl.PROTOCOL_TLSv1_1,
            "TLSv1.2": ssl.PROTOCOL_TLSv1_2,
            "TLSv1.3": ssl.PROTOCOL_TLS_CLIENT,
        }
        
        for proto_name, proto_const in protocol_tests.items():
            try:
                context = ssl.SSLContext(proto_const)
                context.check_hostname = False
                with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                        if proto_name in ["SSLv3", "TLSv1.0", "TLSv1.1"]:
                            self.vulnerabilities.append((proto_name, f"Insecure protocol supported: {proto_name}"))
                            print(f"{Fore.RED}[-] Insecure protocol: {proto_name}")
            except:
                if proto_name in ["SSLv3", "TLSv1.0", "TLSv1.1"]:
                    print(f"{Fore.GREEN}[+] Secure: {proto_name} is disabled")
                else:
                    print(f"{Fore.GREEN}[+] Protocol supported: {proto_name}")

    def _check_headers(self):
        """Check security headers."""
        try:
            r = requests.get(f"https://{self.host}:{self.port}", timeout=self.timeout)
            headers = r.headers
            
            security_headers = {
                'strict-transport-security': 'HSTS',
                'x-frame-options': 'X-Frame-Options',
                'x-xss-protection': 'X-XSS-Protection',
                'content-security-policy': 'CSP',
                'x-content-type-options': 'X-Content-Type-Options',
                'referrer-policy': 'Referrer-Policy',
            }
            
            for header, name in security_headers.items():
                if header.lower() not in headers:
                    self.vulnerabilities.append(("MISSING_HEADER", f"Missing security header: {name}"))
                    print(f"{Fore.YELLOW}[-] Missing: {name}")
                else:
                    print(f"{Fore.GREEN}[+] Present: {name}")
            
            if 'strict-transport-security' not in headers:
                self.vulnerabilities.append(("HSTS_MISSING", "HSTS header missing"))
                
        except Exception as e:
            print(f"{Fore.RED}[-] Could not check headers: {str(e)[:50]}")

    def _calculate_risk_score(self):
        """Calculate risk score based on findings."""
        risk_weights = {
            "CRITICAL": 10,
            "HIGH": 7,
            "MEDIUM": 4,
            "LOW": 1,
            "UNKNOWN": 3
        }
        
        total_score = 0
        for vuln, desc in self.vulnerabilities:
            risk = VULNERABILITIES.get(vuln, {}).get("risk", "UNKNOWN")
            total_score += risk_weights.get(risk, 3)
        
        self.risk_score = min(100, total_score)
        
        print(f"\n{Fore.CYAN}[*] Risk Score: {self.risk_score}/100")
        if self.risk_score < 20:
            print(f"{Fore.GREEN}    Status: SECURE")
        elif self.risk_score < 40:
            print(f"{Fore.YELLOW}    Status: FAIR")
        elif self.risk_score < 60:
            print(f"{Fore.ORANGE}    Status: VULNERABLE")
        else:
            print(f"{Fore.RED}    Status: CRITICAL")

    def _generate_report(self):
        """Create professional HTML/JSON report."""
        # Calculate risk distribution
        risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        for vuln, desc in self.vulnerabilities:
            risk = VULNERABILITIES.get(vuln, {}).get("risk", "UNKNOWN")
            risk_counts[risk] = risk_counts.get(risk, 0) + 1
        
        # Prepare report data
        report_data = {
            "target": self.target,
            "host": self.host,
            "port": self.port,
            "timestamp": str(self.start_time),
            "duration": str(datetime.now() - self.start_time),
            "version": VERSION,
            "certificate": self.cert_info,
            "supported_ciphers": self.ciphers,
            "vulnerabilities": [
                {"id": v[0], "description": v[1], "risk": VULNERABILITIES.get(v[0], {}).get("risk", "UNKNOWN")}
                for v in self.vulnerabilities
            ],
            "risk_score": self.risk_score,
            "risk_summary": risk_counts,
            "fix_recommendations": [
                {"id": v[0], "fix": VULNERABILITIES.get(v[0], {}).get("fix", "Unknown")}
                for v in self.vulnerabilities
            ]
        }

        # Save JSON
        with open(f"report_{self.host}.json", 'w') as f:
            json.dump(report_data, f, indent=2)
        print(f"{Fore.GREEN}[+] JSON report saved: report_{self.host}.json")

        # Generate HTML
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>HTTPS Audit Report - {self.host}</title>
            <style>
                body {{ background: #0a0a0a; color: #00ff41; font-family: 'Courier New', monospace; padding: 30px; }}
                .container {{ max-width: 1200px; margin: 0 auto; }}
                h1 {{ color: #00ff41; text-shadow: 0 0 20px #00ff41; border-bottom: 2px solid #00ff41; padding-bottom: 20px; }}
                .risk-critical {{ color: #ff0040; font-weight: bold; }}
                .risk-high {{ color: #ff8000; font-weight: bold; }}
                .risk-medium {{ color: #ffd700; font-weight: bold; }}
                .risk-low {{ color: #69f0ae; font-weight: bold; }}
                .risk-unknown {{ color: #888; }}
                .score-box {{ background: #1a1a1a; padding: 20px; margin: 20px 0; border: 1px solid #00ff41; border-radius: 10px; }}
                .score-value {{ font-size: 48px; font-weight: bold; }}
                table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
                th, td {{ border: 1px solid #00ff41; padding: 12px; text-align: left; }}
                th {{ background: #1a1a1a; color: #00ff41; }}
                tr:hover {{ background: #1a1a1a; }}
                .status-secure {{ color: #00ff41; }}
                .status-fair {{ color: #ffd700; }}
                .status-vulnerable {{ color: #ff8000; }}
                .status-critical {{ color: #ff0040; }}
            </style>
        </head>
        <body>
        <div class="container">
            <h1>🔒 TLSec – Security Audit Report</h1>
            <p><strong>Target:</strong> {self.target}</p>
            <p><strong>Date:</strong> {self.start_time}</p>
            <p><strong>Duration:</strong> {report_data['duration']}</p>
            <p><strong>Version:</strong> {VERSION}</p>
            
            <div class="score-box">
                <h2>Risk Score: <span class="score-value">{self.risk_score}/100</span></h2>
                <p>Status: <span class="{'status-secure' if self.risk_score < 20 else 'status-fair' if self.risk_score < 40 else 'status-vulnerable' if self.risk_score < 60 else 'status-critical'}">
                    {'SECURE' if self.risk_score < 20 else 'FAIR' if self.risk_score < 40 else 'VULNERABLE' if self.risk_score < 60 else 'CRITICAL'}
                </span></p>
                <p>Total Vulnerabilities: {len(self.vulnerabilities)}</p>
            </div>
            
            <h2>Risk Summary</h2>
            <table>
                <tr><th>Risk Level</th><th>Count</th></tr>
                <tr><td class="risk-critical">CRITICAL</td><td>{risk_counts.get('CRITICAL', 0)}</td></tr>
                <tr><td class="risk-high">HIGH</td><td>{risk_counts.get('HIGH', 0)}</td></tr>
                <tr><td class="risk-medium">MEDIUM</td><td>{risk_counts.get('MEDIUM', 0)}</td></tr>
                <tr><td class="risk-low">LOW</td><td>{risk_counts.get('LOW', 0)}</td></tr>
                <tr><td>UNKNOWN</td><td>{risk_counts.get('UNKNOWN', 0)}</td></tr>
            </table>
            
            <h2>Vulnerabilities Detected</h2>
            <table>
                <tr><th>ID</th><th>Risk</th><th>Description</th><th>Fix</th></tr>
        """
        
        for vuln, desc in self.vulnerabilities:
            risk = VULNERABILITIES.get(vuln, {}).get("risk", "UNKNOWN")
            fix = VULNERABILITIES.get(vuln, {}).get("fix", "Unknown")
            risk_class = f"risk-{risk.lower()}" if risk != "UNKNOWN" else "risk-unknown"
            html += f"<tr><td>{vuln}</td><td class='{risk_class}'>{risk}</td><td>{desc}</td><td>{fix}</td></tr>"
        
        html += f"""
            </table>
            
            <h2>Supported Ciphers ({len(self.ciphers)})</h2>
            <ul>
        """
        
        for c in self.ciphers:
            html += f"<li>{c}</li>"
        
        html += f"""
            </ul>
            
            <h2>Certificate Information</h2>
            <p><strong>Subject:</strong> {self.cert_info.get('subject', {}).get('commonName', 'N/A')}</p>
            <p><strong>Issuer:</strong> {self.cert_info.get('issuer', {}).get('commonName', 'N/A')}</p>
            <p><strong>Valid Until:</strong> {self.cert_info.get('not_after', 'N/A')}</p>
            <p><strong>Serial Number:</strong> {self.cert_info.get('serial', 'N/A')}</p>
            
            <p style="margin-top: 40px; border-top: 1px solid #00ff41; padding-top: 20px;">
                <i>Report generated by TLSec v{VERSION} – Advanced HTTPS Security Auditor</i><br>
                <i>Author: Taha | Contact: tth87343@gmail.com</i>
            </p>
        </div>
        </body>
        </html>
        """
        
        with open(f"report_{self.host}.html", 'w') as f:
            f.write(html)
        print(f"{Fore.GREEN}[+] HTML report saved: report_{self.host}.html")
        print(f"{Fore.YELLOW}\n[!] Open report_{self.host}.html in your browser to view.")

def main():
    if len(sys.argv) < 2:
        print(f"{Fore.RED}Usage: python3 tlsec.py <target> [options]")
        print(f"{Fore.YELLOW}\nOptions:")
        print("  --threads N     Number of threads (default: 10)")
        print("  --timeout N     Connection timeout in seconds (default: 10)")
        print("  --tor           Use Tor proxy")
        print("  --proxy         Enable proxy rotation")
        print(f"{Fore.CYAN}\nExample:")
        print("  python3 tlsec.py example.com --threads 20")
        print("  python3 tlsec.py google.com --tor")
        sys.exit(1)

    target = sys.argv[1]
    threads = 10
    timeout = 10
    use_tor = False
    use_proxy = False
    
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == "--threads" and i+1 < len(sys.argv):
            threads = int(sys.argv[i+1])
            i += 2
        elif sys.argv[i] == "--timeout" and i+1 < len(sys.argv):
            timeout = int(sys.argv[i+1])
            i += 2
        elif sys.argv[i] == "--tor":
            use_tor = True
            i += 1
        elif sys.argv[i] == "--proxy":
            use_proxy = True
            i += 1
        else:
            i += 1

    scanner = TLSScanner(target, threads, timeout, use_proxy, use_tor)
    scanner.scan()

if __name__ == "__main__":
    main()



