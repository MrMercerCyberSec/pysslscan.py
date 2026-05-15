#!/usr/bin/env python3
"""
PySSLScan - Lightweight SSL/TLS Security Scanner
Single file, no dependencies, works on Termux & Kali
"""

import socket
import ssl
import json
import sys
import concurrent.futures
from datetime import datetime
from typing import Dict, List, Tuple

# Simple color codes
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
CYAN = '\033[96m'
BOLD = '\033[1m'
END = '\033[0m'

class SSLScanner:
    def __init__(self, target: str, port: int = 443, timeout: int = 10, threads: int = 5):
        self.target = target
        self.port = port
        self.timeout = timeout
        self.threads = threads
        
        # Common cipher suites to test
        self.ciphers = [
            'ECDHE-RSA-AES256-GCM-SHA384',
            'ECDHE-RSA-AES128-GCM-SHA256',
            'DHE-RSA-AES256-GCM-SHA384',
            'DHE-RSA-AES128-GCM-SHA256',
            'AES256-GCM-SHA384',
            'AES128-GCM-SHA256',
            'ECDHE-RSA-AES256-SHA384',
            'ECDHE-RSA-AES128-SHA256',
            'DES-CBC3-SHA',
            'RC4-SHA',
            'RC4-MD5'
        ]

    def banner(self):
        """Display banner"""
        print(f"{CYAN}{'='*50}{END}")
        print(f"{GREEN}  PySSLScan v2.0 - SSL/TLS Security Scanner{END}")
        print(f"{CYAN}{'='*50}{END}")
        print(f"  Target: {self.target}:{self.port}")
        print(f"{CYAN}{'='*50}{END}\n")

    def test_connection(self) -> bool:
        """Test if host is reachable"""
        try:
            socket.create_connection((self.target, self.port), timeout=self.timeout)
            print(f"{GREEN}[✓] Connected to {self.target}:{self.port}{END}\n")
            return True
        except:
            print(f"{RED}[✗] Cannot connect to {self.target}:{self.port}{END}")
            return False

    def test_protocol(self, version) -> bool:
        """Test specific SSL/TLS protocol"""
        try:
            context = ssl.SSLContext(version)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((self.target, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    return True
        except:
            return False

    def scan_protocols(self) -> Dict:
        """Scan all SSL/TLS protocols"""
        print(f"{BLUE}[*] Testing protocols...{END}")
        
        protocols = {
            'SSLv2': getattr(ssl, 'PROTOCOL_SSLv2', None),
            'SSLv3': getattr(ssl, 'PROTOCOL_SSLv3', None),
            'TLSv1.0': getattr(ssl, 'PROTOCOL_TLSv1', None),
            'TLSv1.1': getattr(ssl, 'PROTOCOL_TLSv1_1', None),
            'TLSv1.2': getattr(ssl, 'PROTOCOL_TLSv1_2', None),
            'TLSv1.3': getattr(ssl, 'PROTOCOL_TLSv1_3', None),
        }
        
        results = {}
        for name, proto in protocols.items():
            if proto:
                supported = self.test_protocol(proto)
                results[name] = supported
                status = f"{GREEN}✓ Supported{END}" if supported else f"{RED}✗ Not supported{END}"
                print(f"  {name:10} : {status}")
            else:
                results[name] = False
                print(f"  {name:10} : {YELLOW}⚠ Not available{END}")
        
        return results

    def test_cipher(self, cipher: str) -> bool:
        """Test if cipher is supported"""
        try:
            context = ssl.create_default_context()
            context.set_ciphers(cipher)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((self.target, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    return True
        except:
            return False

    def scan_ciphers(self) -> List[str]:
        """Scan supported ciphers"""
        print(f"\n{BLUE}[*] Testing ciphers...{END}")
        supported = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_cipher = {executor.submit(self.test_cipher, c): c for c in self.ciphers}
            for future in concurrent.futures.as_completed(future_to_cipher):
                cipher = future_to_cipher[future]
                try:
                    if future.result():
                        supported.append(cipher)
                        print(f"  {GREEN}✓{END} {cipher}")
                    else:
                        print(f"  {RED}✗{END} {cipher}")
                except:
                    print(f"  {YELLOW}?{END} {cipher}")
        
        return supported

    def get_certificate(self) -> Dict:
        """Extract certificate info"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.target, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        'subject': str(cert.get('subject', 'N/A')),
                        'issuer': str(cert.get('issuer', 'N/A')),
                        'notBefore': cert.get('notBefore', 'N/A'),
                        'notAfter': cert.get('notAfter', 'N/A'),
                        'serialNumber': cert.get('serialNumber', 'N/A'),
                    }
        except Exception as e:
            return {'error': str(e)}

    def test_heartbleed(self) -> bool:
        """Test Heartbleed vulnerability"""
        try:
            import subprocess
            result = subprocess.run(
                ['openssl', 's_client', '-connect', f'{self.target}:{self.port}', 
                 '-tlsextdebug', '-msg'],
                input=b'Q\n', timeout=5, capture_output=True, stderr=subprocess.STDOUT
            )
            return 'heartbleed' in result.stdout.decode().lower()
        except:
            return False

    def test_poodle(self) -> bool:
        """Test POODLE vulnerability"""
        try:
            if hasattr(ssl, 'PROTOCOL_SSLv3'):
                context = ssl.SSLContext(ssl.PROTOCOL_SSLv3)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with socket.create_connection((self.target, self.port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                        return True
            return False
        except:
            return False

    def test_robot(self) -> bool:
        """Test ROBOT vulnerability"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.target, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    ssock.send(b'\x00\x16\x03\x03\x00\x01\x01')
                    response = ssock.recv(1024)
                    return b'decryption failed' in response or b'bad record mac' in response
        except:
            return False

    def test_breach(self) -> bool:
        """Test BREACH vulnerability"""
        try:
            import http.client
            conn = http.client.HTTPSConnection(self.target, self.port, timeout=self.timeout)
            conn.request('GET', '/', headers={'Accept-Encoding': 'gzip, deflate'})
            response = conn.getresponse()
            headers = dict(response.getheaders())
            conn.close()
            return 'content-encoding' in headers
        except:
            return False

    def scan_vulnerabilities(self) -> Dict:
        """Scan for vulnerabilities (CRIME removed)"""
        print(f"\n{BLUE}[*] Testing vulnerabilities...{END}")
        
        vulns = {
            'Heartbleed': self.test_heartbleed,
            'POODLE': self.test_poodle,
            'ROBOT': self.test_robot,
            'BREACH': self.test_breach,
        }
        
        results = {}
        for name, test_func in vulns.items():
            try:
                vulnerable = test_func()
                results[name] = vulnerable
                status = f"{RED}⚠ VULNERABLE{END}" if vulnerable else f"{GREEN}✓ Safe{END}"
                print(f"  {name:12} : {status}")
            except:
                results[name] = False
                print(f"  {name:12} : {YELLOW}? Error{END}")
        
        return results

    def calculate_risk(self, protocols: Dict, vulnerabilities: Dict) -> Tuple[str, int]:
        """Calculate risk level"""
        score = 100
        
        # Protocol penalties
        if protocols.get('SSLv2', False):
            score -= 30
        if protocols.get('SSLv3', False):
            score -= 25
        if protocols.get('TLSv1.0', False):
            score -= 15
        if protocols.get('TLSv1.1', False):
            score -= 10
        
        # Vulnerability penalties
        if vulnerabilities.get('Heartbleed', False):
            score -= 35
        if vulnerabilities.get('POODLE', False):
            score -= 20
        if vulnerabilities.get('ROBOT', False):
            score -= 15
        if vulnerabilities.get('BREACH', False):
            score -= 10
        
        score = max(0, min(100, score))
        
        if score >= 80:
            return "LOW", score
        elif score >= 60:
            return "MEDIUM", score
        elif score >= 30:
            return "HIGH", score
        else:
            return "CRITICAL", score

    def save_json(self, filename: str, protocols: Dict, ciphers: List, 
                  vulnerabilities: Dict, certificate: Dict, risk_level: str, risk_score: int):
        """Save JSON report"""
        report = {
            'target': self.target,
            'port': self.port,
            'timestamp': datetime.now().isoformat(),
            'risk_level': risk_level,
            'risk_score': risk_score,
            'protocols': protocols,
            'ciphers_supported': ciphers,
            'vulnerabilities': vulnerabilities,
            'certificate': certificate
        }
        
        with open(f"{filename}.json", 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n{GREEN}[✓] Report saved to {filename}.json{END}")

    def run(self):
        """Main scan function"""
        self.banner()
        
        if not self.test_connection():
            return False
        
        # Run all scans
        protocols = self.scan_protocols()
        ciphers = self.scan_ciphers()
        vulnerabilities = self.scan_vulnerabilities()
        certificate = self.get_certificate()
        
        # Calculate risk
        risk_level, risk_score = self.calculate_risk(protocols, vulnerabilities)
        
        # Display summary
        print(f"\n{CYAN}{'='*50}{END}")
        print(f"{BOLD}SCAN SUMMARY{END}")
        print(f"{CYAN}{'='*50}{END}")
        
        risk_color = GREEN
        if risk_level == 'MEDIUM':
            risk_color = YELLOW
        elif risk_level in ['HIGH', 'CRITICAL']:
            risk_color = RED
        
        print(f"Risk Level: {risk_color}{risk_level}{END} ({risk_score}/100)")
        print(f"Protocols: {sum(1 for v in protocols.values() if v)}/6 supported")
        print(f"Ciphers: {len(ciphers)}/{len(self.ciphers)} supported")
        
        vuln_count = sum(1 for v in vulnerabilities.values() if v)
        if vuln_count > 0:
            print(f"{RED}⚠ Found {vuln_count} vulnerabilities!{END}")
        else:
            print(f"{GREEN}✓ No vulnerabilities detected{END}")
        
        if 'notAfter' in certificate and certificate['notAfter'] != 'N/A':
            print(f"Cert expires: {certificate['notAfter'][:10]}")
        
        print(f"{CYAN}{'='*50}{END}\n")
        
        return {
            'protocols': protocols,
            'ciphers': ciphers,
            'vulnerabilities': vulnerabilities,
            'certificate': certificate,
            'risk_level': risk_level,
            'risk_score': risk_score
        }

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='PySSLScan - Lightweight SSL/TLS Security Scanner',
        epilog='Example: python pysslscan.py example.com'
    )
    parser.add_argument('target', help='Target hostname or IP address')
    parser.add_argument('-p', '--port', type=int, default=443, help='Port number (default: 443)')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Timeout in seconds (default: 10)')
    parser.add_argument('--threads', type=int, default=5, help='Threads for scanning (default: 5)')
    parser.add_argument('-o', '--output', help='Save JSON report to file')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')
    
    args = parser.parse_args()
    
    # Disable colors if requested
    if args.no_color:
        global GREEN, RED, YELLOW, BLUE, CYAN, BOLD, END
        GREEN = RED = YELLOW = BLUE = CYAN = BOLD = END = ''
    
    # Run scanner
    scanner = SSLScanner(args.target, args.port, args.timeout, args.threads)
    results = scanner.run()
    
    if results and args.output:
        scanner.save_json(args.output, results['protocols'], results['ciphers'],
                         results['vulnerabilities'], results['certificate'],
                         results['risk_level'], results['risk_score'])

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Scan interrupted{END}")
        sys.exit(0)
    except Exception as e:
        print(f"{RED}[!] Error: {e}{END}")
        sys.exit(1)
