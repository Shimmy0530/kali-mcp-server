#!/usr/bin/env python3
"""
Custom Security Tests - Web Application Security Testing Suite

A comprehensive, standalone security testing tool for web applications.
No Docker or external tools required - just Python with requests library.

Features:
- HTTP method testing
- Security header validation
- SSL/TLS configuration checks
- SQL injection testing
- XSS vulnerability detection
- Directory traversal testing
- Sensitive file exposure
- CORS misconfiguration detection
- Cookie security validation
- Authentication mechanism testing
- Rate limiting detection

Usage:
    python custom_security_tests.py --target https://example.com
    python custom_security_tests.py -t https://example.com --timeout 15 --output results.json

Author: Kali MCP Server Project
License: MIT
"""

import requests
import json
import time
import sys
import ssl
import socket
import concurrent.futures
from datetime import datetime
from urllib.parse import urljoin, urlparse
from pathlib import Path
import re
from typing import Dict, List, Optional, Any
import argparse

# Disable SSL warnings for testing purposes
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SecurityTester:
    """Comprehensive web application security tester"""
    
    def __init__(self, target: str, timeout: int = 10, 
                 rate_limit_delay: float = 0.5, max_workers: int = 5,
                 output_dir: Optional[str] = None, fast_mode: bool = False):
        """
        Initialize the security tester.
        
        Args:
            target: Target URL to test (must include protocol)
            timeout: Request timeout in seconds
            rate_limit_delay: Delay between requests to avoid rate limiting
            max_workers: Maximum concurrent workers for parallel testing
            output_dir: Directory for output files
            fast_mode: Run faster with reduced payloads/endpoints (default: False)
        """
        # Ensure target has protocol
        if not target.startswith(('http://', 'https://')):
            target = f'https://{target}'
            
        self.target = target.rstrip('/')
        self.timeout = timeout
        self.rate_limit_delay = rate_limit_delay
        self.max_workers = max_workers
        
        # Parse target for hostname
        parsed = urlparse(self.target)
        self.hostname = parsed.hostname
        self.scheme = parsed.scheme
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Cache-Control': 'no-cache',
        })
        self.session.verify = False  # Allow self-signed certs for testing
        
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Set output directory
        if output_dir:
            self.output_dir = Path(output_dir)
        else:
            self.output_dir = Path.cwd() / 'output'
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Fast mode for quicker scans
        self.fast_mode = fast_mode
        
        self.results = {
            'timestamp': self.timestamp,
            'target': self.target,
            'hostname': self.hostname,
            'test_start': datetime.now().isoformat(),
            'test_end': None,
            'summary': {
                'total_tests': 0,
                'passed': 0,
                'failed': 0,
                'warnings': 0,
                'errors': 0
            },
            'findings': [],
            'endpoints': [],
            'vulnerabilities': [],
            'info': []
        }
        
    def log(self, message: str, level: str = 'INFO') -> None:
        """Log messages with timestamp and level"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        colors = {
            'INFO': '\033[94m',      # Blue
            'SUCCESS': '\033[92m',   # Green
            'WARNING': '\033[93m',   # Yellow
            'ERROR': '\033[91m',     # Red
            'HIGH': '\033[91m',      # Red
            'MEDIUM': '\033[93m',    # Yellow
            'LOW': '\033[96m',       # Cyan
            'CRITICAL': '\033[95m',  # Magenta
            'RESET': '\033[0m'
        }
        color = colors.get(level, colors['INFO'])
        reset = colors['RESET']
        print(f"{color}[{timestamp}] [{level}]{reset} {message}")
        
    def add_finding(self, severity: str, category: str, description: str, 
                   evidence: Optional[str] = None, remediation: Optional[str] = None) -> None:
        """Add a security finding with detailed information"""
        finding = {
            'severity': severity,
            'category': category,
            'description': description,
            'evidence': evidence,
            'remediation': remediation,
            'timestamp': datetime.now().isoformat(),
            'url': self.target
        }
        
        if severity in ['HIGH', 'CRITICAL']:
            self.results['vulnerabilities'].append(finding)
        elif severity == 'INFO':
            self.results['info'].append(finding)
        else:
            self.results['findings'].append(finding)
            
        # Update summary
        if severity in ['HIGH', 'CRITICAL']:
            self.results['summary']['failed'] += 1
        elif severity == 'MEDIUM':
            self.results['summary']['warnings'] += 1
        elif severity == 'ERROR':
            self.results['summary']['errors'] += 1
        else:
            self.results['summary']['passed'] += 1
            
        self.results['summary']['total_tests'] += 1
        self.log(f"[{severity}] {category}: {description}", level=severity)
        
    def safe_request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """Make a safe HTTP request with error handling"""
        try:
            kwargs.setdefault('timeout', self.timeout)
            kwargs.setdefault('allow_redirects', False)
            response = self.session.request(method, url, **kwargs)
            time.sleep(self.rate_limit_delay)
            return response
        except requests.exceptions.Timeout:
            return None
        except requests.exceptions.ConnectionError:
            return None
        except requests.exceptions.RequestException:
            return None

    def test_http_methods(self) -> Dict[str, bool]:
        """Test various HTTP methods for security issues"""
        self.log("Testing HTTP methods...")
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD', 'TRACE', 'CONNECT']
        results = {}
        dangerous_methods = []
        
        for method in methods:
            response = self.safe_request(method, self.target)
            if response is not None:
                results[method] = response.status_code
                if response.status_code not in [405, 501, 400]:
                    if method in ['TRACE', 'CONNECT']:
                        dangerous_methods.append(method)
                    elif method in ['PUT', 'DELETE'] and response.status_code == 200:
                        dangerous_methods.append(method)
                        
        if dangerous_methods:
            self.add_finding('MEDIUM', 'HTTP Methods', 
                           f'Potentially dangerous HTTP methods allowed: {", ".join(dangerous_methods)}',
                           evidence=f'Methods returning non-405: {results}',
                           remediation='Disable unnecessary HTTP methods in server configuration')
        else:
            self.add_finding('INFO', 'HTTP Methods', 
                           'No dangerous HTTP methods detected',
                           evidence=f'Tested methods: {list(results.keys())}')
                
        return results
    
    def test_security_headers(self) -> Dict[str, Any]:
        """Comprehensive security header testing"""
        self.log("Testing security headers...")
        
        security_headers = {
            'Strict-Transport-Security': {
                'description': 'HSTS enforcement',
                'severity': 'HIGH',
                'recommended': 'max-age=31536000; includeSubDomains; preload',
                'remediation': 'Add HSTS header with at least 1 year max-age'
            },
            'Content-Security-Policy': {
                'description': 'CSP protection against XSS',
                'severity': 'HIGH',
                'recommended': "default-src 'self'",
                'remediation': 'Implement a strict Content Security Policy'
            },
            'X-Frame-Options': {
                'description': 'Clickjacking prevention',
                'severity': 'MEDIUM',
                'recommended': 'DENY or SAMEORIGIN',
                'remediation': 'Add X-Frame-Options header to prevent clickjacking'
            },
            'X-Content-Type-Options': {
                'description': 'MIME sniffing prevention',
                'severity': 'LOW',
                'recommended': 'nosniff',
                'remediation': 'Add X-Content-Type-Options: nosniff header'
            },
            'X-XSS-Protection': {
                'description': 'XSS filter (legacy browsers)',
                'severity': 'LOW',
                'recommended': '1; mode=block',
                'remediation': 'Add X-XSS-Protection header for legacy browser support'
            },
            'Referrer-Policy': {
                'description': 'Control referrer information',
                'severity': 'LOW',
                'recommended': 'strict-origin-when-cross-origin',
                'remediation': 'Add Referrer-Policy header'
            },
            'Permissions-Policy': {
                'description': 'Feature permissions control',
                'severity': 'LOW',
                'recommended': 'geolocation=(), microphone=(), camera=()',
                'remediation': 'Add Permissions-Policy header to restrict browser features'
            }
        }
        
        response = self.safe_request('GET', self.target)
        if not response:
            self.add_finding('ERROR', 'Security Headers', 
                           'Could not fetch target to check security headers')
            return {}
            
        results = {'present': [], 'missing': [], 'weak': []}
        headers = response.headers
        
        for header, config in security_headers.items():
            if header in headers:
                value = headers[header]
                results['present'].append({header: value})
                
                # Check for weak configurations
                if header == 'Strict-Transport-Security':
                    match = re.search(r'max-age=(\d+)', value)
                    if match and int(match.group(1)) < 31536000:
                        results['weak'].append(header)
                        self.add_finding('MEDIUM', 'Security Headers',
                                       f'{header} has weak max-age value',
                                       evidence=f'Value: {value}',
                                       remediation=f'Increase max-age to at least {config["recommended"]}')
                    else:
                        self.add_finding('INFO', 'Security Headers', 
                                       f'{header} is properly configured')
                else:
                    self.add_finding('INFO', 'Security Headers', 
                                   f'{header} is present: {value[:50]}')
            else:
                results['missing'].append(header)
                self.add_finding(config['severity'], 'Security Headers', 
                               f'Missing security header: {header} - {config["description"]}',
                               remediation=config['remediation'])
                
        # Check for information disclosure headers
        info_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version']
        for header in info_headers:
            if header in headers:
                self.add_finding('LOW', 'Information Disclosure',
                               f'Server reveals technology via {header}: {headers[header]}',
                               remediation=f'Remove or obfuscate the {header} header')
                
        return results
    
    def test_ssl_tls(self) -> Dict[str, Any]:
        """Comprehensive SSL/TLS configuration testing"""
        self.log("Testing SSL/TLS configuration...")
        
        if self.scheme != 'https':
            self.add_finding('HIGH', 'SSL/TLS', 
                           'Target is not using HTTPS',
                           remediation='Implement HTTPS with a valid TLS certificate')
            return {'error': 'Not HTTPS'}
            
        hostname = self.hostname
        port = 443
        results = {'protocol': None, 'cipher': None, 'certificate': {}, 'issues': []}
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    protocol = ssock.version()
                    cipher = ssock.cipher()
                    
                    results['protocol'] = protocol
                    results['cipher'] = cipher
                    
                    # Check protocol version
                    if protocol in ['TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2']:
                        self.add_finding('HIGH', 'SSL/TLS', 
                                       f'Weak TLS version detected: {protocol}',
                                       remediation='Disable TLSv1.0, TLSv1.1, and all SSL versions')
                        results['issues'].append(f'Weak protocol: {protocol}')
                    else:
                        self.add_finding('INFO', 'SSL/TLS', f'TLS Protocol: {protocol}')
                    
                    # Check cipher strength
                    if cipher:
                        cipher_name, _, key_bits = cipher
                        if key_bits and key_bits < 128:
                            self.add_finding('HIGH', 'SSL/TLS',
                                           f'Weak cipher key length: {key_bits} bits',
                                           evidence=f'Cipher: {cipher_name}',
                                           remediation='Use ciphers with at least 128-bit key length')
                        
                        weak_ciphers = ['RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT', 'ANON']
                        for weak in weak_ciphers:
                            if weak in cipher_name.upper():
                                self.add_finding('HIGH', 'SSL/TLS',
                                               f'Weak cipher detected: {cipher_name}',
                                               remediation=f'Disable {weak} ciphers')
                    
                    # Check certificate expiration
                    if cert:
                        not_after = cert.get('notAfter')
                        if not_after:
                            try:
                                exp_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                                days_until_expiry = (exp_date - datetime.now()).days
                                if days_until_expiry < 0:
                                    self.add_finding('CRITICAL', 'SSL/TLS',
                                                   'SSL certificate has expired!',
                                                   remediation='Renew the SSL certificate immediately')
                                elif days_until_expiry < 30:
                                    self.add_finding('HIGH', 'SSL/TLS',
                                                   f'SSL certificate expires in {days_until_expiry} days',
                                                   remediation='Renew the SSL certificate soon')
                                else:
                                    self.add_finding('INFO', 'SSL/TLS',
                                                   f'Certificate valid for {days_until_expiry} days')
                            except ValueError:
                                pass
                                
        except ssl.SSLError as e:
            self.add_finding('HIGH', 'SSL/TLS', f'SSL error: {str(e)}')
        except socket.timeout:
            self.add_finding('ERROR', 'SSL/TLS', 'Connection timeout during SSL check')
        except (socket.error, OSError) as e:
            self.add_finding('ERROR', 'SSL/TLS', f'Connection error: {str(e)}')
            
        return results
    
    def test_cors_configuration(self) -> Dict[str, Any]:
        """Test for CORS misconfigurations"""
        self.log("Testing CORS configuration...")
        
        results = {'vulnerable': False, 'details': []}
        
        test_origins = [
            'https://evil.com',
            'https://attacker.com',
            f'https://subdomain.{self.hostname}',
            'null',
            f'https://{self.hostname}.evil.com',
        ]
        
        for origin in test_origins:
            headers = {'Origin': origin}
            response = self.safe_request('GET', self.target, headers=headers)
            
            if response:
                acao = response.headers.get('Access-Control-Allow-Origin', '')
                acac = response.headers.get('Access-Control-Allow-Credentials', '')
                
                if acao == '*':
                    self.add_finding('MEDIUM', 'CORS',
                                   'Wildcard Access-Control-Allow-Origin detected',
                                   evidence=f'ACAO: {acao}',
                                   remediation='Implement a whitelist of allowed origins')
                    results['vulnerable'] = True
                    
                elif acao == origin and origin not in ['null']:
                    if acac.lower() == 'true':
                        self.add_finding('HIGH', 'CORS',
                                       'Arbitrary origin reflected with credentials allowed',
                                       evidence=f'Origin: {origin}, ACAO: {acao}, ACAC: {acac}',
                                       remediation='Do not reflect arbitrary origins with credentials')
                        results['vulnerable'] = True
                    else:
                        self.add_finding('MEDIUM', 'CORS',
                                       'Origin reflection detected',
                                       evidence=f'Origin: {origin}, ACAO: {acao}')
                    
                elif origin == 'null' and acao == 'null':
                    self.add_finding('HIGH', 'CORS',
                                   'Null origin allowed - can be exploited via sandboxed iframes',
                                   remediation='Do not allow null origin')
                    results['vulnerable'] = True
                    
        if not results['vulnerable']:
            self.add_finding('INFO', 'CORS', 'No obvious CORS misconfigurations detected')
            
        return results
    
    def test_cookie_security(self) -> Dict[str, Any]:
        """Test cookie security attributes"""
        self.log("Testing cookie security...")
        
        results = {'cookies': [], 'issues': []}
        
        response = self.safe_request('GET', self.target)
        if not response:
            return results
            
        cookies = response.cookies
        set_cookie_headers = response.headers.get('Set-Cookie', '')
        
        for cookie in cookies:
            cookie_info = {
                'name': cookie.name,
                'secure': cookie.secure,
                'httponly': cookie.has_nonstandard_attr('httponly') or cookie.has_nonstandard_attr('HttpOnly'),
                'samesite': None,
                'issues': []
            }
            
            if 'samesite=strict' in set_cookie_headers.lower():
                cookie_info['samesite'] = 'Strict'
            elif 'samesite=lax' in set_cookie_headers.lower():
                cookie_info['samesite'] = 'Lax'
            elif 'samesite=none' in set_cookie_headers.lower():
                cookie_info['samesite'] = 'None'
                    
            if not cookie_info['secure'] and self.scheme == 'https':
                cookie_info['issues'].append('Missing Secure flag')
                self.add_finding('MEDIUM', 'Cookie Security',
                               f'Cookie "{cookie.name}" missing Secure flag',
                               remediation='Add Secure flag to cookies on HTTPS sites')
                               
            if not cookie_info['httponly'] and cookie.name.lower() in ['session', 'sessionid', 'auth', 'token']:
                cookie_info['issues'].append('Missing HttpOnly flag')
                self.add_finding('HIGH', 'Cookie Security',
                               f'Sensitive cookie "{cookie.name}" missing HttpOnly flag',
                               remediation='Add HttpOnly flag to prevent XSS cookie theft')
                               
            if cookie_info['samesite'] is None:
                cookie_info['issues'].append('Missing SameSite attribute')
                self.add_finding('LOW', 'Cookie Security',
                               f'Cookie "{cookie.name}" missing SameSite attribute',
                               remediation='Add SameSite=Strict or SameSite=Lax attribute')
                               
            results['cookies'].append(cookie_info)
            if cookie_info['issues']:
                results['issues'].extend(cookie_info['issues'])
                
        if not results['issues']:
            self.add_finding('INFO', 'Cookie Security', 'No cookie security issues detected')
            
        return results
    
    def test_sql_injection(self) -> List[Dict[str, Any]]:
        """Test for SQL injection vulnerabilities"""
        self.log("Testing for SQL injection vulnerabilities...")
        
        findings = []
        sql_payloads = [
            ("'", "Single quote"),
            ("' OR '1'='1", "Basic OR injection"),
            ("' OR '1'='1' --", "OR with comment"),
            ("1' AND '1'='1", "AND true"),
            ("1' AND '1'='2", "AND false"),
        ]
        
        sql_errors = [
            ('you have an error in your sql syntax', 'MySQL'),
            ('mysql_fetch', 'MySQL'),
            ('unclosed quotation mark', 'MSSQL'),
            ('ora-', 'Oracle'),
            ('postgresql', 'PostgreSQL'),
            ('sqlite', 'SQLite'),
            ('sql error', 'Generic SQL'),
        ]
        
        # Use fewer endpoints/params in fast mode
        if self.fast_mode:
            test_endpoints = ['/', '/search', '/login']
            test_params = ['id', 'q', 'search']
            payload_limit = 3
        else:
            test_endpoints = ['/', '/search', '/login', '/api', '/product', '/user']
            test_params = ['id', 'q', 'search', 'query', 'page', 'user']
            payload_limit = len(sql_payloads)
        
        # Calculate total tests and show progress info
        total_tests = len(test_endpoints) * len(test_params) * payload_limit
        est_time = total_tests * (self.timeout / 2 + self.rate_limit_delay)
        self.log(f"  → Testing {total_tests} combinations ({len(test_endpoints)} endpoints × {len(test_params)} params × {payload_limit} payloads)")
        self.log(f"  → Estimated time: {est_time/60:.1f}-{est_time/30:.1f} minutes")
        
        for endpoint_idx, endpoint in enumerate(test_endpoints):
            url = urljoin(self.target, endpoint)
            self.log(f"  → [{endpoint_idx+1}/{len(test_endpoints)}] Testing endpoint: {endpoint}", level='INFO')
            
            for param in test_params:
                for payload, description in sql_payloads[:payload_limit]:
                    params = {param: payload}
                    response = self.safe_request('GET', url, params=params)
                    
                    if response:
                        response_lower = response.text.lower()
                        
                        for error_pattern, db_type in sql_errors:
                            if error_pattern in response_lower:
                                finding = {
                                    'url': url,
                                    'parameter': param,
                                    'payload': payload,
                                    'database': db_type
                                }
                                findings.append(finding)
                                self.add_finding('HIGH', 'SQL Injection',
                                               f'Potential SQL injection at {url}?{param}',
                                               evidence=f'Payload: {payload}, DB: {db_type}',
                                               remediation='Use parameterized queries')
                                break
                                
        if not findings:
            self.add_finding('INFO', 'SQL Injection', 'No SQL injection vulnerabilities detected')
            
        return findings
    
    def test_xss(self) -> List[Dict[str, Any]]:
        """Test for XSS vulnerabilities"""
        self.log("Testing for XSS vulnerabilities...")
        
        findings = []
        xss_payloads = [
            ('<script>alert(1)</script>', 'Basic script tag'),
            ('<img src=x onerror=alert(1)>', 'IMG onerror'),
            ('<svg onload=alert(1)>', 'SVG onload'),
            ("'><script>alert(1)</script>", 'Attribute escape'),
            ('"><img src=x onerror=alert(1)>', 'Double quote escape'),
        ]
        
        # Use fewer endpoints/params in fast mode
        if self.fast_mode:
            test_endpoints = ['/', '/search']
            test_params = ['q', 'search', 'name']
            payload_limit = 3
        else:
            test_endpoints = ['/', '/search', '/comment', '/api', '/contact']
            test_params = ['q', 'search', 'query', 'name', 'message']
            payload_limit = len(xss_payloads)
        
        # Calculate total tests and show progress info
        total_tests = len(test_endpoints) * len(test_params) * payload_limit
        est_time = total_tests * (self.timeout / 2 + self.rate_limit_delay)
        self.log(f"  → Testing {total_tests} combinations ({len(test_endpoints)} endpoints × {len(test_params)} params × {payload_limit} payloads)")
        self.log(f"  → Estimated time: {est_time/60:.1f}-{est_time/30:.1f} minutes")
        
        for endpoint_idx, endpoint in enumerate(test_endpoints):
            url = urljoin(self.target, endpoint)
            self.log(f"  → [{endpoint_idx+1}/{len(test_endpoints)}] Testing endpoint: {endpoint}", level='INFO')
            
            for param in test_params:
                for payload, description in xss_payloads[:payload_limit]:
                    params = {param: payload}
                    response = self.safe_request('GET', url, params=params)
                    
                    if response and payload in response.text:
                        # Check if properly encoded
                        if not self._is_properly_encoded(payload, response.text):
                            finding = {
                                'url': url,
                                'parameter': param,
                                'payload': payload,
                                'description': description
                            }
                            findings.append(finding)
                            self.add_finding('MEDIUM', 'XSS',
                                           f'Potential reflected XSS at {url}?{param}',
                                           evidence=f'Payload reflected: {payload[:30]}',
                                           remediation='Implement proper output encoding')
                                           
        if not findings:
            self.add_finding('INFO', 'XSS', 'No XSS vulnerabilities detected')
            
        return findings
    
    def _is_properly_encoded(self, payload: str, response: str) -> bool:
        """Check if payload is properly HTML encoded"""
        encoded_chars = {'<': '&lt;', '>': '&gt;', '"': '&quot;'}
        for char, encoded in encoded_chars.items():
            if char in payload and encoded in response:
                return True
        return False
    
    def test_directory_traversal(self) -> List[Dict[str, Any]]:
        """Test for directory traversal vulnerabilities"""
        self.log("Testing for directory traversal vulnerabilities...")
        
        findings = []
        traversal_payloads = [
            ('../../../etc/passwd', 'Linux passwd'),
            ('..\\..\\..\\windows\\system32\\drivers\\etc\\hosts', 'Windows hosts'),
            ('....//....//....//etc/passwd', 'Bypass filter'),
            ('%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd', 'URL encoded'),
        ]
        
        linux_indicators = ['root:', 'daemon:', 'bin:']
        windows_indicators = ['[extensions]', '[fonts]']
        
        # Use fewer endpoints/params in fast mode
        if self.fast_mode:
            test_endpoints = ['/file', '/download', '/view']
            test_params = ['file', 'path', 'filename']
            payload_limit = 2
        else:
            test_endpoints = ['/file', '/download', '/read', '/view', '/image']
            test_params = ['file', 'path', 'filename', 'document', 'src']
            payload_limit = len(traversal_payloads)
        
        # Calculate total tests and show progress info
        total_tests = len(test_endpoints) * len(test_params) * payload_limit
        est_time = total_tests * (self.timeout / 2 + self.rate_limit_delay)
        self.log(f"  → Testing {total_tests} combinations ({len(test_endpoints)} endpoints × {len(test_params)} params × {payload_limit} payloads)")
        self.log(f"  → Estimated time: {est_time/60:.1f}-{est_time/30:.1f} minutes")
        
        for endpoint_idx, endpoint in enumerate(test_endpoints):
            url = urljoin(self.target, endpoint)
            self.log(f"  → [{endpoint_idx+1}/{len(test_endpoints)}] Testing endpoint: {endpoint}", level='INFO')
            
            for param in test_params:
                for payload, description in traversal_payloads[:payload_limit]:
                    params = {param: payload}
                    response = self.safe_request('GET', url, params=params)
                    
                    if response:
                        response_text = response.text.lower()
                        
                        if any(ind in response_text for ind in linux_indicators):
                            findings.append({'url': url, 'parameter': param, 'payload': payload})
                            self.add_finding('HIGH', 'Directory Traversal',
                                           f'Directory traversal at {url}?{param}',
                                           evidence=f'Payload: {payload}',
                                           remediation='Validate and sanitize file paths')
                                           
                        if any(ind in response_text for ind in windows_indicators):
                            findings.append({'url': url, 'parameter': param, 'payload': payload})
                            self.add_finding('HIGH', 'Directory Traversal',
                                           f'Directory traversal at {url}?{param}',
                                           evidence=f'Payload: {payload}',
                                           remediation='Validate and sanitize file paths')
                                           
        if not findings:
            self.add_finding('INFO', 'Directory Traversal', 'No directory traversal vulnerabilities detected')
            
        return findings
    
    def test_sensitive_files(self) -> List[Dict[str, Any]]:
        """Test for exposed sensitive files"""
        self.log("Testing for exposed sensitive files...")
        
        findings = []
        sensitive_files = [
            ('/.env', 'Environment configuration'),
            ('/.git/config', 'Git configuration'),
            ('/.git/HEAD', 'Git HEAD reference'),
            ('/.htaccess', 'Apache configuration'),
            ('/.htpasswd', 'Apache password file'),
            ('/web.config', 'IIS configuration'),
            ('/phpinfo.php', 'PHP information'),
            ('/robots.txt', 'Robots file'),
            ('/sitemap.xml', 'Sitemap'),
            ('/backup.sql', 'Database backup'),
            ('/config.php', 'PHP configuration'),
            ('/wp-config.php', 'WordPress configuration'),
            ('/composer.json', 'Composer packages'),
            ('/package.json', 'NPM packages'),
            ('/.aws/credentials', 'AWS credentials'),
        ]
        
        high_risk_patterns = ['.env', 'config', 'passwd', 'credentials', 'secret']
        
        def check_file(file_info):
            file_path, description = file_info
            url = urljoin(self.target, file_path)
            response = self.safe_request('GET', url)
            
            if response and response.status_code == 200:
                content_length = len(response.content)
                if content_length > 10:
                    is_high_risk = any(p in file_path.lower() for p in high_risk_patterns)
                    return {
                        'url': url,
                        'file': file_path,
                        'description': description,
                        'status_code': response.status_code,
                        'content_length': content_length,
                        'severity': 'HIGH' if is_high_risk else 'MEDIUM'
                    }
            return None
            
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            results = list(executor.map(check_file, sensitive_files))
            
        for result in results:
            if result:
                findings.append(result)
                self.add_finding(result['severity'], 'Sensitive Files',
                               f'Exposed sensitive file: {result["file"]}',
                               evidence=f'Size: {result["content_length"]} bytes',
                               remediation='Remove or restrict access to sensitive files')
                               
        if not findings:
            self.add_finding('INFO', 'Sensitive Files', 'No exposed sensitive files detected')
            
        return findings
    
    def discover_endpoints(self) -> List[Dict[str, Any]]:
        """Discover API endpoints and common paths"""
        self.log("Discovering endpoints...")
        
        common_paths = [
            '/api', '/api/v1', '/api/v2',
            '/admin', '/administrator', '/wp-admin',
            '/login', '/signin', '/auth',
            '/register', '/signup',
            '/dashboard', '/panel',
            '/graphql', '/swagger', '/api-docs',
            '/health', '/healthcheck', '/status',
            '/metrics', '/actuator/health',
        ]
        
        def check_endpoint(path):
            url = urljoin(self.target, path)
            response = self.safe_request('GET', url)
            
            if response and response.status_code not in [404, 403, 500, 502, 503]:
                return {
                    'url': url,
                    'path': path,
                    'status': response.status_code,
                    'size': len(response.content),
                    'content_type': response.headers.get('Content-Type', 'unknown')
                }
            return None
            
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            results = list(executor.map(check_endpoint, common_paths))
            
        for result in results:
            if result:
                self.results['endpoints'].append(result)
                self.log(f"Found endpoint: {result['path']} (Status: {result['status']})")
                
        return self.results['endpoints']
    
    def test_authentication(self) -> Dict[str, Any]:
        """Test authentication mechanisms"""
        self.log("Testing authentication mechanisms...")
        
        results = {'login_found': False, 'issues': []}
        login_endpoints = ['/login', '/signin', '/auth/login', '/admin/login', '/api/login']
        
        for endpoint in login_endpoints:
            url = urljoin(self.target, endpoint)
            response = self.safe_request('GET', url)
            
            if response and response.status_code == 200:
                results['login_found'] = True
                response_text = response.text.lower()
                
                # Check for CSRF protection
                if 'csrf' not in response_text and '_token' not in response_text:
                    self.add_finding('MEDIUM', 'Authentication',
                                   f'Login form at {url} may lack CSRF protection',
                                   remediation='Implement CSRF tokens on login forms')
                    results['issues'].append('no_csrf')
                    
                # Check for HTTPS
                if not url.startswith('https://'):
                    self.add_finding('HIGH', 'Authentication',
                                   f'Login form at {url} is not served over HTTPS',
                                   remediation='Serve login pages exclusively over HTTPS')
                    results['issues'].append('no_https')
                    
        if not results['issues']:
            self.add_finding('INFO', 'Authentication', 'No authentication vulnerabilities detected')
            
        return results
    
    def test_rate_limiting(self) -> Dict[str, Any]:
        """Test for rate limiting on sensitive endpoints"""
        self.log("Testing rate limiting...")
        
        results = {'rate_limited': False, 'endpoints_tested': []}
        
        # Use fewer endpoints in fast mode
        if self.fast_mode:
            test_endpoints = ['/login']
            request_count = 5
        else:
            test_endpoints = ['/login', '/api/login', '/register']
            request_count = 10
        
        # Progress info
        self.log(f"  → Testing {len(test_endpoints)} endpoints with {request_count} requests each")
        
        for endpoint_idx, endpoint in enumerate(test_endpoints):
            url = urljoin(self.target, endpoint)
            self.log(f"  → [{endpoint_idx+1}/{len(test_endpoints)}] Testing rate limit on: {endpoint}", level='INFO')
            blocked_at = None
            
            for i in range(request_count):
                response = self.safe_request('POST', url, data={'username': 'test', 'password': 'test'})
                if response:
                    if response.status_code == 429:
                        blocked_at = i + 1
                        break
                        
            result = {
                'endpoint': endpoint,
                'requests_sent': request_count,
                'blocked_at': blocked_at,
                'rate_limited': blocked_at is not None
            }
            results['endpoints_tested'].append(result)
            
            if blocked_at:
                results['rate_limited'] = True
                self.add_finding('INFO', 'Rate Limiting',
                               f'Rate limiting detected at {url} after {blocked_at} requests')
            else:
                self.add_finding('MEDIUM', 'Rate Limiting',
                               f'No rate limiting detected at {url}',
                               evidence=f'Sent {request_count} requests without being blocked',
                               remediation='Implement rate limiting on authentication endpoints')
                               
        return results
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Run all security tests"""
        self.log("=" * 60)
        self.log("Starting comprehensive security testing...")
        self.log(f"Target: {self.target}")
        self.log("=" * 60)
        
        try:
            # Time warning for users
            if self.fast_mode:
                self.log("⏱  Running in FAST mode - estimated time: 2-5 minutes", level='WARNING')
            else:
                self.log("⏱  HEADS UP: Full security scan will take 10-20 minutes", level='WARNING')
                self.log("   Progress updates will be shown for long-running tests", level='WARNING')
                self.log("   Use --fast flag for quicker scans with fewer payloads", level='WARNING')
            
            # Basic connectivity test
            response = self.safe_request('GET', self.target)
            if not response:
                self.add_finding('ERROR', 'Connectivity', 
                               f'Failed to connect to target: {self.target}')
                return self.results
                
            self.log(f"Target is reachable (Status: {response.status_code})")
            
            # Run all test categories
            test_functions = [
                ('HTTP Methods', self.test_http_methods),
                ('Security Headers', self.test_security_headers),
                ('SSL/TLS', self.test_ssl_tls),
                ('CORS Configuration', self.test_cors_configuration),
                ('Cookie Security', self.test_cookie_security),
                ('Endpoint Discovery', self.discover_endpoints),
                ('Sensitive Files', self.test_sensitive_files),
                ('Authentication', self.test_authentication),
                ('Rate Limiting', self.test_rate_limiting),
                ('SQL Injection', self.test_sql_injection),
                ('XSS', self.test_xss),
                ('Directory Traversal', self.test_directory_traversal),
            ]
            
            for test_name, test_func in test_functions:
                self.log(f"\n{'='*40}")
                self.log(f"Running: {test_name}")
                self.log(f"{'='*40}")
                try:
                    test_func()
                except Exception as e:
                    self.add_finding('ERROR', test_name, f'Test failed with error: {str(e)}')
                    
            self.results['test_end'] = datetime.now().isoformat()
            self.log("\n" + "=" * 60)
            self.log("All tests completed")
            self.log("=" * 60)
            
        except Exception as e:
            self.add_finding('ERROR', 'Test Execution', f'Critical error during testing: {str(e)}')
            
        return self.results
    
    def save_results(self, output_file: Optional[str] = None) -> str:
        """Save test results to JSON file"""
        if output_file is None:
            output_file = str(self.output_dir / f"security_test_{self.timestamp}.json")
        else:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        self.log(f"Results saved to {output_file}")
        return output_file
    
    def print_summary(self) -> None:
        """Print test summary to console"""
        print("\n" + "=" * 60)
        print("SECURITY TEST SUMMARY")
        print("=" * 60)
        print(f"Target: {self.target}")
        print(f"Timestamp: {self.timestamp}")
        print(f"\nTotal Tests: {self.results['summary']['total_tests']}")
        print(f"  \033[92m✓ Passed:   {self.results['summary']['passed']}\033[0m")
        print(f"  \033[93m⚠ Warnings: {self.results['summary']['warnings']}\033[0m")
        print(f"  \033[91m✗ Failed:   {self.results['summary']['failed']}\033[0m")
        print(f"  \033[94mℹ Errors:   {self.results['summary']['errors']}\033[0m")
        
        if self.results['vulnerabilities']:
            print(f"\n\033[91mCRITICAL/HIGH VULNERABILITIES FOUND:\033[0m")
            for vuln in self.results['vulnerabilities'][:5]:
                print(f"  • [{vuln['severity']}] {vuln['category']}: {vuln['description']}")
                
        print(f"\nEndpoints discovered: {len(self.results['endpoints'])}")
        print("=" * 60)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Web Application Security Tester',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python custom_security_tests.py --target https://example.com
  python custom_security_tests.py -t https://example.com --timeout 15
  python custom_security_tests.py -t example.com --fast --output results.json
        """
    )
    parser.add_argument('--target', '-t', required=True,
                       help='Target URL to test (e.g., https://example.com)')
    parser.add_argument('--timeout', type=int, default=10,
                       help='Request timeout in seconds (default: 10)')
    parser.add_argument('--rate-limit', type=float, default=0.5,
                       help='Delay between requests in seconds (default: 0.5)')
    parser.add_argument('--workers', type=int, default=5,
                       help='Maximum concurrent workers (default: 5)')
    parser.add_argument('--fast', action='store_true',
                       help='Run faster with reduced payloads/endpoints')
    parser.add_argument('--output', '-o', help='Output file path for results')
    parser.add_argument('--output-dir', help='Output directory for results')
    
    args = parser.parse_args()
    
    tester = SecurityTester(
        target=args.target,
        timeout=args.timeout,
        rate_limit_delay=args.rate_limit,
        max_workers=args.workers,
        output_dir=args.output_dir,
        fast_mode=args.fast
    )
    
    tester.run_all_tests()
    tester.save_results(args.output)
    tester.print_summary()
    
    # Return non-zero if critical vulnerabilities found
    if tester.results['summary']['failed'] > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == '__main__':
    main()

