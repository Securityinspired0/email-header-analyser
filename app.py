from flask import Flask, render_template, request, jsonify, send_file
import re
import dns.resolver
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
import json
import requests
import ipaddress
from datetime import datetime
import os
from dotenv import load_dotenv
import email.utils
import email
from werkzeug.utils import secure_filename
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
import tempfile

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['UPLOAD_FOLDER'] = 'uploads'

class EmailHeaderAnalyser:
    def __init__(self):
        self.dkim_pattern = re.compile(r'^DKIM-Signature:\s*(.+)$', re.IGNORECASE | re.MULTILINE)
        self.spf_pattern = re.compile(r'^Received-SPF:\s*(.+)$', re.IGNORECASE | re.MULTILINE)
        self.dmarc_pattern = re.compile(r'^Authentication-Results:\s*(.+)$', re.IGNORECASE | re.MULTILINE)
        self.received_pattern = re.compile(r'^Received:\s*(.+)$', re.IGNORECASE | re.MULTILINE)
        self.from_pattern = re.compile(r'^From:\s*(.+)$', re.IGNORECASE | re.MULTILINE)
        self.to_pattern = re.compile(r'^To:\s*(.+)$', re.IGNORECASE | re.MULTILINE)
        self.subject_pattern = re.compile(r'^Subject:\s*(.+)$', re.IGNORECASE | re.MULTILINE)
        self.date_pattern = re.compile(r'^Date:\s*(.+)$', re.IGNORECASE | re.MULTILINE)
        self.message_id_pattern = re.compile(r'^Message-ID:\s*(.+)$', re.IGNORECASE | re.MULTILINE)
        self.return_path_pattern = re.compile(r'^Return-Path:\s*(.+)$', re.IGNORECASE | re.MULTILINE)
        self.reply_to_pattern = re.compile(r'^Reply-To:\s*(.+)$', re.IGNORECASE | re.MULTILINE)
        self.ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        
        # API Keys (load from environment variables)
        self.abuseipdb_key = os.getenv('ABUSEIPDB_API_KEY', '')
        self.virustotal_key = os.getenv('VIRUSTOTAL_API_KEY', '')
        self.ipqualityscore_key = os.getenv('IPQUALITYSCORE_API_KEY', '')
        self.talos_key = os.getenv('TALOS_API_KEY', '')
        
    def check_ip_reputation(self, ip):
        """Check IP reputation using multiple APIs with enhanced analysis"""
        reputation_data = {
            'ip': ip,
            'abuseipdb': self.check_abuseipdb(ip),
            'virustotal': self.check_virustotal_ip(ip),
            'ipqualityscore': self.check_ipqualityscore(ip),
            'overall_score': 0,
            'risk_level': 'Unknown',
            'flags': [],
            'detailed_analysis': {},
            'recommendations': [],
            'threat_categories': [],
            'last_seen': None,
            'reputation_age': None
        }
        
        # Enhanced risk calculation with weighted scoring
        scores = []
        weights = []
        
        if reputation_data['abuseipdb']['score'] is not None:
            scores.append(reputation_data['abuseipdb']['score'])
            weights.append(0.4)  # AbuseIPDB gets higher weight
        if reputation_data['virustotal']['score'] is not None:
            scores.append(reputation_data['virustotal']['score'])
            weights.append(0.35)  # VirusTotal gets medium weight
        if reputation_data['ipqualityscore']['score'] is not None:
            scores.append(reputation_data['ipqualityscore']['score'])
            weights.append(0.25)  # IPQualityScore gets lower weight
        
        if scores:
            # Calculate weighted average
            total_weight = sum(weights)
            reputation_data['overall_score'] = sum(score * weight for score, weight in zip(scores, weights)) / total_weight
            
            # Enhanced risk level determination
            if reputation_data['overall_score'] >= 80:
                reputation_data['risk_level'] = 'Critical'
                reputation_data['flags'].append('Critical risk IP detected')
                reputation_data['recommendations'].append('Block this IP immediately')
                reputation_data['recommendations'].append('Report to security team')
            elif reputation_data['overall_score'] >= 60:
                reputation_data['risk_level'] = 'High'
                reputation_data['flags'].append('High risk IP detected')
                reputation_data['recommendations'].append('Monitor this IP closely')
                reputation_data['recommendations'].append('Consider blocking if suspicious activity continues')
            elif reputation_data['overall_score'] >= 40:
                reputation_data['risk_level'] = 'Medium'
                reputation_data['flags'].append('Medium risk IP detected')
                reputation_data['recommendations'].append('Monitor for suspicious activity')
            elif reputation_data['overall_score'] >= 20:
                reputation_data['risk_level'] = 'Low'
                reputation_data['flags'].append('Low risk IP detected')
                reputation_data['recommendations'].append('Continue monitoring')
            else:
                reputation_data['risk_level'] = 'Safe'
                reputation_data['flags'].append('IP appears safe')
                reputation_data['recommendations'].append('No immediate action required')
        
        # Collect threat categories from all sources
        if reputation_data['abuseipdb'].get('categories'):
            reputation_data['threat_categories'].extend(reputation_data['abuseipdb']['categories'])
        if reputation_data['virustotal'].get('categories'):
            reputation_data['threat_categories'].extend(reputation_data['virustotal']['categories'])
        
        # Add detailed analysis
        reputation_data['detailed_analysis'] = {
            'abuseipdb_analysis': self.analyze_abuseipdb_data(reputation_data['abuseipdb']),
            'virustotal_analysis': self.analyze_virustotal_data(reputation_data['virustotal']),
            'ipqualityscore_analysis': self.analyze_ipqualityscore_data(reputation_data['ipqualityscore'])
        }
        
        return reputation_data
    
    def check_domain_reputation(self, domain):
        """Check domain reputation using multiple APIs with enhanced analysis including Talos Intelligence"""
        reputation_data = {
            'domain': domain,
            'virustotal': self.check_virustotal_domain(domain),
            'ipqualityscore': self.check_ipqualityscore_domain(domain),
            'talos': self.check_talos_domain(domain),
            'overall_score': 0,
            'risk_level': 'Unknown',
            'flags': [],
            'detailed_analysis': {},
            'recommendations': [],
            'threat_categories': [],
            'domain_age': None,
            'ssl_status': None,
            'dns_health': None
        }
        
        # Enhanced risk calculation with Talos Intelligence
        scores = []
        weights = []
        
        if reputation_data['virustotal']['score'] is not None:
            scores.append(reputation_data['virustotal']['score'])
            weights.append(0.4)  # VirusTotal gets medium weight
        if reputation_data['ipqualityscore']['score'] is not None:
            scores.append(reputation_data['ipqualityscore']['score'])
            weights.append(0.25)  # IPQualityScore gets lower weight
        if reputation_data['talos']['score'] is not None:
            scores.append(reputation_data['talos']['score'])
            weights.append(0.35)  # Talos Intelligence gets higher weight for domains
        
        if scores:
            # Calculate weighted average
            total_weight = sum(weights)
            reputation_data['overall_score'] = sum(score * weight for score, weight in zip(scores, weights)) / total_weight
            
            # Enhanced risk level determination
            if reputation_data['overall_score'] >= 80:
                reputation_data['risk_level'] = 'Critical'
                reputation_data['flags'].append('Critical risk domain detected')
                reputation_data['recommendations'].append('Block this domain immediately')
                reputation_data['recommendations'].append('Report to security team')
            elif reputation_data['overall_score'] >= 60:
                reputation_data['risk_level'] = 'High'
                reputation_data['flags'].append('High risk domain detected')
                reputation_data['recommendations'].append('Monitor this domain closely')
                reputation_data['recommendations'].append('Consider blocking if suspicious activity continues')
            elif reputation_data['overall_score'] >= 40:
                reputation_data['risk_level'] = 'Medium'
                reputation_data['flags'].append('Medium risk domain detected')
                reputation_data['recommendations'].append('Monitor for suspicious activity')
            elif reputation_data['overall_score'] >= 20:
                reputation_data['risk_level'] = 'Low'
                reputation_data['flags'].append('Low risk domain detected')
                reputation_data['recommendations'].append('Continue monitoring')
            else:
                reputation_data['risk_level'] = 'Safe'
                reputation_data['flags'].append('Domain appears safe')
                reputation_data['recommendations'].append('No immediate action required')
        
        # Add detailed analysis including Talos
        reputation_data['detailed_analysis'] = {
            'virustotal_analysis': self.analyze_virustotal_domain_data(reputation_data['virustotal']),
            'ipqualityscore_analysis': self.analyze_ipqualityscore_domain_data(reputation_data['ipqualityscore']),
            'talos_analysis': self.analyze_talos_domain_data(reputation_data['talos'])
        }
        
        return reputation_data
    
    def check_abuseipdb(self, ip):
        """Check IP reputation using AbuseIPDB API"""
        if not self.abuseipdb_key:
            return {'score': None, 'details': 'API key not configured', 'categories': []}
        
        try:
            url = f'https://api.abuseipdb.com/api/v2/check'
            headers = {
                'Accept': 'application/json',
                'Key': self.abuseipdb_key
            }
            params = {
                'ipAddress': ip,
                'maxAgeInDays': '90'
            }
            
            response = requests.get(url, headers=headers, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                abuse_confidence = data['data']['abuseConfidenceScore']
                categories = data['data']['reports']
                
                return {
                    'score': abuse_confidence,
                    'details': f'Abuse confidence: {abuse_confidence}%',
                    'categories': categories,
                    'total_reports': len(categories)
                }
            else:
                return {'score': None, 'details': f'API error: {response.status_code}', 'categories': []}
                
        except Exception as e:
            return {'score': None, 'details': f'API error: {str(e)}', 'categories': []}
    
    def check_virustotal_ip(self, ip):
        """Check IP reputation using VirusTotal API"""
        if not self.virustotal_key:
            return {'score': None, 'details': 'API key not configured', 'malicious_votes': 0, 'suspicious_votes': 0}
        
        try:
            url = f'https://www.virustotal.com/vtapi/v2/ip-address/report'
            params = {
                'apikey': self.virustotal_key,
                'ip': ip
            }
            
            response = requests.get(url, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('response_code') == 1:
                    positives = data.get('positives', 0)
                    total = data.get('total', 0)
                    score = (positives / total * 100) if total > 0 else 0
                    
                    return {
                        'score': score,
                        'details': f'{positives}/{total} security vendors flagged this IP',
                        'malicious_votes': positives,
                        'suspicious_votes': data.get('suspicious_votes', 0),
                        'harmless_votes': data.get('harmless_votes', 0)
                    }
                else:
                    return {'score': None, 'details': 'IP not found in VirusTotal', 'malicious_votes': 0, 'suspicious_votes': 0}
            else:
                return {'score': None, 'details': f'API error: {response.status_code}', 'malicious_votes': 0, 'suspicious_votes': 0}
                
        except Exception as e:
            return {'score': None, 'details': f'API error: {str(e)}', 'malicious_votes': 0, 'suspicious_votes': 0}
    
    def check_virustotal_domain(self, domain):
        """Check domain reputation using VirusTotal API"""
        if not self.virustotal_key:
            return {'score': None, 'details': 'API key not configured', 'malicious_votes': 0, 'suspicious_votes': 0}
        
        try:
            url = f'https://www.virustotal.com/vtapi/v2/domain/report'
            params = {
                'apikey': self.virustotal_key,
                'domain': domain
            }
            
            response = requests.get(url, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('response_code') == 1:
                    positives = data.get('positives', 0)
                    total = data.get('total', 0)
                    score = (positives / total * 100) if total > 0 else 0
                    
                    return {
                        'score': score,
                        'details': f'{positives}/{total} security vendors flagged this domain',
                        'malicious_votes': positives,
                        'suspicious_votes': data.get('suspicious_votes', 0),
                        'harmless_votes': data.get('harmless_votes', 0)
                    }
                else:
                    return {'score': None, 'details': 'Domain not found in VirusTotal', 'malicious_votes': 0, 'suspicious_votes': 0}
            else:
                return {'score': None, 'details': f'API error: {response.status_code}', 'malicious_votes': 0, 'suspicious_votes': 0}
                
        except Exception as e:
            return {'score': None, 'details': f'API error: {str(e)}', 'malicious_votes': 0, 'suspicious_votes': 0}
    
    def check_ipqualityscore(self, ip):
        """Check IP reputation using IPQualityScore API"""
        if not self.ipqualityscore_key:
            return {'score': None, 'details': 'API key not configured', 'proxy': False, 'vpn': False}
        
        try:
            url = f'https://www.ipqualityscore.com/api/json/ip/{self.ipqualityscore_key}/{ip}'
            
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    # Calculate risk score based on various factors
                    risk_score = 0
                    if data.get('proxy', False):
                        risk_score += 30
                    if data.get('vpn', False):
                        risk_score += 20
                    if data.get('tor', False):
                        risk_score += 40
                    if data.get('fraud_score', 0) > 50:
                        risk_score += data.get('fraud_score', 0)
                    
                    return {
                        'score': min(risk_score, 100),
                        'details': f'Proxy: {data.get("proxy", False)}, VPN: {data.get("vpn", False)}, Tor: {data.get("tor", False)}',
                        'proxy': data.get('proxy', False),
                        'vpn': data.get('vpn', False),
                        'tor': data.get('tor', False),
                        'fraud_score': data.get('fraud_score', 0)
                    }
                else:
                    return {'score': None, 'details': 'IP not found in IPQualityScore', 'proxy': False, 'vpn': False}
            else:
                return {'score': None, 'details': f'API error: {response.status_code}', 'proxy': False, 'vpn': False}
                
        except Exception as e:
            return {'score': None, 'details': f'API error: {str(e)}', 'proxy': False, 'vpn': False}
    
    def check_ipqualityscore_domain(self, domain):
        """Check domain reputation using IPQualityScore API"""
        if not self.ipqualityscore_key:
            return {'score': None, 'details': 'API key not configured', 'disposable': False, 'suspicious': False}
        
        try:
            url = f'https://www.ipqualityscore.com/api/json/email/{self.ipqualityscore_key}/{domain}'
            
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    # Calculate risk score based on various factors
                    risk_score = 0
                    if data.get('disposable', False):
                        risk_score += 40
                    if data.get('suspicious', False):
                        risk_score += 30
                    if data.get('valid', False) == False:
                        risk_score += 50
                    
                    return {
                        'score': min(risk_score, 100),
                        'details': f'Disposable: {data.get("disposable", False)}, Suspicious: {data.get("suspicious", False)}',
                        'disposable': data.get('disposable', False),
                        'suspicious': data.get('suspicious', False),
                        'valid': data.get('valid', True)
                    }
                else:
                    return {'score': None, 'details': 'Domain not found in IPQualityScore', 'disposable': False, 'suspicious': False}
            else:
                return {'score': None, 'details': f'API error: {response.status_code}', 'disposable': False, 'suspicious': False}
                
        except Exception as e:
            return {'score': None, 'details': f'API error: {str(e)}', 'disposable': False, 'suspicious': False}

    def check_talos_domain(self, domain):
        """Check domain reputation using Talos Intelligence API"""
        if not self.talos_key:
            return {'score': None, 'details': 'API key not configured', 'categories': [], 'reputation': 'Unknown'}
        
        try:
            # Talos Intelligence API endpoint for domain reputation
            url = f'https://reputation.cisco.com/v1/domains/{domain}'
            headers = {
                'Authorization': f'Bearer {self.talos_key}',
                'Content-Type': 'application/json'
            }
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                # Extract reputation information
                reputation = data.get('reputation', 'Unknown')
                categories = data.get('categories', [])
                score = data.get('score', 0)
                
                # Convert reputation to risk score
                risk_score = 0
                if reputation == 'Poor':
                    risk_score = 80
                elif reputation == 'Fair':
                    risk_score = 60
                elif reputation == 'Good':
                    risk_score = 20
                elif reputation == 'Excellent':
                    risk_score = 5
                else:
                    risk_score = 50  # Unknown reputation
                
                return {
                    'score': risk_score,
                    'details': f'Talos reputation: {reputation} (Score: {score})',
                    'categories': categories,
                    'reputation': reputation,
                    'raw_score': score,
                    'last_updated': data.get('last_updated', 'Unknown'),
                    'domain_age': data.get('domain_age', 'Unknown')
                }
            elif response.status_code == 404:
                return {
                    'score': 30,  # Medium risk for unknown domains
                    'details': 'Domain not found in Talos database',
                    'categories': [],
                    'reputation': 'Unknown',
                    'raw_score': 0
                }
            else:
                return {'score': None, 'details': f'API error: {response.status_code}', 'categories': [], 'reputation': 'Unknown'}
                
        except Exception as e:
            return {'score': None, 'details': f'API error: {str(e)}', 'categories': [], 'reputation': 'Unknown'}

    def extract_headers(self, headers_text):
        """Extract and organize key email headers"""
        headers = {}
        
        # Extract From header and separate name and email
        from_match = self.from_pattern.search(headers_text)
        if from_match:
            from_value = from_match.group(1).strip()
            # Parse the From header to separate name and email
            from_name, from_email = self.parse_from_header(from_value)
            headers['from_name'] = from_name
            headers['from_email'] = from_email
        else:
            headers['from_name'] = 'Not Found'
            headers['from_email'] = 'Not Found'
        
        # Extract To header
        to_match = self.to_pattern.search(headers_text)
        if to_match:
            headers['to'] = to_match.group(1).strip()
        else:
            headers['to'] = 'Not Found'
        
        # Extract Subject header
        subject_match = self.subject_pattern.search(headers_text)
        if subject_match:
            headers['subject'] = subject_match.group(1).strip()
        else:
            headers['subject'] = 'Not Found'
        
        # Extract Date header
        date_match = self.date_pattern.search(headers_text)
        if date_match:
            headers['date'] = date_match.group(1).strip()
        else:
            headers['date'] = 'Not Found'
        
        # Extract Message-ID header
        message_id_match = self.message_id_pattern.search(headers_text)
        if message_id_match:
            headers['message_id'] = message_id_match.group(1).strip()
        else:
            headers['message_id'] = 'Not Found'
        
        # Extract Return-Path header
        return_path_match = self.return_path_pattern.search(headers_text)
        if return_path_match:
            headers['return_path'] = return_path_match.group(1).strip()
        else:
            headers['return_path'] = 'Not Found'
        
        # Extract Reply-To header
        reply_to_match = self.reply_to_pattern.search(headers_text)
        if reply_to_match:
            headers['reply_to'] = reply_to_match.group(1).strip()
        else:
            headers['reply_to'] = 'Not Found'
        
        # Extract DKIM-Signature header
        dkim_match = self.dkim_pattern.search(headers_text)
        if dkim_match:
            headers['dkim_signature'] = dkim_match.group(1).strip()
        else:
            headers['dkim_signature'] = 'Not Found'
        
        # Extract Received-SPF header
        spf_match = self.spf_pattern.search(headers_text)
        if spf_match:
            headers['received_spf'] = spf_match.group(1).strip()
        else:
            headers['received_spf'] = 'Not Found'
        
        # Extract Authentication-Results header
        auth_results_match = self.dmarc_pattern.search(headers_text)
        if auth_results_match:
            headers['authentication_results'] = auth_results_match.group(1).strip()
        else:
            headers['authentication_results'] = 'Not Found'
        
        return headers
    
    def parse_from_header(self, from_value):
        """Parse From header to extract name and email separately"""
        # Pattern to match "Display Name" <email@domain.com> or just email@domain.com
        email_pattern = r'<([^>]+)>'
        email_match = re.search(email_pattern, from_value)
        
        if email_match:
            # Format: "Display Name" <email@domain.com>
            email = email_match.group(1).strip()
            # Extract name by removing the email part
            name = re.sub(email_pattern, '', from_value).strip()
            # Remove quotes if present
            name = re.sub(r'^["\']|["\']$', '', name).strip()
            return name, email
        else:
            # Format: just email@domain.com
            # Check if it's a valid email
            email_pattern_simple = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if re.match(email_pattern_simple, from_value.strip()):
                return '', from_value.strip()
            else:
                # Invalid format, return as is
                return '', from_value.strip()
    
    def domains_match(self, domain1, domain2):
        """Check if two domains match (case-insensitive and subdomain-aware)"""
        if not domain1 or not domain2:
            return False
        
        # Convert to lowercase for case-insensitive comparison
        domain1_lower = domain1.lower()
        domain2_lower = domain2.lower()
        
        # Direct match
        if domain1_lower == domain2_lower:
            return True
        
        # Check if one is a subdomain of the other
        # Split domains into parts
        parts1 = domain1_lower.split('.')
        parts2 = domain2_lower.split('.')
        
        # Check if one domain ends with the other (subdomain relationship)
        if len(parts1) > len(parts2):
            # domain1 is longer, check if it ends with domain2
            if '.'.join(parts1[-len(parts2):]) == domain2_lower:
                return True
        elif len(parts2) > len(parts1):
            # domain2 is longer, check if it ends with domain1
            if '.'.join(parts2[-len(parts1):]) == domain1_lower:
                return True
        
        return False
    
    def extract_domain_from_email(self, email_string):
        """Extract domain from email address"""
        if not email_string:
            return None
        
        # Handle various email formats
        email_match = re.search(r'[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', email_string)
        if email_match:
            return email_match.group(1)
        
        return None
    
    def extract_all_header_values(self, headers_text, header_name):
        """Extract all values for a specific header (for headers that may appear multiple times)"""
        pattern = re.compile(f'^{re.escape(header_name)}:\\s*(.+)$', re.IGNORECASE | re.MULTILINE)
        matches = pattern.findall(headers_text)
        return matches
    
    def extract_header_value(self, headers_text, header_name):
        """Extract the value of a specific header"""
        pattern = re.compile(f'^{re.escape(header_name)}:\\s*(.+)$', re.IGNORECASE | re.MULTILINE)
        match = pattern.search(headers_text)
        if match:
            return match.group(1).strip()
        return None
    
    def analyse_headers(self, headers_text):
        """Analyse email headers for DKIM, SPF, and DMARC with enhanced features"""
        results = {
            'headers_found': self.extract_headers(headers_text),
            'dkim': self.analyze_dkim(headers_text),
            'spf': self.analyze_spf(headers_text),
            'dmarc': self.analyze_dmarc(headers_text),
            'geolocation': self.analyze_geolocation(headers_text),
            'threat_intelligence': self.analyze_threat_intelligence(headers_text),
            'network_analysis': self.analyze_network(headers_text),
            'domain_analysis': self.analyze_domains(headers_text),
            'spoofing_analysis': self.analyze_spoofing(headers_text),
            'reputation_analysis': self.analyze_reputation(headers_text),
            'mismatch_analysis': self.detect_mismatches_and_warnings(headers_text),
            'compliance_and_forensics': self.analyze_compliance_and_forensics(headers_text),
            'summary': {}
        }
        
        # Create enhanced summary
        results['summary'] = {
            'dkim_status': results['dkim']['status'],
            'spf_status': results['spf']['status'],
            'dmarc_status': results['dmarc']['status'],
            'overall_score': self.calculate_security_score(results),
            'risk_assessment': self.calculate_risk_assessment(results),
            'recommendations': self.generate_recommendations(results)
        }
        
        return results
    
    def analyze_reputation(self, headers_text):
        """Analyze IP and domain reputation using public APIs with enhanced insights"""
        ips = self.ip_pattern.findall(headers_text)
        domains = re.findall(r'@([a-zA-Z0-9.-]+)', headers_text)
        
        # Remove duplicates
        unique_ips = list(set(ips))
        unique_domains = list(set(domains))
        
        # Check IP reputation with enhanced analysis
        ip_reputation = []
        for ip in unique_ips:
            try:
                ip_obj = ipaddress.ip_address(ip)
                if not ip_obj.is_private:  # Only check public IPs
                    reputation = self.check_ip_reputation(ip)
                    ip_reputation.append(reputation)
            except ValueError:
                continue
        
        # Check domain reputation with enhanced analysis
        domain_reputation = []
        for domain in unique_domains:
            if self.is_valid_domain(domain):
                reputation = self.check_domain_reputation(domain)
                domain_reputation.append(reputation)
        
        # Enhanced categorization and insights
        critical_ips = [ip for ip in ip_reputation if ip['risk_level'] == 'Critical']
        high_risk_ips = [ip for ip in ip_reputation if ip['risk_level'] == 'High']
        medium_risk_ips = [ip for ip in ip_reputation if ip['risk_level'] == 'Medium']
        low_risk_ips = [ip for ip in ip_reputation if ip['risk_level'] == 'Low']
        safe_ips = [ip for ip in ip_reputation if ip['risk_level'] == 'Safe']
        
        critical_domains = [domain for domain in domain_reputation if domain['risk_level'] == 'Critical']
        high_risk_domains = [domain for domain in domain_reputation if domain['risk_level'] == 'High']
        medium_risk_domains = [domain for domain in domain_reputation if domain['risk_level'] == 'Medium']
        low_risk_domains = [domain for domain in domain_reputation if domain['risk_level'] == 'Low']
        safe_domains = [domain for domain in domain_reputation if domain['risk_level'] == 'Safe']
        
        # Calculate overall reputation metrics
        total_risk_score = 0
        total_items = len(ip_reputation) + len(domain_reputation)
        
        if total_items > 0:
            for ip in ip_reputation:
                total_risk_score += ip.get('overall_score', 0)
            for domain in domain_reputation:
                total_risk_score += domain.get('overall_score', 0)
            overall_risk_score = total_risk_score / total_items
        else:
            overall_risk_score = 0
        
        # Determine overall reputation status
        if overall_risk_score >= 80:
            overall_status = 'Critical'
            overall_message = 'Multiple critical threats detected'
        elif overall_risk_score >= 60:
            overall_status = 'High'
            overall_message = 'Significant security risks detected'
        elif overall_risk_score >= 40:
            overall_status = 'Medium'
            overall_message = 'Moderate security concerns detected'
        elif overall_risk_score >= 20:
            overall_status = 'Low'
            overall_message = 'Minor security concerns detected'
        else:
            overall_status = 'Safe'
            overall_message = 'No significant security threats detected'
        
        # Generate comprehensive recommendations
        recommendations = []
        if critical_ips or critical_domains:
            recommendations.append('🚨 Immediate action required: Block critical threats')
        if high_risk_ips or high_risk_domains:
            recommendations.append('⚠️ Enhanced monitoring recommended for high-risk items')
        if medium_risk_ips or medium_risk_domains:
            recommendations.append('📊 Continue monitoring medium-risk items')
        if not (critical_ips or high_risk_ips or critical_domains or high_risk_domains):
            recommendations.append('✅ No immediate action required')
        
        return {
            'ip_reputation': ip_reputation,
            'domain_reputation': domain_reputation,
            'critical_ips': critical_ips,
            'high_risk_ips': high_risk_ips,
            'medium_risk_ips': medium_risk_ips,
            'low_risk_ips': low_risk_ips,
            'safe_ips': safe_ips,
            'critical_domains': critical_domains,
            'high_risk_domains': high_risk_domains,
            'medium_risk_domains': medium_risk_domains,
            'low_risk_domains': low_risk_domains,
            'safe_domains': safe_domains,
            'total_ips_checked': len(ip_reputation),
            'total_domains_checked': len(domain_reputation),
            'overall_risk_score': overall_risk_score,
            'overall_status': overall_status,
            'overall_message': overall_message,
            'recommendations': recommendations,
            'summary_stats': {
                'total_items': total_items,
                'critical_count': len(critical_ips) + len(critical_domains),
                'high_risk_count': len(high_risk_ips) + len(high_risk_domains),
                'medium_risk_count': len(medium_risk_ips) + len(medium_risk_domains),
                'low_risk_count': len(low_risk_ips) + len(low_risk_domains),
                'safe_count': len(safe_ips) + len(safe_domains)
            }
        }
    
    def analyze_dkim(self, headers_text):
        """Analyze DKIM signature in headers with enhanced insights"""
        dkim_match = self.dkim_pattern.search(headers_text)
        
        if not dkim_match:
            return {
                'status': 'Not Found',
                'details': 'No DKIM signature found in headers',
                'explanation': 'DKIM (DomainKeys Identified Mail) is an email authentication method that allows the receiver to verify that an email was indeed sent and authorised by the owner of the domain. It uses cryptographic signatures to ensure email integrity.',
                'insight': 'Without DKIM, recipients cannot cryptographically verify that the email came from your domain and hasn\'t been modified in transit. This makes your emails more likely to be flagged as spam or phishing.',
                'recommendation': 'Implement DKIM signing for your domain to improve email deliverability and security. Contact your email service provider to enable DKIM signing.',
                'technical_details': 'DKIM works by adding a digital signature to email headers. The receiving server verifies this signature using the public key published in your domain\'s DNS records.',
                'risk_level': 'High',
                'impact': 'High risk of email spoofing and poor deliverability'
            }
        
        dkim_signature = dkim_match.group(1)
        
        # Parse DKIM signature components
        dkim_parts = {}
        for part in dkim_signature.split(';'):
            part = part.strip()
            if '=' in part:
                key, value = part.split('=', 1)
                dkim_parts[key.strip()] = value.strip()
        
        # Extract key components
        domain = dkim_parts.get('d', 'Unknown')
        selector = dkim_parts.get('s', 'Unknown')
        algorithm = dkim_parts.get('a', 'Unknown')
        signature = dkim_parts.get('b', 'Present')
        
        # Check for common DKIM issues
        issues = []
        if not domain or domain == 'Unknown':
            issues.append('Missing or invalid domain in DKIM signature')
        if not selector or selector == 'Unknown':
            issues.append('Missing or invalid selector in DKIM signature')
        if not signature or signature == 'Present':
            issues.append('DKIM signature appears to be malformed')
        
        # Determine status based on signature quality
        if issues:
            status = 'Found (Issues)'
            risk_level = 'Medium'
            insight = f'DKIM signature found but has potential issues: {", ".join(issues)}. This may indicate a misconfigured DKIM setup.'
        else:
            status = 'Found'
            risk_level = 'Low'
            insight = 'DKIM signature appears to be properly formatted. The signature will be verified by the receiving server using the public key in DNS.'
        
        return {
            'status': status,
            'details': f'Domain: {domain}, Selector: {selector}, Algorithm: {algorithm}',
            'signature': dkim_signature,
            'explanation': 'DKIM (DomainKeys Identified Mail) uses cryptographic signatures to verify that an email was sent by an authorised server and hasn\'t been tampered with during transit.',
            'insight': insight,
            'components': dkim_parts,
            'issues': issues,
            'recommendation': f'DKIM signature found. {"Address the identified issues to improve email security" if issues else "Verify the signature is valid by checking the DNS record at {selector}._domainkey.{domain}"}',
            'technical_details': f'Signature uses {algorithm} algorithm. The receiving server will verify this signature using the public key published in DNS at {selector}._domainkey.{domain}',
            'risk_level': risk_level,
            'impact': 'Good email authentication when properly configured'
        }
    
    def analyze_spf(self, headers_text):
        """Analyze SPF record in headers with enhanced insights"""
        spf_match = self.spf_pattern.search(headers_text)
        
        if not spf_match:
            return {
                'status': 'Not Found',
                'details': 'No SPF record found in headers',
                'explanation': 'SPF (Sender Policy Framework) is an email authentication method that helps prevent email spoofing by allowing domain owners to specify which servers are authorised to send email on their behalf.',
                'insight': 'Without SPF, anyone can send emails claiming to be from your domain. This makes your domain vulnerable to spoofing attacks and can damage your reputation.',
                'recommendation': 'Implement SPF record for your domain to prevent email spoofing. Add a TXT record to your DNS with the format: "v=spf1 include:_spf.yourprovider.com ~all"',
                'technical_details': 'SPF works by publishing a list of authorised sending servers in your domain\'s DNS TXT record. Receiving servers check this list to verify the sender.',
                'risk_level': 'High',
                'impact': 'High risk of email spoofing and poor deliverability'
            }
        
        spf_result = spf_match.group(1)
        
        # Parse SPF result with more detail
        spf_lower = spf_result.lower()
        
        if 'pass' in spf_lower:
            status = 'Pass'
            details = 'SPF check passed - sender is authorised'
            risk_level = 'Low'
            insight = 'The sending server is authorised to send emails for this domain according to the SPF policy. This is the ideal result.'
            recommendation = 'Good SPF implementation. The domain has properly configured SPF records.'
        elif 'fail' in spf_lower:
            status = 'Fail'
            details = 'SPF check failed - sender is not authorised'
            risk_level = 'High'
            insight = 'The sending server is not authorised to send emails for this domain. This could indicate spoofing or a misconfigured SPF record.'
            recommendation = 'Fix SPF policy immediately. The sending server should be added to the domain\'s SPF record or the email may be legitimate but from an unauthorised server.'
        elif 'neutral' in spf_lower:
            status = 'Neutral'
            details = 'SPF check neutral - no policy specified'
            risk_level = 'Medium'
            insight = 'The domain has an SPF record but it doesn\'t specify whether the sending server is authorised or not. This provides limited protection.'
            recommendation = 'Consider tightening SPF policy by replacing "~all" with "-all" for stricter enforcement.'
        elif 'softfail' in spf_lower:
            status = 'Soft Fail'
            details = 'SPF check soft fail - sender is likely not authorised'
            risk_level = 'Medium'
            insight = 'The sending server is likely not authorised but the policy allows the email to be delivered with a warning.'
            recommendation = 'Review SPF policy. Consider changing from "~all" to "-all" for stricter enforcement.'
        elif 'temperror' in spf_lower:
            status = 'Temporary Error'
            details = 'SPF check temporary error - DNS lookup failed'
            risk_level = 'Medium'
            insight = 'The SPF check failed due to a temporary DNS error. This could be due to network issues or DNS problems.'
            recommendation = 'Check DNS connectivity and retry. This is usually a temporary issue.'
        elif 'permerror' in spf_lower:
            status = 'Permanent Error'
            details = 'SPF check permanent error - malformed SPF record'
            risk_level = 'High'
            insight = 'The SPF record is malformed or contains syntax errors. This prevents proper SPF checking.'
            recommendation = 'Fix the SPF record syntax. Common issues include invalid characters or malformed include statements.'
        else:
            status = 'Unknown'
            details = 'SPF result unclear or not recognised'
            risk_level = 'Medium'
            insight = 'The SPF result format is not recognised. This may indicate a non-standard implementation or parsing error.'
            recommendation = 'Review the SPF implementation and ensure it follows standard formats.'
        
        return {
            'status': status,
            'details': details,
            'raw_result': spf_result,
            'explanation': 'SPF (Sender Policy Framework) works by publishing a list of authorised sending servers in DNS. Receiving servers check this list to verify the sender.',
            'insight': insight,
            'recommendation': recommendation,
            'technical_details': f'SPF result: {spf_result}. The receiving server checked the domain\'s SPF record and determined the sending server\'s authorisation status.',
            'risk_level': risk_level,
            'impact': 'Good email authentication when properly configured'
        }
    
    def analyze_dmarc(self, headers_text):
        """Analyze DMARC policy in headers with enhanced insights"""
        dmarc_match = self.dmarc_pattern.search(headers_text)
        
        if not dmarc_match:
            return {
                'status': 'Not Found',
                'details': 'No DMARC results found in headers',
                'explanation': 'DMARC (Domain-based Message Authentication, Reporting and Conformance) combines SPF and DKIM to provide a comprehensive email authentication policy.',
                'insight': 'Without DMARC, even if SPF and DKIM are implemented, there\'s no policy telling receiving servers what to do with failed emails. This can lead to inconsistent handling.',
                'recommendation': 'Implement DMARC policy for your domain to improve email security. Start with a monitoring policy: "v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com"',
                'technical_details': 'DMARC works by publishing a policy in DNS that tells receiving servers how to handle emails that fail SPF and DKIM checks.',
                'risk_level': 'High',
                'impact': 'Inconsistent email handling and potential deliverability issues'
            }
        
        dmarc_result = dmarc_match.group(1)
        dmarc_lower = dmarc_result.lower()
        
        # Look for DMARC results in the authentication results
        if 'dmarc=pass' in dmarc_lower:
            status = 'Pass'
            details = 'DMARC check passed'
            risk_level = 'Low'
            insight = 'The email passed DMARC policy checks. Both SPF and DKIM passed, or the policy allows the email despite authentication failures.'
            recommendation = 'Good DMARC implementation. The domain has properly configured DMARC policy.'
        elif 'dmarc=fail' in dmarc_lower:
            status = 'Fail'
            details = 'DMARC check failed'
            risk_level = 'High'
            insight = 'The email failed DMARC policy checks. This could indicate spoofing or legitimate emails from unauthorised sources.'
            recommendation = 'Review and fix DMARC policy. Check if legitimate emails are being blocked and adjust the policy accordingly.'
        elif 'dmarc=neutral' in dmarc_lower:
            status = 'Neutral'
            details = 'DMARC check neutral'
            risk_level = 'Medium'
            insight = 'The DMARC policy doesn\'t specify how to handle this email. This provides limited protection against spoofing.'
            recommendation = 'Consider implementing a more specific DMARC policy with clear actions for failed emails.'
        elif 'dmarc=quarantine' in dmarc_lower:
            status = 'Quarantine'
            details = 'DMARC policy quarantined the email'
            risk_level = 'Medium'
            insight = 'The email was quarantined according to DMARC policy. This usually means it was delivered to spam folder.'
            recommendation = 'Review DMARC policy. Consider if quarantine is appropriate for your domain\'s legitimate emails.'
        elif 'dmarc=reject' in dmarc_lower:
            status = 'Reject'
            details = 'DMARC policy rejected the email'
            risk_level = 'High'
            insight = 'The email was rejected according to DMARC policy. This provides strong protection but may block legitimate emails.'
            recommendation = 'Review DMARC policy. Ensure legitimate emails aren\'t being blocked by overly strict policy.'
        else:
            status = 'Unknown'
            details = 'DMARC result unclear or not recognised'
            risk_level = 'Medium'
            insight = 'The DMARC result format is not recognised. This may indicate a non-standard implementation or parsing error.'
            recommendation = 'Review the DMARC implementation and ensure it follows standard formats.'
        
        # Extract additional DMARC information if available
        policy_info = {}
        if 'p=' in dmarc_result:
            policy_match = re.search(r'p=([^;]+)', dmarc_result)
            if policy_match:
                policy_info['policy'] = policy_match.group(1)
        
        if 'sp=' in dmarc_result:
            subdomain_match = re.search(r'sp=([^;]+)', dmarc_result)
            if subdomain_match:
                policy_info['subdomain_policy'] = subdomain_match.group(1)
        
        if 'pct=' in dmarc_result:
            percentage_match = re.search(r'pct=([^;]+)', dmarc_result)
            if percentage_match:
                policy_info['percentage'] = percentage_match.group(1)
        
        return {
            'status': status,
            'details': details,
            'raw_result': dmarc_result,
            'explanation': 'DMARC (Domain-based Message Authentication, Reporting and Conformance) tells receiving servers what to do with emails that fail SPF and DKIM checks.',
            'insight': insight,
            'recommendation': recommendation,
            'technical_details': f'DMARC result: {dmarc_result}. The receiving server applied the domain\'s DMARC policy to determine how to handle this email.',
            'policy_info': policy_info,
            'risk_level': risk_level,
            'impact': 'Comprehensive email authentication when properly configured'
        }
    
    def analyze_geolocation(self, headers_text):
        """Analyze geolocation of sending servers"""
        ips = self.ip_pattern.findall(headers_text)
        
        # Remove duplicate IPs and sort for consistent display
        unique_ips = []
        seen_ips = set()
        
        for ip in ips:
            if ip not in seen_ips:
                seen_ips.add(ip)
                unique_ips.append(ip)
        
        # Sort IPs for consistent display
        unique_ips.sort()
        
        geolocation_data = []
        for ip in unique_ips:
            try:
                # Basic IP validation
                ip_obj = ipaddress.ip_address(ip)
                
                # Get geolocation data (simplified - in production, use a proper geolocation service)
                geo_info = self.get_ip_geolocation(ip)
                geolocation_data.append({
                    'ip': ip,
                    'type': 'Public' if not ip_obj.is_private else 'Private',
                    'location': geo_info.get('location', 'Unknown'),
                    'city': geo_info.get('city', 'Unknown'),
                    'region': geo_info.get('region', 'Unknown'),
                    'country': geo_info.get('country', 'Unknown'),
                    'isp': geo_info.get('isp', 'Unknown'),
                    'risk_factors': geo_info.get('risk_factors', [])
                })
            except ValueError:
                continue
        
        return {
            'ips_found': len(geolocation_data),
            'locations': geolocation_data,
            'analysis': self.analyze_geolocation_risks(geolocation_data)
        }
    
    def get_ip_geolocation(self, ip):
        """Get geolocation data for an IP address"""
        try:
            # Using ipapi.co for geolocation (free tier)
            response = requests.get(f'https://ipapi.co/{ip}/json/', timeout=10)
            if response.status_code == 200:
                data = response.json()
                
                # Build location string
                city = data.get('city', 'Unknown')
                region = data.get('region', 'Unknown')
                country = data.get('country_name', 'Unknown')
                
                location_parts = []
                if city and city != 'Unknown':
                    location_parts.append(city)
                if region and region != 'Unknown':
                    location_parts.append(region)
                if country and country != 'Unknown':
                    location_parts.append(country)
                
                location = ', '.join(location_parts) if location_parts else 'Unknown'
                
                return {
                    'location': location,
                    'country': country,
                    'city': city,
                    'region': region,
                    'isp': data.get('org', 'Unknown'),
                    'risk_factors': self.assess_ip_risk(data)
                }
        except Exception as e:
            print(f"Geolocation error for {ip}: {str(e)}")
        
        # Fallback to a simpler geolocation service
        try:
            response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    city = data.get('city', 'Unknown')
                    region = data.get('regionName', 'Unknown')
                    country = data.get('country', 'Unknown')
                    
                    location_parts = []
                    if city and city != 'Unknown':
                        location_parts.append(city)
                    if region and region != 'Unknown':
                        location_parts.append(region)
                    if country and country != 'Unknown':
                        location_parts.append(country)
                    
                    location = ', '.join(location_parts) if location_parts else 'Unknown'
                    
                    return {
                        'location': location,
                        'country': country,
                        'city': city,
                        'region': region,
                        'isp': data.get('isp', 'Unknown'),
                        'risk_factors': self.assess_ip_risk(data)
                    }
        except Exception as e:
            print(f"Fallback geolocation error for {ip}: {str(e)}")
        
        return {
            'location': 'Unknown',
            'country': 'Unknown',
            'city': 'Unknown',
            'region': 'Unknown',
            'isp': 'Unknown',
            'risk_factors': []
        }
    
    def assess_ip_risk(self, geo_data):
        """Assess risk factors for an IP address"""
        risk_factors = []
        
        # Check for known high-risk countries (simplified list)
        high_risk_countries = ['XX', 'YY', 'ZZ']  # Example codes
        if geo_data.get('country_code') in high_risk_countries:
            risk_factors.append('High-risk country')
        
        # Check for suspicious ISP patterns
        suspicious_isps = ['vpn', 'proxy', 'tor', 'anonymous']
        isp_lower = geo_data.get('org', '').lower()
        if any(susp in isp_lower for susp in suspicious_isps):
            risk_factors.append('Suspicious ISP')
        
        return risk_factors
    
    def analyze_geolocation_risks(self, locations):
        """Analyze geolocation risks"""
        if not locations:
            return {'risk_level': 'Unknown', 'details': 'No IP addresses found'}
        
        risk_scores = []
        suspicious_locations = []
        
        for location in locations:
            risk_score = 0
            if location['risk_factors']:
                risk_score += len(location['risk_factors']) * 2
            if location['type'] == 'Private':
                risk_score += 1
            risk_scores.append(risk_score)
            
            if location['risk_factors']:
                suspicious_locations.append(location)
        
        avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0
        
        if avg_risk >= 3:
            risk_level = 'High'
        elif avg_risk >= 1:
            risk_level = 'Medium'
        else:
            risk_level = 'Low'
        
        return {
            'risk_level': risk_level,
            'average_risk_score': avg_risk,
            'suspicious_locations': suspicious_locations,
            'details': f'Analyzed {len(locations)} IP addresses with average risk score of {avg_risk:.1f}'
        }
    
    def analyze_threat_intelligence(self, headers_text):
        """Analyze threat intelligence indicators"""
        threat_indicators = []
        
        # Extract domains and IPs for threat analysis
        domains = re.findall(r'@([a-zA-Z0-9.-]+)', headers_text)
        ips = self.ip_pattern.findall(headers_text)
        
        # Check for suspicious patterns
        suspicious_patterns = [
            r'bitcoin',
            r'crypto',
            r'urgent',
            r'account.*suspended',
            r'verify.*account',
            r'click.*here'
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, headers_text, re.IGNORECASE):
                threat_indicators.append(f'Suspicious content pattern: {pattern}')
        
        # Check for unusual sender domains
        sender_domains = set(domains)
        if len(sender_domains) > 3:
            threat_indicators.append('Multiple sender domains detected')
        
        return {
            'threat_indicators': threat_indicators,
            'risk_level': 'High' if threat_indicators else 'Low',
            'details': f'Found {len(threat_indicators)} potential threat indicators'
        }
    
    def analyze_network(self, headers_text):
        """Analyze network routing and hops"""
        received_headers = self.received_pattern.findall(headers_text)
        
        network_analysis = {
            'hop_count': len(received_headers),
            'routing_path': [],
            'suspicious_hops': []
        }
        
        for i, header in enumerate(received_headers):
            hop_info = {
                'hop_number': i + 1,
                'header': header[:100] + '...' if len(header) > 100 else header,
                'analysis': self.analyze_hop(header)
            }
            network_analysis['routing_path'].append(hop_info)
            
            if hop_info['analysis']['suspicious']:
                network_analysis['suspicious_hops'].append(hop_info)
        
        return network_analysis
    
    def analyze_hop(self, header):
        """Analyze a single routing hop"""
        suspicious = False
        reasons = []
        
        # Check for suspicious patterns
        if 'unknown' in header.lower():
            suspicious = True
            reasons.append('Unknown server')
        
        if 'localhost' in header.lower():
            suspicious = True
            reasons.append('Localhost routing')
        
        return {
            'suspicious': suspicious,
            'reasons': reasons
        }
    
    def analyze_domains(self, headers_text):
        """Analyze domain information"""
        domains = re.findall(r'@([a-zA-Z0-9.-]+)', headers_text)
        
        # Remove duplicates case-insensitively and sort for consistent display
        unique_domains = []
        seen_domains = set()
        
        for domain in domains:
            domain_lower = domain.lower()
            if domain_lower not in seen_domains:
                seen_domains.add(domain_lower)
                unique_domains.append(domain)
        
        # Sort domains for consistent display
        unique_domains.sort()
        
        domain_analysis = []
        for domain in unique_domains:
            analysis = self.analyze_single_domain(domain)
            domain_analysis.append(analysis)
        
        return {
            'domains_found': len(unique_domains),
            'domain_analysis': domain_analysis
        }
    
    def analyze_single_domain(self, domain):
        """Analyze a single domain"""
        try:
            # Basic domain validation
            valid = self.is_valid_domain(domain)
            
            # Check for suspicious patterns
            suspicious_patterns = [
                r'unknown',
                r'fake',
                r'spam',
                r'malicious',
                r'suspicious',
                r'test',
                r'example',
                r'demo',
                r'temp',
                r'temporary',
                r'localhost',
                r'127\.0\.0\.1',
                r'0\.0\.0\.0'
            ]
            
            is_suspicious = any(re.search(pattern, domain, re.IGNORECASE) for pattern in suspicious_patterns)
            
            # Check domain structure
            has_valid_structure = self.has_valid_domain_structure(domain)
            
            # Determine if domain is valid
            is_valid = valid and has_valid_structure and not is_suspicious
            
            # Generate analysis message
            if not has_valid_structure:
                analysis = f'Domain {domain} has invalid structure'
            elif is_suspicious:
                analysis = f'Domain {domain} contains suspicious patterns'
            elif not valid:
                analysis = f'Domain {domain} failed validation checks'
            else:
                analysis = f'Domain {domain} appears valid'
            
            return {
                'domain': domain,
                'valid': is_valid,
                'age': 'Unknown',  # Would need WHOIS lookup
                'reputation': 'Unknown',
                'analysis': analysis,
                'suspicious_patterns': is_suspicious,
                'valid_structure': has_valid_structure
            }
        except Exception as e:
            return {
                'domain': domain,
                'valid': False,
                'age': 'Unknown',
                'reputation': 'Unknown',
                'analysis': f'Domain {domain} failed analysis: {str(e)}',
                'suspicious_patterns': True,
                'valid_structure': False
            }
    
    def is_valid_domain(self, domain):
        """Check if domain is valid"""
        try:
            # Basic domain validation rules
            if not domain or len(domain) < 3:
                return False
            
            # Check for valid characters
            if not re.match(r'^[a-zA-Z0-9.-]+$', domain):
                return False
            
            # Check for valid TLD (at least 2 characters)
            parts = domain.split('.')
            if len(parts) < 2:
                return False
            
            # Check TLD length
            if len(parts[-1]) < 2:
                return False
            
            # Check for consecutive dots
            if '..' in domain:
                return False
            
            # Check for leading/trailing dots
            if domain.startswith('.') or domain.endswith('.'):
                return False
            
            return True
        except:
            return False
    
    def has_valid_domain_structure(self, domain):
        """Check if domain has valid structure"""
        try:
            # Must have at least one dot
            if '.' not in domain:
                return False
            
            # Split by dots
            parts = domain.split('.')
            
            # Must have at least 2 parts (domain.tld)
            if len(parts) < 2:
                return False
            
            # Each part must be at least 1 character
            for part in parts:
                if len(part) == 0:
                    return False
            
            # TLD must be at least 2 characters
            if len(parts[-1]) < 2:
                return False
            
            return True
        except:
            return False
    
    def analyze_spoofing(self, headers_text):
        """Analyze email headers for spoofing indicators"""
        spoofing_indicators = []
        spoofing_score = 0
        max_score = 15  # Increased max score for more granular scoring
        
        # 1. Check for mismatched From and Return-Path (strong indicator)
        from_match = self.from_pattern.search(headers_text)
        return_path_match = re.search(r'Return-Path:\s*(.+)', headers_text, re.IGNORECASE)
        
        if from_match and return_path_match:
            from_email = from_match.group(1).strip()
            return_path = return_path_match.group(1).strip()
            
            # Extract email addresses
            from_email_addr = re.search(r'<(.+?)>', from_email)
            return_path_addr = re.search(r'<(.+?)>', return_path)
            
            if from_email_addr and return_path_addr:
                from_addr = from_email_addr.group(1)
                return_addr = return_path_addr.group(1)
                
                if from_addr != return_addr:
                    spoofing_indicators.append(f'From/Return-Path mismatch: {from_addr} vs {return_addr}')
                    spoofing_score += 4  # Strong indicator
        
        # 2. Check for suspicious Received header patterns
        received_headers = self.received_pattern.findall(headers_text)
        if len(received_headers) > 0:
            # Check for unusual routing patterns
            for i, header in enumerate(received_headers):
                # Look for highly suspicious keywords (more specific)
                suspicious_keywords = ['unknown-server', 'localhost', '127.0.0.1', '0.0.0.0', 'fake-server']
                if any(keyword in header.lower() for keyword in suspicious_keywords):
                    spoofing_indicators.append(f'Suspicious Received header {i+1}: {header[:50]}...')
                    spoofing_score += 3
                
                # Check for unusual IP patterns (only flag obvious private IPs in external routing)
                ip_matches = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', header)
                for ip in ip_matches:
                    try:
                        ip_obj = ipaddress.ip_address(ip)
                        # Only flag if it's a private IP AND appears to be an external hop
                        if ip_obj.is_private and ('from' in header.lower() and 'by' in header.lower()):
                            # Check if this looks like an external routing hop
                            if not any(domain in header.lower() for domain in ['internal', 'local', 'corp', 'company']):
                                # Only flag if it's a loopback IP (127.x.x.x) or 0.0.0.0
                                if ip.startswith('127.') or ip == '0.0.0.0':
                                    spoofing_indicators.append(f'Private IP in external routing: {ip}')
                                    spoofing_score += 2
                    except:
                        pass
        
        # 3. Check for missing or suspicious Message-ID
        message_id_match = self.message_id_pattern.search(headers_text)
        if not message_id_match:
            spoofing_indicators.append('Missing Message-ID header')
            spoofing_score += 2
        else:
            message_id = message_id_match.group(1).strip()
            # Check for suspicious Message-ID patterns (more specific)
            if not re.match(r'^<[^@]+@[^>]+>$', message_id) or 'unknown' in message_id.lower():
                spoofing_indicators.append(f'Suspicious Message-ID format: {message_id}')
                spoofing_score += 2
        
        # 4. Check for Date header inconsistencies (more lenient)
        date_match = self.date_pattern.search(headers_text)
        if date_match:
            date_str = date_match.group(1).strip()
            try:
                # Parse date and check if it's reasonable
                from email.utils import parsedate_to_datetime
                from datetime import datetime, timedelta
                
                parsed_date = parsedate_to_datetime(date_str)
                now = datetime.now()
                
                # Check if date is too far in future or past (more lenient)
                if parsed_date > now + timedelta(days=2):
                    spoofing_indicators.append(f'Future date in header: {date_str}')
                    spoofing_score += 2
                elif parsed_date < now - timedelta(days=90):  # More lenient for old emails
                    spoofing_indicators.append(f'Very old date in header: {date_str}')
                    spoofing_score += 1
            except Exception as e:
                # Only flag if it's clearly an invalid format, not just parsing issues
                if not re.match(r'^[A-Za-z]{3},\s+\d{1,2}\s+[A-Za-z]{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+[+-]\d{4}$', date_str):
                    spoofing_indicators.append(f'Invalid date format: {date_str}')
                    spoofing_score += 1
        
        # 5. Check for multiple From headers (should only be one)
        from_headers = self.from_pattern.findall(headers_text)
        if len(from_headers) > 1:
            spoofing_indicators.append(f'Multiple From headers detected: {len(from_headers)}')
            spoofing_score += 3
        
        # 6. Check for suspicious Subject patterns (more specific and less aggressive)
        subject_match = self.subject_pattern.search(headers_text)
        if subject_match:
            subject = subject_match.group(1).strip()
            # More specific suspicious patterns that are less likely to appear in legitimate emails
            suspicious_subject_patterns = [
                r'account.*suspended.*urgent',
                r'verify.*account.*immediately',
                r'click.*here.*urgent',
                r'bitcoin.*urgent',
                r'crypto.*urgent',
                r'password.*expired.*urgent',
                r'security.*alert.*urgent',
                r'urgent.*action.*required',
                r'account.*locked.*urgent'
            ]
            
            for pattern in suspicious_subject_patterns:
                if re.search(pattern, subject, re.IGNORECASE):
                    spoofing_indicators.append(f'Suspicious subject pattern: {pattern}')
                    spoofing_score += 2
                    break
        
        # 7. Check for authentication (less aggressive - missing auth is common)
        dkim_status = self.analyze_dkim(headers_text)['status']
        spf_status = self.analyze_spf(headers_text)['status']
        
        # Only penalize if both are missing AND there are other suspicious indicators
        if dkim_status == 'Not Found' and spf_status in ['Fail', 'Not Found']:
            if spoofing_score > 0:  # Only add if there are other indicators
                spoofing_indicators.append('Missing both DKIM and SPF authentication')
                spoofing_score += 1  # Reduced penalty
        
        # Calculate spoofing risk level (adjusted thresholds)
        spoofing_percentage = (spoofing_score / max_score) * 100
        
        if spoofing_percentage >= 60:  # Increased threshold
            risk_level = 'High'
        elif spoofing_percentage >= 30:  # Increased threshold
            risk_level = 'Medium'
        else:
            risk_level = 'Low'
        
        return {
            'spoofing_score': spoofing_score,
            'max_score': max_score,
            'percentage': spoofing_percentage,
            'risk_level': risk_level,
            'indicators': spoofing_indicators,
            'details': f'Detected {len(spoofing_indicators)} spoofing indicators with {spoofing_percentage:.1f}% spoofing risk'
        }

    def detect_mismatches_and_warnings(self, headers_text):
        """Detect mismatches and suspicious patterns in email headers"""
        warnings = []
        
        # Extract headers
        from_match = self.from_pattern.search(headers_text)
        return_path_match = re.search(r'Return-Path:\s*(.+)', headers_text, re.IGNORECASE)
        dkim_match = self.dkim_pattern.search(headers_text)
        spf_match = self.spf_pattern.search(headers_text)
        dmarc_match = self.dmarc_pattern.search(headers_text)
        received_matches = self.received_pattern.findall(headers_text)
        date_matches = self.date_pattern.findall(headers_text)
        
        # Check From vs Return-Path mismatch
        if from_match and return_path_match:
            from_value = from_match.group(1).strip()
            return_path_value = return_path_match.group(1).strip()
            
            # Extract domains
            from_domain = re.search(r'@([a-zA-Z0-9.-]+)', from_value)
            return_path_domain = re.search(r'@([a-zA-Z0-9.-]+)', return_path_value)
            
            if from_domain and return_path_domain:
                from_domain_str = from_domain.group(1).lower()
                return_path_domain_str = return_path_domain.group(1).lower()
                
                # Check if domains are actually different (case-insensitive and subdomain-aware)
                if not self.domains_match(from_domain_str, return_path_domain_str):
                    warnings.append({
                        'type': 'mismatch',
                        'severity': 'high',
                        'icon': '❗',
                        'message': 'Return-Path domain does not match From address domain',
                        'details': f"From: {from_domain.group(1)} vs Return-Path: {return_path_domain.group(1)}"
                    })
        
        # Check authentication failures
        if dkim_match:
            dkim_value = dkim_match.group(1).strip()
            if 'fail' in dkim_value.lower():
                warnings.append({
                    'type': 'authentication',
                    'severity': 'high',
                    'icon': '❌',
                    'message': 'DKIM authentication failed',
                    'details': 'Digital signature verification failed'
                })
        
        if spf_match:
            spf_value = spf_match.group(1).strip()
            if 'fail' in spf_value.lower():
                warnings.append({
                    'type': 'authentication',
                    'severity': 'high',
                    'icon': '❌',
                    'message': 'SPF authentication failed',
                    'details': 'Sending IP not authorised by domain'
                })
        
        if dmarc_match:
            dmarc_value = dmarc_match.group(1).strip()
            if 'fail' in dmarc_value.lower():
                warnings.append({
                    'type': 'authentication',
                    'severity': 'high',
                    'icon': '❌',
                    'message': 'DMARC authentication failed',
                    'details': 'Domain-based authentication policy violation'
                })
        
        # Check for private IPs or localhost in Received headers
        for i, received in enumerate(received_matches):
            suspicious_ips = ['localhost', '127.0.0.1', '0.0.0.0', '::1', 'unknown']
            if any(ip in received.lower() for ip in suspicious_ips):
                warnings.append({
                    'type': 'suspicious_ip',
                    'severity': 'medium',
                    'icon': '⚠️',
                    'message': f'Private/localhost IP detected in Received header {i+1}',
                    'details': f'Header: {received[:100]}...'
                })
        
        # Check for timestamp sequence issues
        if len(date_matches) > 1:
            try:
                dates = []
                for date_str in date_matches:
                    # Basic date parsing - you might want to use a more robust parser
                    if '2024' in date_str or '2023' in date_str:
                        dates.append(date_str)
                
                if len(dates) > 1:
                    # Check if dates are in reasonable sequence
                    # This is a simplified check - you might want more sophisticated logic
                    pass
            except:
                warnings.append({
                    'type': 'timestamp',
                    'severity': 'medium',
                    'icon': '⏰',
                    'message': 'Timestamp sequence issues detected',
                    'details': 'Multiple dates found with potential inconsistencies'
                })
        
        # Check for missing critical headers
        if not from_match:
            warnings.append({
                'type': 'missing_header',
                'severity': 'medium',
                'icon': '❓',
                'message': 'From header missing',
                'details': 'Email sender information not found'
            })
        
        if not return_path_match:
            warnings.append({
                'type': 'missing_header',
                'severity': 'low',
                'icon': 'ℹ️',
                'message': 'Return-Path header missing',
                'details': 'Bounce handling information not found'
            })
        
        # Check for suspicious patterns in headers
        suspicious_patterns = [
            ('urgent', 'Subject contains urgent language'),
            ('password', 'Subject mentions password'),
            ('verify', 'Subject asks for verification'),
            ('account suspended', 'Subject mentions account suspension'),
            ('bank', 'Subject mentions banking'),
            ('paypal', 'Subject mentions PayPal'),
            ('amazon', 'Subject mentions Amazon')
        ]
        
        subject_match = self.subject_pattern.search(headers_text)
        if subject_match:
            subject = subject_match.group(1).strip().lower()
            for pattern, message in suspicious_patterns:
                if pattern in subject:
                    warnings.append({
                        'type': 'suspicious_content',
                        'severity': 'medium',
                        'icon': '🚨',
                        'message': message,
                        'details': f'Subject: {subject_match.group(1).strip()}'
                    })
                    break
        
        return {
            'warnings': warnings,
            'total_warnings': len(warnings),
            'high_severity': len([w for w in warnings if w['severity'] == 'high']),
            'medium_severity': len([w for w in warnings if w['severity'] == 'medium']),
            'low_severity': len([w for w in warnings if w['severity'] == 'low'])
        }
    
    def calculate_security_score(self, results):
        """Calculate overall email security score"""
        score = 0
        max_score = 3
        
        if results['dkim']['status'] == 'Found':
            score += 1
        if results['spf']['status'] == 'Pass':
            score += 1
        if results['dmarc']['status'] == 'Pass':
            score += 1
        
        percentage = (score / max_score) * 100
        
        if percentage >= 80:
            level = 'Excellent'
        elif percentage >= 60:
            level = 'Good'
        elif percentage >= 40:
            level = 'Fair'
        else:
            level = 'Poor'
        
        return {
            'score': score,
            'max_score': max_score,
            'percentage': percentage,
            'level': level
        }
    
    def calculate_risk_assessment(self, results):
        """Calculate overall risk assessment"""
        risk_factors = []
        risk_score = 0
        
        # Authentication risks
        if results['dkim']['risk_level'] == 'High':
            risk_factors.append('Missing DKIM')
            risk_score += 3
        if results['spf']['risk_level'] == 'High':
            risk_factors.append('SPF failure')
            risk_score += 2
        if results['dmarc']['risk_level'] == 'High':
            risk_factors.append('DMARC failure')
            risk_score += 2
        
        # Spoofing risks (reduced impact)
        if results['spoofing_analysis']['risk_level'] == 'High':
            risk_factors.append('High spoofing risk')
            risk_score += 3  # Reduced from 4
        elif results['spoofing_analysis']['risk_level'] == 'Medium':
            risk_factors.append('Medium spoofing risk')
            risk_score += 1  # Reduced from 2
        
        # Geolocation risks
        geo_risk = results['geolocation']['analysis']['risk_level']
        if geo_risk == 'High':
            risk_factors.append('High-risk geolocation')
            risk_score += 2
        
        # Threat intelligence risks
        if results['threat_intelligence']['risk_level'] == 'High':
            risk_factors.append('Threat indicators detected')
            risk_score += 3
        
        # Network risks
        if results['network_analysis']['suspicious_hops']:
            risk_factors.append('Suspicious routing')
            risk_score += 1
        
        # Reputation risks
        if results['reputation_analysis']['high_risk_ips']:
            risk_factors.append('High-risk IPs detected')
            risk_score += 3
        if results['reputation_analysis']['high_risk_domains']:
            risk_factors.append('High-risk domains detected')
            risk_score += 3
        
        if risk_score >= 8:
            overall_risk = 'High'
        elif risk_score >= 4:
            overall_risk = 'Medium'
        else:
            overall_risk = 'Low'
        
        return {
            'risk_score': risk_score,
            'risk_level': overall_risk,
            'risk_factors': risk_factors
        }
    
    def generate_recommendations(self, results):
        """Generate comprehensive recommendations"""
        recommendations = []
        
        # Authentication recommendations
        if results['dkim']['status'] == 'Not Found':
            recommendations.append('Implement DKIM signing for your domain')
        if results['spf']['status'] in ['Fail', 'Not Found']:
            recommendations.append('Configure SPF record in DNS')
        if results['dmarc']['status'] in ['Fail', 'Not Found']:
            recommendations.append('Set up DMARC policy')
        
        # Spoofing recommendations (less alarmist)
        if results['spoofing_analysis']['risk_level'] == 'High':
            recommendations.append('⚠️ HIGH SPOOFING RISK: This email shows multiple suspicious indicators')
        elif results['spoofing_analysis']['risk_level'] == 'Medium':
            recommendations.append('⚠️ MEDIUM SPOOFING RISK: Some suspicious indicators detected - review carefully')
        
        # Geolocation recommendations
        if results['geolocation']['analysis']['risk_level'] == 'High':
            recommendations.append('Review sending server locations')
        
        # Threat intelligence recommendations
        if results['threat_intelligence']['risk_level'] == 'High':
            recommendations.append('Investigate suspicious content patterns')
        
        # Reputation recommendations
        if results['reputation_analysis']['high_risk_ips']:
            recommendations.append('🚨 HIGH-RISK IPs DETECTED: Block these IP addresses immediately')
        if results['reputation_analysis']['high_risk_domains']:
            recommendations.append('🚨 HIGH-RISK DOMAINS DETECTED: Block these domains immediately')
        
        return recommendations

    def analyze_compliance_and_forensics(self, headers_text):
        """Analyze regulatory compliance and forensic soundness"""
        compliance_issues = []
        forensic_notes = []
        
        # Extract key information
        from_header = self.extract_header_value(headers_text, 'From')
        return_path = self.extract_header_value(headers_text, 'Return-Path')
        received_headers = self.extract_all_header_values(headers_text, 'Received')
        date_header = self.extract_header_value(headers_text, 'Date')
        message_id = self.extract_header_value(headers_text, 'Message-ID')
        
        # GDPR Compliance Analysis
        gdpr_issues = self.check_gdpr_compliance(headers_text, from_header, return_path)
        compliance_issues.extend(gdpr_issues)
        
        # UK NCSC Guidance Analysis
        ncsc_issues = self.check_ncsc_guidance(headers_text, received_headers)
        compliance_issues.extend(ncsc_issues)
        
        # Anti-spam Policy Analysis
        spam_issues = self.check_anti_spam_policies(headers_text, from_header, return_path)
        compliance_issues.extend(spam_issues)
        
        # Forensic Soundness Analysis
        forensic_notes = self.analyze_forensic_soundness(headers_text, date_header, message_id)
        
        return {
            'compliance_issues': compliance_issues,
            'forensic_notes': forensic_notes,
            'total_compliance_issues': len(compliance_issues),
            'gdpr_violations': len([i for i in compliance_issues if 'GDPR' in i['type']]),
            'ncsc_violations': len([i for i in compliance_issues if 'NCSC' in i['type']]),
            'spam_violations': len([i for i in compliance_issues if 'Anti-spam' in i['type']]),
            'forensic_score': self.calculate_forensic_score(forensic_notes)
        }
    
    def check_gdpr_compliance(self, headers_text, from_header, return_path):
        """Check GDPR compliance issues"""
        issues = []
        
        # Check for consent-related headers
        consent_headers = ['X-Consent', 'X-Marketing-Consent', 'List-Unsubscribe']
        has_consent_header = any(self.extract_header_value(headers_text, header) for header in consent_headers)
        
        if not has_consent_header:
            issues.append({
                'type': 'GDPR',
                'severity': 'medium',
                'message': 'Missing consent-related headers',
                'details': 'No clear indication of user consent for marketing communications. Consider adding List-Unsubscribe header.'
            })
        
        # Check for data subject rights headers
        if not self.extract_header_value(headers_text, 'List-Unsubscribe'):
            issues.append({
                'type': 'GDPR',
                'severity': 'high',
                'message': 'Missing List-Unsubscribe header',
                'details': 'Required for GDPR compliance to allow users to opt-out of marketing communications.'
            })
        
        # Check for legitimate interest justification
        if from_header and 'noreply' in from_header.lower():
            issues.append({
                'type': 'GDPR',
                'severity': 'low',
                'message': 'Using noreply address',
                'details': 'Consider using a replyable address to comply with GDPR right to be informed.'
            })
        
        return issues
    
    def check_ncsc_guidance(self, headers_text, received_headers):
        """Check UK NCSC guidance compliance"""
        issues = []
        
        # Check for suspicious routing patterns
        if len(received_headers) > 10:
            issues.append({
                'type': 'NCSC',
                'severity': 'medium',
                'message': 'Excessive routing hops',
                'details': 'Email has passed through many servers, increasing risk of interception or modification.'
            })
        
        # Check for private IP addresses in routing
        private_ips = []
        for header in received_headers:
            ips = re.findall(r'\b(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d+\.\d+\b', header)
            private_ips.extend(ips)
        
        if private_ips:
            issues.append({
                'type': 'NCSC',
                'severity': 'high',
                'message': 'Private IP addresses in routing',
                'details': f'Email routed through private IPs: {", ".join(set(private_ips))}. This may indicate internal routing or potential security issues.'
            })
        
        # Check for missing authentication headers
        auth_headers = ['Authentication-Results', 'DKIM-Signature', 'Received-SPF']
        missing_auth = [h for h in auth_headers if not self.extract_header_value(headers_text, h)]
        
        if len(missing_auth) >= 2:
            issues.append({
                'type': 'NCSC',
                'severity': 'high',
                'message': 'Missing authentication headers',
                'details': f'Missing critical authentication headers: {", ".join(missing_auth)}. Reduces email security and trustworthiness.'
            })
        
        return issues
    
    def check_anti_spam_policies(self, headers_text, from_header, return_path):
        """Check anti-spam policy compliance"""
        issues = []
        
        # Check for proper From/Return-Path alignment
        if from_header and return_path:
            from_domain = self.extract_domain_from_email(from_header)
            return_domain = self.extract_domain_from_email(return_path)
            
            if from_domain and return_domain and from_domain != return_domain:
                issues.append({
                    'type': 'Anti-spam',
                    'severity': 'medium',
                    'message': 'From/Return-Path domain mismatch',
                    'details': f'From domain ({from_domain}) differs from Return-Path domain ({return_domain}). This can trigger spam filters.'
                })
        
        # Check for suspicious subject patterns
        subject = self.extract_header_value(headers_text, 'Subject')
        if subject:
            spam_indicators = ['urgent', 'act now', 'limited time', 'free', 'winner', 'lottery', 'viagra']
            if any(indicator in subject.lower() for indicator in spam_indicators):
                issues.append({
                    'type': 'Anti-spam',
                    'severity': 'low',
                    'message': 'Suspicious subject patterns',
                    'details': 'Subject contains common spam indicators that may trigger filters.'
                })
        
        # Check for missing Message-ID
        if not self.extract_header_value(headers_text, 'Message-ID'):
            issues.append({
                'type': 'Anti-spam',
                'severity': 'medium',
                'message': 'Missing Message-ID header',
                'details': 'Message-ID is important for email tracking and spam filtering.'
            })
        
        return issues
    
    def analyze_forensic_soundness(self, headers_text, date_header, message_id):
        """Analyze forensic soundness of email headers"""
        notes = []
        
        # Check header integrity
        if self.check_header_integrity(headers_text):
            notes.append({
                'type': 'positive',
                'message': 'Header integrity preserved',
                'details': 'Headers appear to be complete and properly formatted.'
            })
        else:
            notes.append({
                'type': 'warning',
                'message': 'Potential header tampering',
                'details': 'Headers may have been modified or are incomplete.'
            })
        
        # Check timestamp consistency
        if self.check_timestamp_consistency(headers_text):
            notes.append({
                'type': 'positive',
                'message': 'Timestamp consistency verified',
                'details': 'Email timestamps follow logical sequence.'
            })
        else:
            notes.append({
                'type': 'warning',
                'message': 'Timestamp inconsistencies detected',
                'details': 'Email timestamps may have been manipulated.'
            })
        
        # Check for forensic markers
        if message_id:
            notes.append({
                'type': 'positive',
                'message': 'Message-ID present',
                'details': 'Unique identifier available for tracking.'
            })
        
        if date_header:
            try:
                parsed_date = email.utils.parsedate_to_datetime(date_header)
                notes.append({
                    'type': 'positive',
                    'message': 'Valid date format',
                    'details': f'Date header properly formatted: {parsed_date.strftime("%Y-%m-%d %H:%M:%S")}'
                })
            except:
                notes.append({
                    'type': 'warning',
                    'message': 'Invalid date format',
                    'details': 'Date header format may be suspicious.'
                })
        
        return notes
    
    def check_header_integrity(self, headers_text):
        """Check if headers appear to be complete and untampered"""
        # Check for basic required headers
        required_headers = ['From', 'Date', 'Message-ID']
        missing_required = [h for h in required_headers if not self.extract_header_value(headers_text, h)]
        
        # Check for suspicious patterns
        suspicious_patterns = [
            r'X-Forwarded-For:\s*$',  # Empty X-Forwarded-For
            r'Received:\s*$',  # Empty Received
            r'From:\s*$'  # Empty From
        ]
        
        has_suspicious = any(re.search(pattern, headers_text, re.MULTILINE) for pattern in suspicious_patterns)
        
        return len(missing_required) == 0 and not has_suspicious
    
    def check_timestamp_consistency(self, headers_text):
        """Check if timestamps follow logical sequence"""
        received_headers = self.extract_all_header_values(headers_text, 'Received')
        dates = []
        
        for header in received_headers:
            # Extract date from Received header
            date_match = re.search(r';\s*([A-Za-z]{3},\s*\d+\s+[A-Za-z]{3}\s+\d+\s+\d+:\d+:\d+)', header)
            if date_match:
                try:
                    parsed_date = email.utils.parsedate_to_datetime(date_match.group(1))
                    dates.append(parsed_date)
                except:
                    continue
        
        if len(dates) < 2:
            return True  # Not enough data to determine
        
        # Check if dates are in descending order (newest first)
        for i in range(len(dates) - 1):
            if dates[i] < dates[i + 1]:
                return False
        
        return True
    
    def calculate_forensic_score(self, forensic_notes):
        """Calculate forensic soundness score"""
        positive_count = len([n for n in forensic_notes if n['type'] == 'positive'])
        warning_count = len([n for n in forensic_notes if n['type'] == 'warning'])
        total_count = len(forensic_notes)
        
        if total_count == 0:
            return 100
        
        score = (positive_count / total_count) * 100
        return max(0, min(100, score))

    def analyze_abuseipdb_data(self, abuseipdb_data):
        """Analyze AbuseIPDB data and provide detailed insights"""
        analysis = {
            'summary': '',
            'risk_factors': [],
            'confidence': 'Unknown',
            'recommendations': []
        }
        
        if abuseipdb_data['score'] is not None:
            score = abuseipdb_data['score']
            
            if score >= 90:
                analysis['confidence'] = 'Very High'
                analysis['summary'] = f'IP has {score}% abuse confidence - extremely suspicious'
                analysis['risk_factors'].append('Very high abuse confidence score')
                analysis['recommendations'].append('Immediate blocking recommended')
            elif score >= 70:
                analysis['confidence'] = 'High'
                analysis['summary'] = f'IP has {score}% abuse confidence - highly suspicious'
                analysis['risk_factors'].append('High abuse confidence score')
                analysis['recommendations'].append('Strong monitoring recommended')
            elif score >= 50:
                analysis['confidence'] = 'Medium'
                analysis['summary'] = f'IP has {score}% abuse confidence - moderately suspicious'
                analysis['risk_factors'].append('Medium abuse confidence score')
                analysis['recommendations'].append('Monitor for suspicious activity')
            elif score >= 20:
                analysis['confidence'] = 'Low'
                analysis['summary'] = f'IP has {score}% abuse confidence - slightly suspicious'
                analysis['risk_factors'].append('Low abuse confidence score')
                analysis['recommendations'].append('Continue monitoring')
            else:
                analysis['confidence'] = 'Very Low'
                analysis['summary'] = f'IP has {score}% abuse confidence - appears safe'
                analysis['risk_factors'].append('Low abuse confidence score')
                analysis['recommendations'].append('No immediate action required')
            
            if abuseipdb_data.get('total_reports', 0) > 0:
                analysis['risk_factors'].append(f'{abuseipdb_data["total_reports"]} abuse reports filed')
                analysis['summary'] += f' ({abuseipdb_data["total_reports"]} reports)'
        
        return analysis
    
    def analyze_virustotal_data(self, virustotal_data):
        """Analyze VirusTotal data and provide detailed insights"""
        analysis = {
            'summary': '',
            'risk_factors': [],
            'vendor_consensus': 'Unknown',
            'recommendations': []
        }
        
        if virustotal_data['score'] is not None:
            score = virustotal_data['score']
            positives = virustotal_data.get('malicious_votes', 0)
            total = positives + virustotal_data.get('harmless_votes', 0)
            
            if score >= 50:
                analysis['vendor_consensus'] = 'High Risk'
                analysis['summary'] = f'{positives}/{total} security vendors flagged this IP ({score:.1f}%)'
                analysis['risk_factors'].append('High number of security vendor detections')
                analysis['recommendations'].append('Block this IP immediately')
            elif score >= 20:
                analysis['vendor_consensus'] = 'Medium Risk'
                analysis['summary'] = f'{positives}/{total} security vendors flagged this IP ({score:.1f}%)'
                analysis['risk_factors'].append('Multiple security vendor detections')
                analysis['recommendations'].append('Monitor this IP closely')
            elif score >= 5:
                analysis['vendor_consensus'] = 'Low Risk'
                analysis['summary'] = f'{positives}/{total} security vendors flagged this IP ({score:.1f}%)'
                analysis['risk_factors'].append('Some security vendor detections')
                analysis['recommendations'].append('Continue monitoring')
            else:
                analysis['vendor_consensus'] = 'Safe'
                analysis['summary'] = f'No security vendors flagged this IP ({score:.1f}%)'
                analysis['risk_factors'].append('No security vendor detections')
                analysis['recommendations'].append('No immediate action required')
        
        return analysis
    
    def analyze_ipqualityscore_data(self, ipqualityscore_data):
        """Analyze IPQualityScore data and provide detailed insights"""
        analysis = {
            'summary': '',
            'risk_factors': [],
            'proxy_analysis': 'Unknown',
            'recommendations': []
        }
        
        if ipqualityscore_data['score'] is not None:
            score = ipqualityscore_data['score']
            
            # Analyze proxy/VPN/Tor usage
            proxy_indicators = []
            if ipqualityscore_data.get('proxy', False):
                proxy_indicators.append('Proxy detected')
                analysis['risk_factors'].append('IP is using a proxy')
            if ipqualityscore_data.get('vpn', False):
                proxy_indicators.append('VPN detected')
                analysis['risk_factors'].append('IP is using a VPN')
            if ipqualityscore_data.get('tor', False):
                proxy_indicators.append('Tor detected')
                analysis['risk_factors'].append('IP is using Tor network')
            
            if proxy_indicators:
                analysis['proxy_analysis'] = 'High Risk'
                analysis['summary'] = f'IP uses: {", ".join(proxy_indicators)}'
                analysis['recommendations'].append('Monitor for suspicious activity')
            else:
                analysis['proxy_analysis'] = 'Low Risk'
                analysis['summary'] = 'No proxy/VPN/Tor detected'
                analysis['recommendations'].append('No immediate action required')
            
            # Analyze fraud score
            fraud_score = ipqualityscore_data.get('fraud_score', 0)
            if fraud_score > 80:
                analysis['risk_factors'].append(f'Very high fraud score: {fraud_score}')
                analysis['recommendations'].append('Block this IP immediately')
            elif fraud_score > 50:
                analysis['risk_factors'].append(f'High fraud score: {fraud_score}')
                analysis['recommendations'].append('Monitor this IP closely')
            elif fraud_score > 20:
                analysis['risk_factors'].append(f'Moderate fraud score: {fraud_score}')
                analysis['recommendations'].append('Continue monitoring')
        
        return analysis
    
    def analyze_virustotal_domain_data(self, virustotal_data):
        """Analyze VirusTotal domain data and provide detailed insights"""
        analysis = {
            'summary': '',
            'risk_factors': [],
            'vendor_consensus': 'Unknown',
            'recommendations': []
        }
        
        if virustotal_data['score'] is not None:
            score = virustotal_data['score']
            positives = virustotal_data.get('malicious_votes', 0)
            total = positives + virustotal_data.get('harmless_votes', 0)
            
            if score >= 50:
                analysis['vendor_consensus'] = 'High Risk'
                analysis['summary'] = f'{positives}/{total} security vendors flagged this domain ({score:.1f}%)'
                analysis['risk_factors'].append('High number of security vendor detections')
                analysis['recommendations'].append('Block this domain immediately')
            elif score >= 20:
                analysis['vendor_consensus'] = 'Medium Risk'
                analysis['summary'] = f'{positives}/{total} security vendors flagged this domain ({score:.1f}%)'
                analysis['risk_factors'].append('Multiple security vendor detections')
                analysis['recommendations'].append('Monitor this domain closely')
            elif score >= 5:
                analysis['vendor_consensus'] = 'Low Risk'
                analysis['summary'] = f'{positives}/{total} security vendors flagged this domain ({score:.1f}%)'
                analysis['risk_factors'].append('Some security vendor detections')
                analysis['recommendations'].append('Continue monitoring')
            else:
                analysis['vendor_consensus'] = 'Safe'
                analysis['summary'] = f'No security vendors flagged this domain ({score:.1f}%)'
                analysis['risk_factors'].append('No security vendor detections')
                analysis['recommendations'].append('No immediate action required')
        
        return analysis
    
    def analyze_ipqualityscore_domain_data(self, ipqualityscore_data):
        """Analyze IPQualityScore domain data and provide detailed insights"""
        analysis = {
            'summary': '',
            'risk_factors': [],
            'domain_quality': 'Unknown',
            'recommendations': []
        }
        
        if ipqualityscore_data['score'] is not None:
            score = ipqualityscore_data['score']
            
            # Analyze domain characteristics
            if ipqualityscore_data.get('disposable', False):
                analysis['domain_quality'] = 'High Risk'
                analysis['summary'] = 'Disposable email domain detected'
                analysis['risk_factors'].append('Domain is disposable/temporary')
                analysis['recommendations'].append('Block this domain')
            elif ipqualityscore_data.get('suspicious', False):
                analysis['domain_quality'] = 'Medium Risk'
                analysis['summary'] = 'Suspicious domain characteristics detected'
                analysis['risk_factors'].append('Domain has suspicious characteristics')
                analysis['recommendations'].append('Monitor this domain closely')
            elif not ipqualityscore_data.get('valid', True):
                analysis['domain_quality'] = 'High Risk'
                analysis['summary'] = 'Invalid domain format detected'
                analysis['risk_factors'].append('Domain format is invalid')
                analysis['recommendations'].append('Block this domain')
            else:
                analysis['domain_quality'] = 'Low Risk'
                analysis['summary'] = 'Domain appears legitimate'
                analysis['risk_factors'].append('Domain appears legitimate')
                analysis['recommendations'].append('No immediate action required')
        
        return analysis
    
    def analyze_talos_domain_data(self, talos_data):
        """Analyze Talos Intelligence domain data and provide detailed insights"""
        analysis = {
            'summary': '',
            'risk_factors': [],
            'reputation_status': 'Unknown',
            'recommendations': [],
            'categories': [],
            'last_updated': 'Unknown',
            'domain_age': 'Unknown'
        }
        
        if talos_data['score'] is not None:
            score = talos_data['score']
            reputation = talos_data.get('reputation', 'Unknown')
            categories = talos_data.get('categories', [])
            
            # Analyze reputation status
            if reputation == 'Poor':
                analysis['reputation_status'] = 'Critical Risk'
                analysis['summary'] = f'Talos reputation: Poor (Score: {score}%)'
                analysis['risk_factors'].append('Poor reputation in Talos Intelligence database')
                analysis['recommendations'].append('Block this domain immediately')
                analysis['recommendations'].append('Report to security team')
            elif reputation == 'Fair':
                analysis['reputation_status'] = 'High Risk'
                analysis['summary'] = f'Talos reputation: Fair (Score: {score}%)'
                analysis['risk_factors'].append('Fair reputation in Talos Intelligence database')
                analysis['recommendations'].append('Monitor this domain closely')
                analysis['recommendations'].append('Consider blocking if suspicious activity continues')
            elif reputation == 'Good':
                analysis['reputation_status'] = 'Low Risk'
                analysis['summary'] = f'Talos reputation: Good (Score: {score}%)'
                analysis['risk_factors'].append('Good reputation in Talos Intelligence database')
                analysis['recommendations'].append('Continue monitoring')
            elif reputation == 'Excellent':
                analysis['reputation_status'] = 'Safe'
                analysis['summary'] = f'Talos reputation: Excellent (Score: {score}%)'
                analysis['risk_factors'].append('Excellent reputation in Talos Intelligence database')
                analysis['recommendations'].append('No immediate action required')
            else:
                analysis['reputation_status'] = 'Medium Risk'
                analysis['summary'] = f'Talos reputation: Unknown (Score: {score}%)'
                analysis['risk_factors'].append('Unknown reputation in Talos Intelligence database')
                analysis['recommendations'].append('Monitor for suspicious activity')
            
            # Analyze categories
            if categories:
                analysis['categories'] = categories
                analysis['risk_factors'].append(f'Categorized as: {", ".join(categories)}')
            
            # Add metadata
            analysis['last_updated'] = talos_data.get('last_updated', 'Unknown')
            analysis['domain_age'] = talos_data.get('domain_age', 'Unknown')
            
            # Additional recommendations based on score
            if score >= 80:
                analysis['recommendations'].append('High risk score indicates malicious activity')
            elif score >= 60:
                analysis['recommendations'].append('Moderate risk score - monitor closely')
            elif score >= 40:
                analysis['recommendations'].append('Some risk indicators present')
            else:
                analysis['recommendations'].append('Low risk indicators')
        
        return analysis

    def generate_pdf_report(self, analysis_results, headers_text):
        """Generate a comprehensive PDF report of the email header analysis"""
        # Create a temporary file for the PDF
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmp_file:
            pdf_path = tmp_file.name
        
        # Create the PDF document
        doc = SimpleDocTemplate(pdf_path, pagesize=A4, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
        story = []
        
        # Get styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.darkblue
        )
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            spaceAfter=12,
            spaceBefore=20,
            textColor=colors.darkblue
        )
        subheading_style = ParagraphStyle(
            'CustomSubheading',
            parent=styles['Heading3'],
            fontSize=14,
            spaceAfter=8,
            spaceBefore=12,
            textColor=colors.darkgreen
        )
        normal_style = styles['Normal']
        code_style = ParagraphStyle(
            'Code',
            parent=styles['Normal'],
            fontName='Courier',
            fontSize=9,
            leftIndent=20
        )
        
        # Title page
        story.append(Paragraph("Email Header Analysis Report", title_style))
        story.append(Spacer(1, 20))
        story.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
        story.append(Spacer(1, 30))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", heading_style))
        security_score = analysis_results.get('security_score', 0)
        risk_assessment = analysis_results.get('risk_assessment', {})
        overall_risk = risk_assessment.get('overall_risk', 'Unknown')
        
        summary_text = f"""
        This email header analysis reveals a security score of {security_score}/100. 
        The overall risk assessment indicates a {overall_risk} level of concern.
        """
        story.append(Paragraph(summary_text, normal_style))
        story.append(Spacer(1, 12))
        
        # Authentication Results
        story.append(Paragraph("Email Authentication Analysis", heading_style))
        
        # DKIM
        dkim = analysis_results.get('dkim', {})
        dkim_status = dkim.get('status', 'Unknown')
        story.append(Paragraph(f"DKIM Status: {dkim_status}", subheading_style))
        story.append(Paragraph(f"Details: {dkim.get('details', 'N/A')}", normal_style))
        if dkim.get('insight'):
            story.append(Paragraph(f"Insight: {dkim['insight']}", normal_style))
        if dkim.get('recommendation'):
            story.append(Paragraph(f"Recommendation: {dkim['recommendation']}", normal_style))
        story.append(Spacer(1, 12))
        
        # SPF
        spf = analysis_results.get('spf', {})
        spf_status = spf.get('status', 'Unknown')
        story.append(Paragraph(f"SPF Status: {spf_status}", subheading_style))
        story.append(Paragraph(f"Details: {spf.get('details', 'N/A')}", normal_style))
        if spf.get('insight'):
            story.append(Paragraph(f"Insight: {spf['insight']}", normal_style))
        if spf.get('recommendation'):
            story.append(Paragraph(f"Recommendation: {spf['recommendation']}", normal_style))
        story.append(Spacer(1, 12))
        
        # DMARC
        dmarc = analysis_results.get('dmarc', {})
        dmarc_status = dmarc.get('status', 'Unknown')
        story.append(Paragraph(f"DMARC Status: {dmarc_status}", subheading_style))
        story.append(Paragraph(f"Details: {dmarc.get('details', 'N/A')}", normal_style))
        if dmarc.get('insight'):
            story.append(Paragraph(f"Insight: {dmarc['insight']}", normal_style))
        if dmarc.get('recommendation'):
            story.append(Paragraph(f"Recommendation: {dmarc['recommendation']}", normal_style))
        story.append(Spacer(1, 20))
        
        # Headers Found
        story.append(Paragraph("Headers Found", heading_style))
        headers_found = analysis_results.get('headers_found', {})
        
        headers_data = []
        for header_name, header_value in headers_found.items():
            if header_value:
                # Truncate long values for PDF
                display_value = header_value[:100] + "..." if len(header_value) > 100 else header_value
                headers_data.append([header_name, display_value])
        
        if headers_data:
            headers_table = Table(headers_data, colWidths=[2*inch, 4*inch])
            headers_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(headers_table)
        else:
            story.append(Paragraph("No headers found", normal_style))
        story.append(Spacer(1, 20))
        
        # Security & Compliance Analysis
        story.append(Paragraph("Security & Compliance Analysis", heading_style))
        
        # Mismatch Analysis (Security Warnings)
        mismatch_analysis = analysis_results.get('mismatch_analysis', {})
        if mismatch_analysis and mismatch_analysis.get('warnings'):
            story.append(Paragraph("Security Warnings:", subheading_style))
            for warning in mismatch_analysis['warnings']:
                severity = warning.get('severity', 'medium').upper()
                story.append(Paragraph(f"• [{severity}] {warning.get('message', 'Unknown warning')}", normal_style))
                if warning.get('details'):
                    story.append(Paragraph(f"  Details: {warning['details']}", normal_style))
        else:
            story.append(Paragraph("No security warnings detected", normal_style))
        story.append(Spacer(1, 12))
        
        # Compliance Issues
        compliance_forensics = analysis_results.get('compliance_and_forensics', {})
        if compliance_forensics and compliance_forensics.get('compliance_issues'):
            story.append(Paragraph("Compliance Issues:", subheading_style))
            for issue in compliance_forensics['compliance_issues']:
                severity = issue.get('severity', 'medium').upper()
                story.append(Paragraph(f"• [{severity}] {issue.get('message', 'Unknown issue')}", normal_style))
                if issue.get('details'):
                    story.append(Paragraph(f"  Details: {issue['details']}", normal_style))
        else:
            story.append(Paragraph("No compliance issues detected", normal_style))
        story.append(Spacer(1, 12))
        
        # Forensic Analysis
        if compliance_forensics and compliance_forensics.get('forensic_notes'):
            story.append(Paragraph("Forensic Analysis:", subheading_style))
            forensic_score = compliance_forensics.get('forensic_score', 0)
            story.append(Paragraph(f"Forensic Score: {forensic_score}%", normal_style))
            for note in compliance_forensics['forensic_notes']:
                note_type = note.get('type', 'info').upper()
                story.append(Paragraph(f"• [{note_type}] {note.get('message', 'Unknown note')}", normal_style))
                if note.get('details'):
                    story.append(Paragraph(f"  Details: {note['details']}", normal_style))
        else:
            story.append(Paragraph("No forensic analysis data available", normal_style))
        story.append(Spacer(1, 20))
        
        # Geolocation Analysis
        story.append(Paragraph("Geolocation Analysis", heading_style))
        geolocation = analysis_results.get('geolocation', {})
        if geolocation:
            ips_found = geolocation.get('ips_found', 0)
            analysis_data = geolocation.get('analysis', {})
            risk_level = analysis_data.get('risk_level', 'Unknown')
            
            story.append(Paragraph(f"IPs Found: {ips_found}", subheading_style))
            story.append(Paragraph(f"Risk Level: {risk_level}", normal_style))
            story.append(Paragraph(f"Details: {analysis_data.get('details', 'N/A')}", normal_style))
            
            locations = geolocation.get('locations', [])
            if locations:
                story.append(Paragraph("Geographic Locations:", subheading_style))
                for location in locations:
                    ip = location.get('ip', 'Unknown')
                    country = location.get('country', 'Unknown')
                    city = location.get('city', 'Unknown')
                    isp = location.get('isp', 'Unknown')
                    story.append(Paragraph(f"• IP {ip}: {city}, {country} (ISP: {isp})", normal_style))
            else:
                story.append(Paragraph("No location data available", normal_style))
        else:
            story.append(Paragraph("No geolocation data available", normal_style))
        story.append(Spacer(1, 20))
        
        # Reputation Analysis
        story.append(Paragraph("Reputation Analysis", heading_style))
        reputation = analysis_results.get('reputation_analysis', {})
        
        # Overall reputation status
        overall_status = reputation.get('overall_status', 'Unknown')
        overall_message = reputation.get('overall_message', 'N/A')
        overall_risk_score = reputation.get('overall_risk_score', 0)
        
        story.append(Paragraph(f"Overall Status: {overall_status}", subheading_style))
        story.append(Paragraph(f"Message: {overall_message}", normal_style))
        story.append(Paragraph(f"Risk Score: {overall_risk_score:.1f}%", normal_style))
        
        # IP Reputation
        ip_reputation = reputation.get('ip_reputation', [])
        if ip_reputation:
            story.append(Paragraph("IP Reputation:", subheading_style))
            for ip_data in ip_reputation:
                ip = ip_data.get('ip', 'Unknown')
                risk_level = ip_data.get('risk_level', 'Unknown')
                overall_score = ip_data.get('overall_score', 0)
                story.append(Paragraph(f"• IP {ip}: {risk_level} risk (Score: {overall_score:.1f}%)", normal_style))
        story.append(Spacer(1, 12))
        
        # Domain Reputation
        domain_reputation = reputation.get('domain_reputation', [])
        if domain_reputation:
            story.append(Paragraph("Domain Reputation:", subheading_style))
            for domain_data in domain_reputation:
                domain = domain_data.get('domain', 'Unknown')
                risk_level = domain_data.get('risk_level', 'Unknown')
                overall_score = domain_data.get('overall_score', 0)
                story.append(Paragraph(f"• Domain {domain}: {risk_level} risk (Score: {overall_score:.1f}%)", normal_style))
        story.append(Spacer(1, 20))
        
        # Threat Intelligence
        story.append(Paragraph("Threat Intelligence", heading_style))
        threat_intelligence = analysis_results.get('threat_intelligence', {})
        if threat_intelligence:
            risk_level = threat_intelligence.get('risk_level', 'Unknown')
            story.append(Paragraph(f"Risk Level: {risk_level}", subheading_style))
            story.append(Paragraph(f"Details: {threat_intelligence.get('details', 'N/A')}", normal_style))
            
            threat_indicators = threat_intelligence.get('threat_indicators', [])
            if threat_indicators:
                story.append(Paragraph("Threat Indicators:", subheading_style))
                for indicator in threat_indicators:
                    story.append(Paragraph(f"• {indicator}", normal_style))
            else:
                story.append(Paragraph("No threat indicators detected", normal_style))
        else:
            story.append(Paragraph("No threat intelligence data available", normal_style))
        story.append(Spacer(1, 20))
        
        # Spoofing Analysis
        story.append(Paragraph("Spoofing Analysis", heading_style))
        spoofing_analysis = analysis_results.get('spoofing_analysis', {})
        if spoofing_analysis:
            risk_level = spoofing_analysis.get('risk_level', 'Unknown')
            spoofing_score = spoofing_analysis.get('spoofing_score', 0)
            max_score = spoofing_analysis.get('max_score', 100)
            percentage = spoofing_analysis.get('percentage', 0)
            
            story.append(Paragraph(f"Risk Level: {risk_level}", subheading_style))
            story.append(Paragraph(f"Spoofing Score: {spoofing_score}/{max_score} ({percentage:.1f}%)", normal_style))
            story.append(Paragraph(f"Details: {spoofing_analysis.get('details', 'N/A')}", normal_style))
            
            indicators = spoofing_analysis.get('indicators', [])
            if indicators:
                story.append(Paragraph("Spoofing Indicators:", subheading_style))
                for indicator in indicators:
                    story.append(Paragraph(f"• {indicator}", normal_style))
            else:
                story.append(Paragraph("No spoofing indicators detected", normal_style))
        else:
            story.append(Paragraph("No spoofing analysis data available", normal_style))
        story.append(Spacer(1, 20))
        
        # Network Analysis
        story.append(Paragraph("Network Analysis", heading_style))
        network = analysis_results.get('network_analysis', {})
        routing_path = network.get('routing_path', [])
        if routing_path:
            story.append(Paragraph("Email Routing Path:", subheading_style))
            for i, hop in enumerate(routing_path):
                server = hop.get('header', 'Unknown')
                story.append(Paragraph(f"Hop {i+1}: {server}", normal_style))
        else:
            story.append(Paragraph("No network analysis data available", normal_style))
        story.append(Spacer(1, 20))
        
        # Domain Analysis
        story.append(Paragraph("Domain Analysis", heading_style))
        domain_analysis = analysis_results.get('domain_analysis', {})
        if domain_analysis:
            domains_found = domain_analysis.get('domains_found', 0)
            story.append(Paragraph(f"Domains Found: {domains_found}", subheading_style))
            
            domain_list = domain_analysis.get('domain_analysis', [])
            if domain_list:
                for domain_data in domain_list:
                    domain = domain_data.get('domain', 'Unknown')
                    valid = domain_data.get('valid', False)
                    analysis = domain_data.get('analysis', 'N/A')
                    status = "✅ Valid" if valid else "❌ Invalid"
                    story.append(Paragraph(f"• {domain}: {status}", normal_style))
                    story.append(Paragraph(f"  Analysis: {analysis}", normal_style))
            else:
                story.append(Paragraph("No domain analysis data available", normal_style))
        else:
            story.append(Paragraph("No domain analysis data available", normal_style))
        story.append(Spacer(1, 20))
        
        # Recommendations
        story.append(Paragraph("Recommendations", heading_style))
        summary = analysis_results.get('summary', {})
        recommendations = summary.get('recommendations', [])
        if recommendations:
            for rec in recommendations:
                story.append(Paragraph(f"• {rec}", normal_style))
        else:
            story.append(Paragraph("No specific recommendations available", normal_style))
        story.append(Spacer(1, 20))
        
        # Raw Headers (last page)
        story.append(PageBreak())
        story.append(Paragraph("Raw Email Headers", heading_style))
        story.append(Paragraph("For forensic analysis purposes:", subheading_style))
        story.append(Paragraph(headers_text, code_style))
        
        # Build the PDF
        doc.build(story)
        
        return pdf_path

analyzer = EmailHeaderAnalyser()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    headers_text = request.form.get('headers', '')
    
    if not headers_text.strip():
        return jsonify({'error': 'Please provide email headers'})
    
    try:
        results = analyzer.analyse_headers(headers_text)
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': f'Analysis failed: {str(e)}'})

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle .eml file uploads"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'})
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'})
    
    if file and file.filename.lower().endswith('.eml'):
        try:
            # Read the .eml file content
            file_content = file.read().decode('utf-8', errors='ignore')
            
            # Parse the email using Python's email module
            email_message = email.message_from_string(file_content)
            
            # Extract headers as a single string
            headers_text = ""
            for header, value in email_message.items():
                headers_text += f"{header}: {value}\n"
            
            # Analyze the headers
            results = analyzer.analyse_headers(headers_text)
            return jsonify(results)
            
        except Exception as e:
            return jsonify({'error': f'Failed to process .eml file: {str(e)}'})
    else:
        return jsonify({'error': 'Please upload a valid .eml file'})

@app.route('/download-pdf', methods=['POST'])
def download_pdf():
    """Generate and download PDF report"""
    headers_text = request.form.get('headers', '')
    
    if not headers_text.strip():
        return jsonify({'error': 'Please provide email headers'})
    
    try:
        # Analyze the headers
        results = analyzer.analyse_headers(headers_text)
        
        # Generate PDF report
        pdf_path = analyzer.generate_pdf_report(results, headers_text)
        
        # Send the PDF file
        return send_file(
            pdf_path,
            as_attachment=True,
            download_name=f'email_header_analysis_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf',
            mimetype='application/pdf'
        )
        
    except Exception as e:
        return jsonify({'error': f'PDF generation failed: {str(e)}'})
    finally:
        # Clean up the temporary PDF file
        try:
            if 'pdf_path' in locals():
                os.unlink(pdf_path)
        except:
            pass

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000) 