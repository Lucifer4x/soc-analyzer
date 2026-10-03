import yaml
import re

class ThreatDetector:
    def __init__(self, rules_path):
        with open(rules_path, 'r') as f:
            self.rules = yaml.safe_load(f)
            
        for rule in self.rules:
            if 'pattern' in rule:
                rule['regex'] = re.compile(rule['pattern'], re.IGNORECASE)

    def analyze(self, logs):
        alerts = []
        
        # State tracking for behavioral rules
        ip_auth_failures = {}
        ip_ports = {}
        
        for log in logs:
            # Pattern based detection
            for rule in self.rules:
                if 'regex' in rule:
                    search_str = log['raw_message']
                    if 'request' in log['metadata']:
                        search_str += " " + log['metadata']['request']
                    if 'user_agent' in log['metadata']:
                        search_str += " " + log['metadata']['user_agent']
                        
                    if rule['regex'].search(search_str):
                        alerts.append(self._create_alert(rule, log))
                        
            # Behavioral detections (simplified for standalone implementation)
            src_ip = log.get('source_ip')
            if src_ip:
                # Brute force (SSH/Auth)
                if 'Failed password' in log['raw_message'] or 'failure' in log['raw_message'].lower():
                    ip_auth_failures[src_ip] = ip_auth_failures.get(src_ip, 0) + 1
                    if ip_auth_failures[src_ip] >= 5:
                        alerts.append({
                            'rule_id': 'BEH-01', 'name': 'Brute Force Attack', 'severity': 'critical',
                            'description': f'Multiple failed auth attempts from {src_ip}',
                            'mitre_technique_id': 'T1110', 'source_ip': src_ip, 'raw_log': log['raw_message']
                        })
                        ip_auth_failures[src_ip] = 0 # reset
                        
                # Port Scan
                dst_port = log.get('dest_port')
                if dst_port:
                    if src_ip not in ip_ports:
                        ip_ports[src_ip] = set()
                    ip_ports[src_ip].add(dst_port)
                    if len(ip_ports[src_ip]) >= 10:
                        alerts.append({
                            'rule_id': 'BEH-02', 'name': 'Port Scan Detected', 'severity': 'high',
                            'description': f'Port scanning activity from {src_ip}',
                            'mitre_technique_id': 'T1046', 'source_ip': src_ip, 'raw_log': log['raw_message']
                        })
                        ip_ports[src_ip] = set()
                        
        return alerts

    def _create_alert(self, rule, log):
        return {
            'rule_id': rule['id'],
            'name': rule['name'],
            'severity': rule['severity'],
            'description': rule['description'],
            'mitre_technique_id': rule.get('mitre_technique_id', 'Unknown'),
            'source_ip': log.get('source_ip', 'Unknown'),
            'raw_log': log['raw_message']
        }
