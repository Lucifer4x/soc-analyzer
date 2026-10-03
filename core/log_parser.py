import re
import json
from datetime import datetime
from dateutil import parser as date_parser

class LogParser:
    def __init__(self):
        # Regex for common log formats
        self.syslog_pattern = re.compile(r'^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<process>[^:]+):\s+(?P<message>.*)$')
        self.apache_pattern = re.compile(r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<request>[^"]+)"\s+(?P<status>\d{3})\s+(?P<size>\S+)\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)"')
        
    def parse(self, filename, content):
        parsed_logs = []
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line: continue
            
            # Try JSON
            try:
                data = json.loads(line)
                parsed_logs.append(self._normalize_json(data))
                continue
            except json.JSONDecodeError:
                pass
                
            # Try Apache
            apache_match = self.apache_pattern.match(line)
            if apache_match:
                parsed_logs.append(self._normalize_apache(apache_match.groupdict(), line))
                continue
                
            # Try Syslog
            syslog_match = self.syslog_pattern.match(line)
            if syslog_match:
                parsed_logs.append(self._normalize_syslog(syslog_match.groupdict(), line))
                continue
                
            # Default fallback
            parsed_logs.append({
                'timestamp': datetime.now().isoformat(),
                'source_ip': None, 'dest_ip': None, 'source_port': None, 'dest_port': None,
                'protocol': 'unknown', 'action': 'unknown', 'severity': 'info',
                'raw_message': line, 'metadata': {}
            })
            
        return parsed_logs
        
    def _normalize_json(self, data):
        return {
            'timestamp': data.get('timestamp', datetime.now().isoformat()),
            'source_ip': data.get('src_ip') or data.get('source_ip'),
            'dest_ip': data.get('dest_ip') or data.get('dst_ip'),
            'source_port': data.get('src_port') or data.get('source_port'),
            'dest_port': data.get('dest_port') or data.get('dst_port'),
            'protocol': data.get('protocol', 'unknown'),
            'action': data.get('action', 'unknown'),
            'severity': data.get('severity', 'info'),
            'raw_message': json.dumps(data),
            'metadata': data
        }

    def _normalize_apache(self, match, raw):
        try:
            ts = date_parser.parse(match['timestamp'].replace(':', ' ', 1)).isoformat()
        except:
            ts = datetime.now().isoformat()
            
        return {
            'timestamp': ts,
            'source_ip': match['ip'], 'dest_ip': None, 'source_port': None, 'dest_port': None,
            'protocol': 'http', 'action': match['status'], 'severity': 'info',
            'raw_message': raw,
            'metadata': {'request': match['request'], 'user_agent': match['user_agent'], 'referer': match['referer']}
        }

    def _normalize_syslog(self, match, raw):
        return {
            'timestamp': match['timestamp'], # Keep as is for now or parse
            'source_ip': None, 'dest_ip': None, 'source_port': None, 'dest_port': None,
            'protocol': 'syslog', 'action': 'log', 'severity': 'info',
            'raw_message': raw,
            'metadata': {'host': match['host'], 'process': match['process'], 'message': match['message']}
        }
