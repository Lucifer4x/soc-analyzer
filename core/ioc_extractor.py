import re

class IOCExtractor:
    def __init__(self):
        self.patterns = {
            'ipv4': re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
            'url': re.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'),
            'md5': re.compile(r'\b[a-f0-9]{32}\b', re.IGNORECASE),
            'sha256': re.compile(r'\b[a-f0-9]{64}\b', re.IGNORECASE)
        }
        
    def extract(self, logs):
        iocs = {'ipv4': set(), 'url': set(), 'md5': set(), 'sha256': set()}
        
        for log in logs:
            msg = log['raw_message']
            for ioc_type, pattern in self.patterns.items():
                matches = pattern.findall(msg)
                for match in matches:
                    # Basic filtering for local IPs
                    if ioc_type == 'ipv4':
                        if match.startswith('127.') or match.startswith('10.') or match.startswith('192.168.'):
                            continue
                    iocs[ioc_type].add(match)
                    
        # Convert sets to list of dicts with counts (simplified)
        results = []
        for ioc_type, items in iocs.items():
            for item in items:
                results.append({'type': ioc_type, 'value': item, 'risk': 'high' if ioc_type in ['md5', 'sha256'] else 'medium'})
                
        return results
