class MitreMapper:
    def __init__(self):
        self.techniques = {
            'T1110': {'name': 'Brute Force', 'tactic': 'Credential Access'},
            'T1046': {'name': 'Network Service Discovery', 'tactic': 'Discovery'},
            'T1190': {'name': 'Exploit Public-Facing Application', 'tactic': 'Initial Access'},
            'T1595': {'name': 'Active Scanning', 'tactic': 'Reconnaissance'},
            'T1059': {'name': 'Command and Scripting Interpreter', 'tactic': 'Execution'}
        }
        
    def map_alerts(self, alerts):
        mapping = {}
        for alert in alerts:
            tid = alert.get('mitre_technique_id')
            if tid in self.techniques:
                if tid not in mapping:
                    mapping[tid] = {'info': self.techniques[tid], 'count': 0, 'alerts': []}
                mapping[tid]['count'] += 1
                mapping[tid]['alerts'].append(alert['name'])
        return mapping
