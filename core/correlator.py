class Correlator:
    def correlate(self, alerts):
        chains = []
        ip_alerts = {}
        for alert in alerts:
            ip = alert.get('source_ip')
            if ip and ip != 'Unknown':
                if ip not in ip_alerts: ip_alerts[ip] = []
                ip_alerts[ip].append(alert)
                
        for ip, alist in ip_alerts.items():
            if len(alist) > 1:
                chains.append({
                    'source_ip': ip,
                    'chain_length': len(alist),
                    'description': f'Multiple stages of attack from {ip}: ' + ' -> '.join(set([a['name'] for a in alist])),
                    'severity': 'critical' if len(alist) >= 3 else 'high'
                })
        return chains
