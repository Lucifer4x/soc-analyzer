class AnomalyDetector:
    def __init__(self):
        pass
        
    def detect(self, logs):
        # Simplified anomaly detection
        anomalies = []
        ip_counts = {}
        for log in logs:
            ip = log.get('source_ip')
            if ip: ip_counts[ip] = ip_counts.get(ip, 0) + 1
            
        if not ip_counts: return anomalies
        
        avg = sum(ip_counts.values()) / len(ip_counts)
        for ip, count in ip_counts.items():
            if count > avg * 3 and count > 10:  # simplistic >3x avg spike
                anomalies.append({
                    'type': 'Volume Anomaly',
                    'description': f'Unusually high traffic from {ip} (Count: {count})',
                    'severity': 'medium'
                })
        return anomalies
