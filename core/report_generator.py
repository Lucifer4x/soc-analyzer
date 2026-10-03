class ReportGenerator:
    def generate(self, data):
        # Generate simple HTML report string (could be extended)
        html = "<h1>SOC Analysis Report</h1>\n"
        html += f"<p>Total Alerts: {len(data['alerts'])}</p>\n"
        html += "<h2>Critical Alerts</h2><ul>"
        for a in data['alerts']:
            if a['severity'] == 'critical':
                html += f"<li>{a['name']} from {a['source_ip']}</li>"
        html += "</ul>"
        return html
