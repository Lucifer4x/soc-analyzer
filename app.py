import os
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
from werkzeug.utils import secure_filename
from config import Config
from core.log_parser import LogParser
from core.threat_detector import ThreatDetector
from core.ioc_extractor import IOCExtractor
from core.anomaly_detector import AnomalyDetector
from core.mitre_mapper import MitreMapper
from core.correlator import Correlator
from core.geo_lookup import GeoLookup

app = Flask(__name__)
app.config.from_object(Config)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Global state to hold analysis results for demo
analysis_results = {
    'logs': [],
    'alerts': [],
    'iocs': [],
    'anomalies': [],
    'mitre': {},
    'chains': [],
    'stats': {'total_events': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
}

parser = LogParser()
detector = ThreatDetector(app.config['RULES_FILE'])
ioc_ext = IOCExtractor()
anomaly_det = AnomalyDetector()
mitre_map = MitreMapper()
correlator = Correlator()
geo = GeoLookup(app.config['GEO_API_URL'])

def run_analysis():
    global analysis_results
    alerts = detector.analyze(analysis_results['logs'])
    iocs = ioc_ext.extract(analysis_results['logs'])
    anomalies = anomaly_det.detect(analysis_results['logs'])
    mitre = mitre_map.map_alerts(alerts)
    chains = correlator.correlate(alerts)
    
    analysis_results['alerts'] = alerts
    analysis_results['iocs'] = iocs
    analysis_results['anomalies'] = anomalies
    analysis_results['mitre'] = mitre
    analysis_results['chains'] = chains
    
    stats = {'total_events': len(analysis_results['logs']), 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for a in alerts:
        sev = a.get('severity', 'info').lower()
        if sev in stats: stats[sev] += 1
    analysis_results['stats'] = stats

@app.route('/')
def dashboard():
    return render_template('dashboard.html', results=analysis_results)

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        if 'files[]' not in request.files:
            return jsonify({'error': 'No file part'})
        files = request.files.getlist('files[]')
        
        global analysis_results
        analysis_results['logs'] = []
        
        for file in files:
            if file.filename:
                content = file.read().decode('utf-8', errors='ignore')
                parsed = parser.parse(file.filename, content)
                analysis_results['logs'].extend(parsed)
                
        run_analysis()
        return jsonify({'message': 'Analysis complete', 'redirect': url_for('dashboard')})
    return render_template('upload.html')

@app.route('/alerts')
def alerts():
    return render_template('alerts.html', alerts=analysis_results['alerts'])

@app.route('/iocs')
def iocs():
    return render_template('iocs.html', iocs=analysis_results['iocs'])

@app.route('/mitre')
def mitre():
    return render_template('mitre.html', mitre=analysis_results['mitre'])

@app.route('/analysis')
def analysis():
    return render_template('analysis.html', anomalies=analysis_results['anomalies'], chains=analysis_results['chains'])

@app.route('/report')
def report():
    return render_template('report.html', results=analysis_results)

if __name__ == '__main__':
    # Load sample logs automatically if empty
    sample_dir = os.path.join(os.path.dirname(__file__), 'sample_logs')
    for f in os.listdir(sample_dir):
        if os.path.isfile(os.path.join(sample_dir, f)):
            with open(os.path.join(sample_dir, f), 'r') as fd:
                analysis_results['logs'].extend(parser.parse(f, fd.read()))
    if analysis_results['logs']:
        run_analysis()
    app.run(host='0.0.0.0', port=5000, debug=True)
