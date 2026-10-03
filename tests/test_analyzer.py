import unittest
from core.log_parser import LogParser
from core.threat_detector import ThreatDetector
from core.ioc_extractor import IOCExtractor
import os

class TestAnalyzer(unittest.TestCase):
    def setUp(self):
        self.parser = LogParser()
        self.detector = ThreatDetector(os.path.join(os.path.dirname(__file__), '../rules/default_rules.yaml'))
        self.ioc_ext = IOCExtractor()
        
    def test_log_parsing(self):
        content = '192.168.1.100 - - [03/Oct/2026:10:16:00 +0000] "GET /login.php?user=admin\' OR 1=1-- HTTP/1.1" 200 500 "-" "sqlmap/1.5"'
        parsed = self.parser.parse('apache_access.log', content)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]['source_ip'], '192.168.1.100')
        self.assertEqual(parsed[0]['metadata']['user_agent'], 'sqlmap/1.5')

    def test_threat_detection(self):
        logs = [{
            'source_ip': '192.168.1.100',
            'raw_message': '192.168.1.100 - - [03/Oct/2026:10:16:00 +0000] "GET /login.php?user=admin\' OR 1=1-- HTTP/1.1" 200 500 "-" "sqlmap/1.5"',
            'metadata': {'request': '/login.php?user=admin\' OR 1=1--', 'user_agent': 'sqlmap/1.5'}
        }]
        alerts = self.detector.analyze(logs)
        self.assertTrue(len(alerts) > 0)
        
    def test_ioc_extraction(self):
        logs = [{'raw_message': 'Suspicious file hash 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 found'}]
        iocs = self.ioc_ext.extract(logs)
        self.assertTrue(any(ioc['value'] == '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8' for ioc in iocs))

if __name__ == '__main__':
    unittest.main()
