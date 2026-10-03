import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-only-change-this-secret')
    UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50 MB
    HIGH_RISK_COUNTRIES = ['KP', 'IR', 'RU', 'CN', 'SY', 'CU']
    GEO_API_URL = 'http://ip-api.com/json/{}'
    RULES_FILE = os.path.join(os.path.dirname(__file__), 'rules', 'default_rules.yaml')
