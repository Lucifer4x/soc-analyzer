import requests

class GeoLookup:
    def __init__(self, api_url):
        self.api_url = api_url
        self.cache = {}
        
    def lookup(self, ip):
        if ip in ['127.0.0.1', '::1', None, 'Unknown'] or ip.startswith('192.168.') or ip.startswith('10.'):
            return {'country': 'Local', 'city': 'Local'}
            
        if ip in self.cache: return self.cache[ip]
        
        try:
            resp = requests.get(self.api_url.format(ip), timeout=2)
            if resp.status_code == 200:
                data = resp.json()
                res = {'country': data.get('country', 'Unknown'), 'city': data.get('city', 'Unknown')}
                self.cache[ip] = res
                return res
        except:
            pass
        return {'country': 'Unknown', 'city': 'Unknown'}
