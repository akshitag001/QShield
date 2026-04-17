import requests

r = requests.get('http://localhost:9001/login', allow_redirects=False)
print(f'Status: {r.status_code}')
print(f'Contains Google: {"google" in r.text.lower()}')
print(f'Contains Firebase: {"firebase" in r.text.lower()}')
print(f'Contains Sign-In Button: {"google-signin-btn" in r.text}')
print(f'Page length: {len(r.text)} bytes')
