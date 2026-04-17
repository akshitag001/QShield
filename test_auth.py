import requests

session = requests.Session()

# Test 1: Login with invalid credentials
print('Test 1: Login with invalid credentials')
response = session.post(
    'http://localhost:9000/login',
    data={'username': 'admin', 'password': 'wrongpassword'}
)
print(f'Status: {response.status_code}')
print(f'Response contains error: {"error" in response.text}')
print()

# Test 2: Check if session cookie was NOT set
print('Test 2: Session cookie status after failed login')
print(f'Cookies: {session.cookies}')
print()

# Test 3: Try to access dashboard (should redirect to login)
print('Test 3: Try to access dashboard without valid session')
response = session.get('http://localhost:9000/', allow_redirects=False)
print(f'Status: {response.status_code}')
print(f'Redirects to login: {"login" in response.headers.get("location", "")}')
