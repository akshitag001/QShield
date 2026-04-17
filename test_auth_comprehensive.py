#!/usr/bin/env python
"""Comprehensive authentication flow tests."""

import requests

session = requests.Session()

print("=" * 60)
print("Q-SHIELD AUTHENTICATION SYSTEM TEST")
print("=" * 60)

# Test 1: Attempt login with invalid credentials
print("\n[Test 1] Login with invalid credentials")
response = session.post(
    'http://localhost:9000/login',
    data={'username': 'admin', 'password': 'wrongpassword'},
    allow_redirects=False
)
print(f"  Status Code: {response.status_code}")
print(f"  Response contains 'error': {'error' in response.text}")
print(f"  Session cookies: {session.cookies}")

# Test 2: Access dashboard without authentication
print("\n[Test 2] Access dashboard without authentication")
response = session.get('http://localhost:9000/', allow_redirects=False)
print(f"  Status Code: {response.status_code} (should be 302 - redirect)")
print(f"  Redirects to: {response.headers.get('location', 'N/A')}")

# Test 3: Login with valid credentials
print("\n[Test 3] Login with valid credentials (admin/admin123)")
response = session.post(
    'http://localhost:9000/login',
    data={'username': 'admin', 'password': 'admin123'},
    allow_redirects=False
)
print(f"  Status Code: {response.status_code} (should be 302 - redirect to dashboard)")
print(f"  Redirects to: {response.headers.get('location', 'N/A')}")
print(f"  Session cookies after login: {session.cookies}")
print(f"  Session ID cookie: {session.cookies.get('session_id', 'NOT SET')}")

# Test 4: Access dashboard with valid session
print("\n[Test 4] Access dashboard with valid session")
response = session.get('http://localhost:9000/', allow_redirects=False)
print(f"  Status Code: {response.status_code} (should be 200 - success)")
if response.status_code == 200:
    print(f"  Page content length: {len(response.text)} bytes")
    print(f"  Contains 'Scan Report': {'Scan Report' in response.text}")

# Test 5: Logout
print("\n[Test 5] Logout")
response = session.get('http://localhost:9000/logout', allow_redirects=False)
print(f"  Status Code: {response.status_code} (should be 302)")
print(f"  Redirects to: {response.headers.get('location', 'N/A')}")
print(f"  Session cookies after logout: {session.cookies}")

# Test 6: Verify dashboard is no longer accessible
print("\n[Test 6] Verify dashboard is no longer accessible after logout")
response = session.get('http://localhost:9000/', allow_redirects=False)
print(f"  Status Code: {response.status_code} (should be 302 - redirect to login)")
print(f"  Redirects to: {response.headers.get('location', 'N/A')}")

print("\n" + "=" * 60)
print("All tests completed!")
print("=" * 60)
