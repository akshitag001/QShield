#!/usr/bin/env python
"""
Test Firebase token verification with detailed output
"""

import json
import logging
import requests

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Firebase configuration
FIREBASE_API_KEY = "AIzaSyDzu1KxLQsJgIchEgsIiKU97Ga2Derz6a4"
FIREBASE_TOKEN_VERIFY_URL = "https://identitytoolkit.googleapis.com/v1/accounts:lookup"

def test_firebase_api():
    """Test Firebase API connectivity"""
    print("="*60)
    print("Testing Firebase API Verification Endpoint")
    print("="*60)
    
    # Try with a fake token first
    fake_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyMzQ1Njc4OTAifQ.eyJzdWIiOiIxMjM0NTY3ODkwIn0.fake"
    
    url = f"{FIREBASE_TOKEN_VERIFY_URL}?key={FIREBASE_API_KEY}"
    
    print(f"\nEndpoint: {url[:80]}...")
    print(f"Token: {fake_token[:50]}...")
    
    payload = {
        "idToken": fake_token
    }
    
    print(f"\nSending request with payload:")
    print(f"  {json.dumps(payload, indent=2)[:100]}...")
    
    try:
        response = requests.post(url, json=payload, timeout=10)
        
        print(f"\nResponse Status: {response.status_code}")
        print(f"Response Headers: {dict(response.headers)}")
        print(f"\nResponse Content:")
        print(response.text[:500])
        
        if response.status_code == 200:
            data = response.json()
            print(f"\nParsed Response:")
            print(json.dumps(data, indent=2)[:500])
        else:
            print(f"\nError Response:")
            try:
                error_data = response.json()
                print(json.dumps(error_data, indent=2))
            except:
                print(f"Could not parse error response as JSON")
    
    except Exception as e:
        print(f"\nException during request: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_firebase_api()
