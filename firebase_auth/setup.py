"""
Firebase Configuration Setup Guide
Environment variables and configuration for Q-Shield Firebase integration
"""

# ENVIRONMENT VARIABLES REQUIRED

# ===== Firebase Configuration =====
# Get these from: https://console.firebase.google.com/ 
# Project Settings → Your apps → Web app

FIREBASE_API_KEY = "AIzaSyDzu1KxLQsJgIchEgsIiKU97Ga2Derz6a4"
FIREBASE_AUTH_DOMAIN = "qshield-c5847.firebaseapp.com"
FIREBASE_PROJECT_ID = "qshield-c5847"
FIREBASE_STORAGE_BUCKET = "qshield-c5847.firebasestorage.app"
FIREBASE_MESSAGING_SENDER_ID = "954289198164"
FIREBASE_APP_ID = "1:954289198164:web:ab57d0f93b74649070c9c1"
FIREBASE_MEASUREMENT_ID = "G-BW9E4HEEJY"

# ===== Optional: Firebase Realtime Database =====
# Only needed if using Firebase Realtime Database
# FIREBASE_DATABASE_URL = "https://qshield-c5847-default-rtdb.firebaseio.com"

# ===== Application Configuration =====
# URL where Q-Shield will be hosted (for OAuth redirect)
QSHIELD_URL = "http://localhost:9000"  # Development
# QSHIELD_URL = "https://qshield.yourdomain.com"  # Production

# ===== Setup Steps =====
"""
1. Create Firebase Project
   - Go to https://console.firebase.google.com/
   - Click "Add Project" for Q-Shield
   - Select or create Google Cloud project
   - Enable Google Analytics (optional)

2. Register Web App
   - In Firebase Console, click "+ Add app"
   - Select "Web" platform
   - Copy configuration values above
   - Accept terms and continue

3. Enable Google Authentication
   - In Firebase Console, go to Authentication → Sign-in method
   - Enable "Google" provider
   - Add authorized domains (localhost for dev, your domain for prod)

4. Configure OAuth Consent Screen
   - Go to Google Cloud Console → APIs & Services → OAuth consent screen
   - Create external app or user-created
   - Add scopes: "email", "profile"
   - Add test users (for development)

5. Set Environment Variables
   
   Development (.env file):
   ---
   FIREBASE_API_KEY=AIzaSyDzu1KxLQsJgIchEgsIiKU97Ga2Derz6a4
   QSHIELD_URL=http://localhost:9000
   ---
   
   Production (Environment Variables):
   - Set in your deployment platform (Vercel, Render, etc.)
   - FIREBASE_API_KEY=...
   - QSHIELD_URL=https://qshield.yourdomain.com

6. Configure Authorized Redirect URIs
   - Firebase Console → Project Settings → Authorized domains
   - Add: localhost, 127.0.0.1 (development)
   - Add: yourdomain.com (production)

7. Test the Integration
   - Start Q-Shield: python -m uvicorn app:app
   - Go to http://localhost:9000/login
   - Click "Sign in with Google"
   - Verify sign-in works

Troubleshooting:

Issue: "Authorization error" when clicking Google Sign-In
- Check FIREBASE_API_KEY is correct
- Verify localhost:9000 is in authorized domains
- Clear browser cache and cookies
- Check browser console for CORS errors

Issue: "Invalid Firebase configuration"
- Verify all Firebase config values are correct
- Check Firebase project hasn't been deleted
- Ensure Web API is enabled in Google Cloud Console

Issue: "User creation failed"
- Check database migrations are applied
- Verify User table has all required columns
- Check database permissions for user creation

Issue: "Session token not set"
- Verify _create_session_token() function is available
- Check User.session_token column exists
- Ensure database commit is successful

For detailed docs, see: firebase_auth/README.md
"""

import os


def validate_firebase_config():
    """Validate Firebase configuration is properly set"""
    required_keys = [
        "FIREBASE_API_KEY",
    ]
    
    missing = []
    for key in required_keys:
        if not os.getenv(key):
            missing.append(key)
    
    if missing:
        raise Exception(
            f"Missing Firebase configuration: {', '.join(missing)}\n"
            f"Please set environment variables in firebase_auth/setup.py or .env file"
        )
    
    print("✅ Firebase configuration is valid")


if __name__ == "__main__":
    validate_firebase_config()
