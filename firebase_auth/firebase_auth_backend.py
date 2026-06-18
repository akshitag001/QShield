"""
Firebase Authentication Backend
Verify Firebase tokens and manage user sessions
"""

import json
import logging
from typing import Optional, Dict, Any, Type

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    requests = None

from fastapi import HTTPException
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

# Firebase token verification endpoint
FIREBASE_TOKEN_VERIFY_URL = "https://identitytoolkit.googleapis.com/v1/accounts:lookup"


class FirebaseAuthError(Exception):
    """Custom exception for Firebase authentication errors"""
    pass


def verify_firebase_id_token(id_token: str, firebase_api_key: str) -> Dict[str, Any]:
    """
    Verify Firebase ID token by calling Firebase REST API
    
    Args:
        id_token: Firebase ID token from client
        firebase_api_key: Firebase Web API Key
        
    Returns:
        Decoded token data with user info
        
    Raises:
        FirebaseAuthError: If token is invalid or verification fails
    """
    try:
        # Use Firebase REST API to verify token
        url = f"{FIREBASE_TOKEN_VERIFY_URL}?key={firebase_api_key}"
        
        payload = {
            "idToken": id_token
        }
        
        logger.info(f"Verifying Firebase token with endpoint: {url[:80]}...")
        logger.debug(f"Token (first 50 chars): {id_token[:50]}...")
        
        response = requests.post(url, json=payload, timeout=10)
        
        logger.info(f"Firebase API response status: {response.status_code}")
        logger.debug(f"Firebase API response: {response.text[:500]}")
        
        if response.status_code != 200:
            error_data = response.json() if response.headers.get('content-type') == 'application/json' else {"message": response.text}
            logger.error(f"Firebase verification failed (status {response.status_code}): {error_data}")
            # Extract error message from nested error structure
            if isinstance(error_data, dict) and "error" in error_data:
                error_msg = error_data["error"].get("message", str(error_data))
            else:
                error_msg = error_data.get("message", str(error_data))
            raise FirebaseAuthError(f"Firebase API error: {error_msg}")
        
        data = response.json()
        
        if not data.get("users"):
            logger.error(f"Firebase response has no users: {data}")
            raise FirebaseAuthError("No user info in token response")
        
        user_info = data["users"][0]
        
        logger.info(f"Successfully verified Firebase token for user: {user_info.get('email')}")
        
        return {
            "uid": user_info.get("localId"),
            "email": user_info.get("email"),
            "display_name": user_info.get("displayName"),
            "photo_url": user_info.get("photoUrl"),
            "email_verified": user_info.get("emailVerified", False),
            "provider_id": user_info.get("providerUserInfo", [{}])[0].get("rawId", "")
        }
    
    except requests.RequestException as e:
        logger.error(f"Firebase API request error: {e}")
        raise FirebaseAuthError(f"Firebase verification request failed: {str(e)}")
    except (KeyError, ValueError, json.JSONDecodeError) as e:
        logger.error(f"Firebase response parsing error: {e}")
        raise FirebaseAuthError(f"Invalid Firebase response: {str(e)}")


def get_or_create_firebase_user(
    db: Session,
    user_model: Type,
    firebase_user_data: Dict[str, Any]
) -> Any:
    """
    Get existing user or create new one from Firebase data
    
    Args:
        db: Database session
        user_model: SQLAlchemy User model
        firebase_user_data: User data from Firebase verification
        
    Returns:
        User instance (existing or newly created)
    """
    try:
        email = firebase_user_data.get("email")
        logger.info(f"Looking up Firebase user: {email}")
        
        if not email:
            logger.error("Firebase user data missing email")
            raise ValueError("Firebase user data must contain email")
        
        # Try to find existing user by email
        user = db.query(user_model).filter(user_model.username == email).first()
        
        if user:
            logger.info(f"Found existing user for email: {email}")
            # Update Firebase-specific info
            if not user.password_hash or user.password_hash != "FIREBASE_AUTH":
                # Mark as Firebase-only user (no traditional password)
                user.password_hash = "FIREBASE_AUTH"
                db.commit()
            return user
        
        # Create new user from Firebase data
        display_name = firebase_user_data.get("display_name", email.split("@")[0])
        logger.info(f"Creating new Firebase user: {email} (display_name: {display_name})")
        
        new_user = user_model(
            username=email,
            password_hash="FIREBASE_AUTH",  # Firebase-only users don't have passwords
            role="viewer",  # Default role for new Google sign-in users
        )
        
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        
        logger.info(f"Created new Firebase user: {email} with ID: {new_user.id}")
        
        return new_user
    
    except Exception as e:
        db.rollback()
        logger.error(f"Error creating/retrieving Firebase user: {e}")
        logger.exception("Full traceback for Firebase user creation:")
        raise


def create_session_from_firebase(
    db: Session,
    user,
    session_token_generator: callable
) -> str:
    """
    Create application session token from Firebase authentication
    
    Args:
        db: Database session
        user: User instance
        session_token_generator: Function to generate secure token
        
    Returns:
        Session token string
    """
    try:
        from datetime import datetime, timezone
        
        logger.info(f"Creating session for Firebase user: {user.username} (ID: {user.id})")
        
        # Generate session token
        session_token = session_token_generator()
        logger.debug(f"Generated session token (first 20 chars): {session_token[:20]}...")
        
        # Store token in user record
        user.session_token = session_token
        user.last_login = datetime.now(timezone.utc)
        db.commit()
        
        logger.info(f"Successfully created session for Firebase user: {user.username}")
        
        return session_token
    
    except Exception as e:
        db.rollback()
        logger.error(f"Error creating session from Firebase: {e}")
        raise


def validate_firebase_config(firebase_api_key: str) -> bool:
    """
    Validate Firebase API key is properly configured
    
    Args:
        firebase_api_key: Firebase Web API Key
        
    Returns:
        True if valid, raises exception otherwise
    """
    if not firebase_api_key or len(firebase_api_key) < 10:
        raise FirebaseAuthError("Invalid Firebase API key configuration")
    return True


__all__ = [
    "verify_firebase_id_token",
    "get_or_create_firebase_user",
    "create_session_from_firebase",
    "validate_firebase_config",
    "FirebaseAuthError"
]
