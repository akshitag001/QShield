"""
Firebase Authentication Package for Q-Shield
Provides Google Sign-In integration and session management
"""

from .firebase_auth_backend import (
    verify_firebase_id_token,
    get_or_create_firebase_user,
    create_session_from_firebase,
    validate_firebase_config,
    FirebaseAuthError
)

__version__ = "1.0.0"
__all__ = [
    "verify_firebase_id_token",
    "get_or_create_firebase_user",
    "create_session_from_firebase",
    "validate_firebase_config",
    "FirebaseAuthError"
]
