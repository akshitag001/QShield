# Firebase Authentication Module for Q-Shield

This folder contains Firebase Google Sign-In integration for Q-Shield.

## Files

### Frontend (JavaScript)

1. **config.js** - Firebase project configuration
   - Contains Firebase API keys and project details
   - Exported as ES module

2. **auth.js** - Main Firebase authentication service
   - `initializeGoogleSignIn()` - Initialize Firebase
   - `handleGoogleSignIn()` - Trigger Google Sign-In popup
   - `sendTokenToBackend()` - Send Firebase token to backend
   - `handleSignOut()` - Sign out user
   - `onAuthStateChangedListener()` - Monitor auth state
   - `getCurrentUser()` - Get current authenticated user
   - `getIdToken()` - Get Firebase ID token

3. **ui.js** - UI components for Firebase authentication
   - `createGoogleSignInButton()` - Create button HTML
   - `attachGoogleSignInButton()` - Attach button to page
   - `getGoogleSignInStyles()` - Get CSS styles

### Backend (Python)

4. **firebase_auth_backend.py** - Firebase token verification and session management
   - `verify_firebase_id_token()` - Verify Firebase token validity
   - `get_or_create_firebase_user()` - Auto-create users on first sign-in
   - `create_session_from_firebase()` - Create application session
   - `validate_firebase_config()` - Validate Firebase configuration

## Integration Steps

### 1. Update Login Page Template

In `templates/login.html`, add:

```html
<div id="firebase-signin-container"></div>

<div class="auth-divider">
  <span>or</span>
</div>

<!-- Existing username/password form -->
```

Add before closing `</body>`:

```html
<script type="module">
  import { attachGoogleSignInButton } from "/static/firebase_auth/ui.js";
  import { getGoogleSignInStyles } from "/static/firebase_auth/ui.js";
  
  // Inject styles
  const style = document.createElement('style');
  style.textContent = getGoogleSignInStyles();
  document.head.appendChild(style);
  
  // Attach button
  attachGoogleSignInButton('firebase-signin-container');
</script>
```

### 2. Update Main App (app.py)

Import Firebase backend functions:

```python
from firebase_auth.firebase_auth_backend import (
    verify_firebase_id_token,
    get_or_create_firebase_user,
    create_session_from_firebase,
    validate_firebase_config
)
import os
```

Add Firebase API key to environment:

```python
FIREBASE_API_KEY = os.getenv("FIREBASE_API_KEY", "AIzaSyDzu1KxLQsJgIchEgsIiKU97Ga2Derz6a4")
```

Add new API endpoints:

```python
@app.post("/api/auth/firebase-login")
async def firebase_login(request: Request, db: Session = Depends(get_db)):
    """Handle Firebase Google Sign-In"""
    try:
        body = await request.json()
        id_token = body.get("idToken")
        
        if not id_token:
            raise HTTPException(status_code=400, detail="No token provided")
        
        # Verify Firebase token
        firebase_user = verify_firebase_id_token(id_token, FIREBASE_API_KEY)
        
        # Get or create user
        user = get_or_create_firebase_user(db, User, firebase_user)
        
        # Create session
        session_token = create_session_from_firebase(
            db, user, _create_session_token
        )
        
        # Create response with session cookie
        response = JSONResponse({"success": True, "user": firebase_user})
        response.set_cookie(
            key="session_id",
            value=session_token,
            max_age=86400 * 7,
            httponly=True,
            samesite="lax"
        )
        
        _log_event(db, user, "login_google_signin")
        return response
    
    except Exception as e:
        logger.error(f"Firebase login error: {e}")
        raise HTTPException(status_code=401, detail="Firebase authentication failed")


@app.post("/api/auth/firebase-logout")
async def firebase_logout(request: Request, db: Session = Depends(get_db)):
    """Handle Firebase Sign-Out"""
    try:
        user = _get_current_user(request, db)
        if user:
            user.session_token = None
            db.commit()
            _log_event(db, user, "logout_google_signin")
        
        response = JSONResponse({"success": True})
        response.delete_cookie(key="session_id")
        return response
    except Exception as e:
        logger.error(f"Firebase logout error: {e}")
        raise HTTPException(status_code=500, detail="Logout failed")
```

### 3. Set Environment Variable

Add to `.env` or deployment config:

```
FIREBASE_API_KEY=AIzaSyDzu1KxLQsJgIchEgsIiKU97Ga2Derz6a4
```

### 4. Copy Frontend Files to Static

```bash
cp firebase_auth/config.js static/firebase_auth/
cp firebase_auth/auth.js static/firebase_auth/
cp firebase_auth/ui.js static/firebase_auth/
```

## Features

✅ **Google Sign-In Popup** - OAuth 2.0 authentication
✅ **Auto User Creation** - Automatically creates users on first sign-in
✅ **Session Management** - Creates application session tokens
✅ **Dual Authentication** - Users can use Google or username/password
✅ **Audit Logging** - Tracks all authentication events
✅ **Token Verification** - Secure backend verification of Firebase tokens
✅ **Responsive Design** - Works on mobile and desktop

## Security Features

- Firebase ID token verification via official REST API
- HttpOnly session cookies prevent XSS attacks
- SameSite cookie protection against CSRF
- Secure session token generation
- Audit trail for all authentication events
- No hardcoded secrets in frontend code

## Testing

Use `test_firebase_auth.py` to test the authentication flow:

```bash
python test_firebase_auth.py
```

## Troubleshooting

### "Invalid Firebase token" error
- Check FIREBASE_API_KEY environment variable
- Verify Google Cloud Console has Web API enabled
- Ensure authorized JavaScript origins include your domain

### "CORS error" when calling backend
- Ensure CORS is enabled in FastAPI app
- Check browser console for CORS errors
- Verify endpoint URL matches your server

### User not created automatically
- Check database User model has proper schema
- Verify get_or_create_firebase_user() permissions
- Check database logs for constraint violations

## References

- [Firebase Web Authentication](https://firebase.google.com/docs/auth/web)
- [Google Sign-In Integration](https://developers.google.com/identity/protocols/oauth2/web-server)
- [Firebase Console](https://console.firebase.google.com/)
