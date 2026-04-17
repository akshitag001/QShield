/**
 * Firebase Authentication Service
 * Handles Google Sign-In and user authentication flows
 */

import { initializeApp } from "https://www.gstatic.com/firebasejs/12.12.0/firebase-app.js";
import { 
  getAuth, 
  signInWithPopup, 
  GoogleAuthProvider, 
  onAuthStateChanged,
  signOut 
} from "https://www.gstatic.com/firebasejs/12.12.0/firebase-auth.js";

import firebaseConfig from "./config.js";

// Initialize Firebase
const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const googleProvider = new GoogleAuthProvider();

/**
 * Initialize Google Sign-In
 */
export function initializeGoogleSignIn() {
  // Set up Firebase Google Auth Provider
  googleProvider.addScope('profile');
  googleProvider.addScope('email');
  return auth;
}

/**
 * Handle Google Sign-In Button Click
 */
export async function handleGoogleSignIn() {
  try {
    console.log("Starting Google Sign-In process...");
    
    // Create a timeout promise that rejects after 30 seconds
    const timeoutPromise = new Promise((_, reject) =>
      setTimeout(() => reject(new Error("Google Sign-In timeout - popup may be blocked")), 30000)
    );
    
    // Race between actual signin and timeout
    const result = await Promise.race([
      signInWithPopup(auth, googleProvider),
      timeoutPromise
    ]);
    
    console.log("Google Sign-In successful, user:", result.user.email);
    
    // Get Firebase ID token for backend verification
    console.log("Fetching ID token...");
    const idToken = await result.user.getIdToken();
    console.log("ID token obtained successfully");
    
    // Send token to backend for session creation
    console.log("Sending token to backend...");
    await sendTokenToBackend(idToken);
    
    return { success: true, user: result.user };
  } catch (error) {
    console.error("Google Sign-In Error:", error);
    console.error("Error code:", error.code);
    console.error("Error message:", error.message);
    
    // Provide helpful error messages
    let friendlyMessage = error.message;
    if (error.code === 'auth/popup-blocked') {
      friendlyMessage = "Popup was blocked. Please allow popups and try again.";
    } else if (error.code === 'auth/popup-closed-by-user') {
      friendlyMessage = "Sign-in popup was closed.";
    } else if (error.message.includes('timeout')) {
      friendlyMessage = "Sign-in timed out. Your popup may be blocked.";
    }
    
    throw new Error(friendlyMessage);
  }
}

/**
 * Send Firebase token to backend for verification and session creation
 */
export async function sendTokenToBackend(idToken) {
  try {
    console.log("Sending token to /api/auth/firebase-login...");
    const response = await fetch('/api/auth/firebase-login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ idToken })
    });

    console.log("Backend response status:", response.status);

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      console.error("Backend error response:", errorData);
      throw new Error(`Authentication failed: ${errorData.detail || response.statusText}`);
    }

    const data = await response.json();
    console.log("Backend auth successful:", data);
    
    // Redirect to dashboard on successful authentication
    if (data.success) {
      console.log("Redirecting to dashboard...");
      window.location.href = '/';
    }
    
    return data;
  } catch (error) {
    console.error("Backend authentication error:", error);
    throw error;
  }
}

/**
 * Monitor Auth State Changes
 */
export function onAuthStateChangedListener(callback) {
  return onAuthStateChanged(auth, callback);
}

/**
 * Sign Out User
 */
export async function handleSignOut() {
  try {
    await signOut(auth);
    
    // Notify backend to clear session
    await fetch('/api/auth/firebase-logout', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      }
    });
    
    window.location.href = '/login';
  } catch (error) {
    console.error("Sign out error:", error);
  }
}

/**
 * Get current authenticated user
 */
export function getCurrentUser() {
  return auth.currentUser;
}

/**
 * Get current user's ID token
 */
export async function getIdToken() {
  if (auth.currentUser) {
    return await auth.currentUser.getIdToken();
  }
  return null;
}

export default {
  initializeGoogleSignIn,
  handleGoogleSignIn,
  sendTokenToBackend,
  onAuthStateChangedListener,
  handleSignOut,
  getCurrentUser,
  getIdToken
};
