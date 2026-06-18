/**
 * Firebase UI Components
 * Reusable UI elements for Firebase authentication
 */

import { handleGoogleSignIn } from "./auth.js";

/**
 * Create Google Sign-In Button HTML
 */
export function createGoogleSignInButton() {
  const buttonHTML = `
    <button id="google-signin-btn" class="google-signin-button">
      <svg class="google-icon" viewBox="0 0 24 24" width="20" height="20">
        <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
        <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
        <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
        <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
      </svg>
      <span>Sign in with Google</span>
    </button>
  `;
  return buttonHTML;
}

/**
 * Create and attach Google Sign-In button to a container
 */
export function attachGoogleSignInButton(containerId) {
  console.log("attachGoogleSignInButton called with container:", containerId);
  
  const container = document.getElementById(containerId);
  if (!container) {
    console.error(`Container with ID '${containerId}' not found`);
    return;
  }

  container.innerHTML = createGoogleSignInButton();
  
  const button = document.getElementById('google-signin-btn');
  if (!button) {
    console.error("Google Sign-In button not found after creation");
    return;
  }
  
  console.log("Google Sign-In button created successfully");
  
  button.addEventListener('click', async () => {
    console.log("Google Sign-In button clicked");
    button.disabled = true;
    button.innerHTML = '<span>Signing in...</span>';
    
    try {
      console.log("Calling handleGoogleSignIn...");
      const result = await handleGoogleSignIn();
      console.log("handleGoogleSignIn result:", result);
      // Note: if successful, the page will redirect to '/'
    } catch (error) {
      console.error("Error in button click handler:", error);
      console.error("Error stack:", error.stack);
      
      // Reset button
      button.disabled = false;
      button.innerHTML = '<svg class="google-icon" viewBox="0 0 24 24" width="20" height="20"><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/><path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/></svg><span>Sign in with Google</span>';
      
      // Show error in alert
      alert(`Sign-in failed: ${error.message}`);
    }
  });
}

/**
 * Get Google Sign-In Button CSS
 */
export function getGoogleSignInStyles() {
  return `
    .google-signin-button {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 10px;
      padding: 12px 24px;
      border: 1px solid #dadce0;
      border-radius: 4px;
      font-size: 16px;
      font-weight: 500;
      color: #3c4043;
      background-color: #fff;
      cursor: pointer;
      transition: all 0.3s ease;
      width: 100%;
      max-width: 400px;
    }

    .google-signin-button:hover {
      border-color: #4285f4;
      background-color: #f8f9fa;
      box-shadow: 0 1px 3px rgba(66, 133, 244, 0.3);
    }

    .google-signin-button:active {
      background-color: #f1f3f4;
    }

    .google-signin-button:disabled {
      opacity: 0.5;
      cursor: not-allowed;
    }

    .google-icon {
      width: 20px;
      height: 20px;
    }

    .auth-divider {
      display: flex;
      align-items: center;
      gap: 16px;
      margin: 24px 0;
      color: #999;
    }

    .auth-divider span {
      white-space: nowrap;
      font-size: 14px;
    }

    .auth-divider::before,
    .auth-divider::after {
      content: '';
      flex: 1;
      height: 1px;
      background-color: #e0e0e0;
    }
  `;
}

export default {
  createGoogleSignInButton,
  attachGoogleSignInButton,
  getGoogleSignInStyles
};
