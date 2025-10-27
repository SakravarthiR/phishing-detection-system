/**
 * Login page stuff - handles authentication and redirects.
 * 
 * Uses JWT tokens stored in localStorage. Added some loading animations
 * to make it feel more responsive. The parallax background was a fun touch.
 */

// 3D Parallax Background Effect
document.addEventListener('mousemove', (e) => {
    const parallaxBg = document.querySelector('.parallax-bg-login');
    if (!parallaxBg) return;
    
    const mouseX = e.clientX / window.innerWidth;
    const mouseY = e.clientY / window.innerHeight;
    
    const moveX = (mouseX - 0.5) * 40;
    const moveY = (mouseY - 0.5) * 40;
    
    parallaxBg.style.transform = `translate(${moveX}px, ${moveY}px) scale(1.05)`;
});

// Configuration
const USE_SECURE_API = true; // Set to true to use secure backend JWT authentication
const API_BASE_URL = 'https://api.phishingdetector.systems';

// Local credentials (fallback if secure API is disabled) - DISABLED FOR SECURITY
const VALID_USERNAME = 'admin';
const VALID_PASSWORD = null; // Disabled - use secure backend only
const SESSION_KEY = 'phishing_detector_session';
const SESSION_DURATION = 24 * 60 * 60 * 1000; // 24 hours in milliseconds

// DOM Elements
const loginForm = document.getElementById('loginForm');
const usernameInput = document.getElementById('username');
const passwordInput = document.getElementById('password');
const loginBtn = document.getElementById('loginBtn');
const btnText = loginBtn.querySelector('.btn-text');
const btnIcon = loginBtn.querySelector('.btn-icon');
const btnSpinner = loginBtn.querySelector('.btn-spinner');
const errorMessage = document.getElementById('errorMessage');

// Check if user is already logged in
function checkSession() {
    const session = localStorage.getItem(SESSION_KEY);
    
    if (session) {
        try {
            const sessionData = JSON.parse(session);
            const currentTime = new Date().getTime();
            
            // Check if session is still valid
            if (currentTime < sessionData.expiry) {
                // Redirect to main page
                window.location.href = 'index.html';
                return true;
            } else {
                // Session expired, remove it
                localStorage.removeItem(SESSION_KEY);
            }
        } catch (e) {
            localStorage.removeItem(SESSION_KEY);
        }
    }
    
    return false;
}

// Create local session (for non-JWT mode)
function createLocalSession() {
    const currentTime = new Date().getTime();
    const expiry = currentTime + SESSION_DURATION;
    
    const sessionData = {
        username: VALID_USERNAME,
        loginTime: currentTime,
        expiry: expiry,
        expiresAt: expiry, // Backward compatibility
        local: true
    };
    
    localStorage.setItem(SESSION_KEY, JSON.stringify(sessionData));
}

// Create JWT session (for secure backend)
function createJWTSession(token, expiresIn) {
    const currentTime = new Date().getTime();
    const expiry = currentTime + (expiresIn * 1000); // expiresIn is in seconds
    
    const sessionData = {
        token: token,
        loginTime: currentTime,
        expiry: expiry,
        expiresAt: expiry, // Backward compatibility
        local: false
    };
    
    localStorage.setItem(SESSION_KEY, JSON.stringify(sessionData));
}

// Show error message
function showError(message) {
    errorMessage.textContent = message;
    errorMessage.classList.remove('hidden');
    
    // Auto-hide after 5 seconds
    setTimeout(() => {
        hideError();
    }, 5000);
}

// Hide error message
function hideError() {
    errorMessage.classList.add('hidden');
}

// Set loading state
function setLoading(loading) {
    if (loading) {
        loginBtn.disabled = true;
        btnText.textContent = 'AUTHENTICATING';
        btnIcon.style.display = 'none';
        btnSpinner.classList.remove('hidden');
    } else {
        loginBtn.disabled = false;
        btnText.textContent = 'ACCESS SYSTEM';
        btnIcon.style.display = 'inline-block';
        btnSpinner.classList.add('hidden');
    }
}

// Authenticate with secure backend
async function authenticateWithBackend(username, password) {
    console.log('🔐 Attempting backend authentication...');
    console.log(`   URL: ${API_BASE_URL}/login`);
    console.log(`   Username: ${username}`);
    
    try {
        const response = await fetch(`${API_BASE_URL}/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ 
                username: username, 
                password: password 
            })
        });
        
        const data = await response.json();
        
        console.log(`   Response Status: ${response.status}`);
        console.log(`   Response Data:`, data);
        
        if (response.ok && data.success) {
            console.log('✅ Authentication successful!');
            return {
                success: true,
                token: data.token,
                expiresIn: data.expires_in
            };
        } else {
            console.log('❌ Authentication failed:', data.message);
            return {
                success: false,
                message: data.message || data.error || 'Authentication failed'
            };
        }
    } catch (error) {
        console.error('❌ Backend connection error:', error);
        return {
            success: false,
            message: `Cannot connect to API at ${API_BASE_URL}. Please ensure secure_api.py is running.`
        };
    }
}

// Local authentication (fallback) - DISABLED for security
function authenticateLocally(username, password) {
    // Local auth is disabled - only use secure backend
    return { 
        success: false, 
        message: 'Backend authentication required. Please ensure API is running.' 
    };
}

// Handle login
async function handleLogin(e) {
    e.preventDefault();
    
    const username = usernameInput.value.trim();
    const password = passwordInput.value;
    
    // Hide previous errors
    hideError();
    
    // Validate input
    if (!username || !password) {
        showError('⚠️ USERNAME AND PASSWORD REQUIRED');
        return;
    }
    
    // Set loading state
    setLoading(true);
    
    let authResult;
    
    // Try secure backend authentication (local fallback disabled)
    if (USE_SECURE_API) {
        authResult = await authenticateWithBackend(username, password);
        
        // Backend auth successful - create JWT session
        if (authResult.success) {
            createJWTSession(authResult.token, authResult.expiresIn);
        }
        // Backend auth failed - show error (no fallback to local)
    } else {
        // Local auth disabled for security
        authResult = {
            success: false,
            message: 'Backend authentication is required. Please enable USE_SECURE_API.'
        };
    }
    
    if (authResult.success) {
        // Success - show success message and redirect
        btnText.textContent = 'ACCESS GRANTED';
        btnIcon.textContent = '✓';
        btnIcon.style.display = 'inline-block';
        btnSpinner.classList.add('hidden');
        
        setTimeout(() => {
            window.location.href = 'index.html';
        }, 500);
    } else {
        // Failed authentication
        setLoading(false);
        showError(`⚠️ ${authResult.message || 'INVALID CREDENTIALS - ACCESS DENIED'}`);
        
        // Clear password field
        passwordInput.value = '';
        passwordInput.focus();
    }
}

// Event Listeners
loginForm.addEventListener('submit', handleLogin);

// Check session on page load
checkSession();

// Auto-focus username input
usernameInput.focus();

console.log('🔐 Login System Initialized');
console.log(`Mode: ${USE_SECURE_API ? 'Secure Backend JWT' : 'Local'}`);
console.log('Credentials: Check credentials.json file');
