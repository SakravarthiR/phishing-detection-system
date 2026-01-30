/**
 * Login page stuff - handles authentication and redirects.
 * Optimized for low memory (Render 512MB tier)
 */

// Get API URL based on environment
function getAPIURL() {
    const hostname = window.location.hostname;
    
    // Local development or file:// access
    if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '') {
        return 'http://localhost:5000';
    }
    
    // Production
    return 'https://phishing-detection-system-1.onrender.com';
}

// Throttle function
function throttle(func, limit) {
    let inThrottle;
    return function(...args) {
        if (!inThrottle) {
            func.apply(this, args);
            inThrottle = true;
            setTimeout(() => inThrottle = false, limit);
        }
    };
}

// 3D Parallax Background Effect (memory-optimized with throttling)
const parallaxBg = document.querySelector('.parallax-bg-login');
let isIdle = true;
let idleTimer = null;

const resetParallax = () => {
    if (parallaxBg) {
        parallaxBg.style.transform = 'translate(0px, 0px) scale(1.05)';
    }
};

const handleParallaxMove = throttle((e) => {
    if (!parallaxBg || isIdle) return;
    
    const mouseX = e.clientX / window.innerWidth;
    const mouseY = e.clientY / window.innerHeight;
    
    const moveX = (mouseX - 0.5) * 40;
    const moveY = (mouseY - 0.5) * 40;
    
    parallaxBg.style.transform = `translate(${moveX}px, ${moveY}px) scale(1.05)`;
}, 50);

document.addEventListener('mousemove', (e) => {
    isIdle = false;
    
    if (idleTimer) {
        clearTimeout(idleTimer);
    }
    
    handleParallaxMove(e);
    
    // Reset after 3 seconds of inactivity
    idleTimer = setTimeout(() => {
        isIdle = true;
        resetParallax();
    }, 3000);
}, {passive: true});

// Configuration
const USE_SECURE_API = true; // Must use secure backend JWT authentication

const API_BASE_URL = getAPIURL();

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
    
    try {
        const response = await fetch(`${API_BASE_URL}/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password })
        });
        
        console.log(`Response status: ${response.status}`);
        
        if (!response.ok) {
            return {
                success: false,
                message: 'Authentication failed'
            };
        }
        
        const data = await response.json();
        console.log('Response data:', data);
        
        if (data.success) {
            console.log('✅ Authentication successful!');
            return {
                success: true,
                token: data.token,
                session_id: data.session_id,
                expiresIn: data.expires_in,
                privileged: data.privileged || false,
                device_name: data.device_name || 'Unknown Device',
                username: username
            };
        } else {
            return {
                success: false,
                message: data.message || 'Authentication failed'
            };
        }
    } catch (error) {
        console.error('Connection error:', error);
        return {
            success: false,
            message: 'Connection failed. Is the backend running?'
        };
    }
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
    
    try {
        // Authenticate with secure backend (required)
        const authResult = await authenticateWithBackend(username, password);
        
        if (authResult.success) {
            // Clear any errors
            hideError();
            
            // Store session using the new IP-based session manager
            storeSession(authResult);
            
            // Success - show success message and redirect
            btnText.textContent = 'ACCESS GRANTED';
            btnIcon.textContent = '✓';
            btnIcon.style.display = 'inline-block';
            btnSpinner.classList.add('hidden');
            
            console.log('✅ Session stored. Privilege level:', authResult.privileged ? 'ADMIN' : 'USER');
            
            // Immediate redirect
            window.location.href = 'index.html';
        } else {
            // Failed authentication
            setLoading(false);
            showError(`⚠️ ${authResult.message || 'INVALID CREDENTIALS - ACCESS DENIED'}`);
            
            // Clear password field
            passwordInput.value = '';
            passwordInput.focus();
        }
    } catch (error) {
        console.error('Login error:', error);
        setLoading(false);
        showError('⚠️ LOGIN ERROR - TRY AGAIN');
        passwordInput.value = '';
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
