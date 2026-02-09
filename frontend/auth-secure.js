/**
 * Login page stuff - handles authentication and redirects.
 * Optimized for low memory (Render 512MB tier)
 */

console.log('[AUTH] Script loading...');

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

// SESSION_KEY and SESSION_DURATION already declared elsewhere, remove duplicate

// DOM Elements - will be set after DOM loads
let loginForm, usernameInput, passwordInput, loginBtn;
let btnText, btnIcon, btnSpinner, errorMessage;

// Protect input values from being cleared
let protectedUsername = '';
let protectedPassword = '';

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
        console.log('📤 Sending fetch request...');
        const response = await fetch(`${API_BASE_URL}/login`, {
            method: 'POST',
            mode: 'cors',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify({ username, password })
        });
        
        console.log('📥 Response received');
        console.log(`   Status: ${response.status}`);
        console.log(`   OK: ${response.ok}`);
        console.log(`   Headers:`, [...response.headers.entries()]);
        
        if (!response.ok) {
            const errorText = await response.text();
            console.error('❌ Response not OK:', errorText);
            return {
                success: false,
                message: 'Authentication failed: ' + response.status
            };
        }
        
        const responseText = await response.text();
        console.log('📄 Response text:', responseText);
        
        let data;
        try {
            data = JSON.parse(responseText);
        } catch (parseError) {
            console.error('❌ JSON parse error:', parseError);
            return {
                success: false,
                message: 'Invalid response from server'
            };
        }
        
        console.log('📦 Parsed data:', data);
        
        if (data.success) {
            console.log('✅ Authentication successful!');
            return {
                success: true,
                token: data.token,
                session_id: data.session_id,
                expires_in: data.expires_in,
                csrf_token: data.csrf_token,
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
        console.error('❌ Fetch error:', error);
        console.error('   Name:', error.name);
        console.error('   Message:', error.message);
        console.error('   Stack:', error.stack);
        return {
            success: false,
            message: `Connection failed: ${error.message}`
        };
    }
}

// Handle login
async function handleLogin(e) {
    // CRITICAL: Stop form submission immediately
    e.preventDefault();
    e.stopPropagation();
    
    console.log('🔐 Login attempt started');
    console.log('   Username field value:', usernameInput.value);
    console.log('   Username protected value:', protectedUsername);
    console.log('   Password field has value:', !!passwordInput.value);
    console.log('   Password protected has value:', !!protectedPassword);
    
    // Use protected values OR input values (whichever is available)
    const username = (protectedUsername || usernameInput.value).trim();
    const password = protectedPassword || passwordInput.value;
    
    console.log('   Username (final):', username);
    console.log('   Password length:', password.length);
    
    // Hide previous errors
    hideError();
    
    // Validate input
    if (!username || !password) {
        showError('⚠️ USERNAME AND PASSWORD REQUIRED');
        console.log('❌ Validation failed - empty fields');
        return;
    }
    
    console.log('✓ Validation passed, setting loading state...');
    
    // Set loading state
    setLoading(true);
    
    try {
        // Authenticate with secure backend (required)
        const authResult = await authenticateWithBackend(username, password);
        
        if (authResult.success) {
            // Clear any errors
            hideError();
            
            console.log('🔑 authResult received:', JSON.stringify(authResult, null, 2));
            
            // Store session using the new IP-based session manager
            storeSession(authResult);
            
            // Verify session was stored
            const storedSession = localStorage.getItem('phishing_detector_session');
            console.log('📦 Session in localStorage:', storedSession);
            
            // Success - show success message and redirect
            btnText.textContent = 'ACCESS GRANTED';
            btnIcon.textContent = '✓';
            btnIcon.style.display = 'inline-block';
            btnSpinner.classList.add('hidden');
            
            console.log('✅ Session stored. Privilege level:', authResult.privileged ? 'ADMIN' : 'USER');
            console.log('🚀 Redirecting to index.html in 500ms...');
            
            // Delay redirect slightly to ensure localStorage is written
            setTimeout(() => {
                console.log('🚀 Executing redirect now...');
                window.location.href = 'index.html';
            }, 500);
        } else {
            // Failed authentication
            console.log('❌ Authentication failed:', authResult.message);
            setLoading(false);
            showError(authResult.message || '⚠️ AUTHENTICATION FAILED');
            protectedPassword = '';
            // Only clear password field, keep username
            passwordInput.value = '';
            passwordInput.focus();
            console.log('   Username preserved:', usernameInput.value);
        }
    } catch (error) {
        console.error('❌ Login error:', error);
        setLoading(false);
        showError('⚠️ LOGIN ERROR - TRY AGAIN');
        protectedPassword = '';
        passwordInput.value = '';
        passwordInput.focus();
        console.log('   Username preserved after error:', usernameInput.value);
    }
}

// Initialize everything when DOM is ready
window.addEventListener('DOMContentLoaded', function() {
    console.log('[+] DOM loaded, initializing login system...');
    
    // Get DOM elements
    loginForm = document.getElementById('loginForm');
    usernameInput = document.getElementById('username');
    passwordInput = document.getElementById('password');
    loginBtn = document.getElementById('loginBtn');
    errorMessage = document.getElementById('errorMessage');
    
    if (loginBtn) {
        btnText = loginBtn.querySelector('.btn-text');
        btnIcon = loginBtn.querySelector('.btn-icon');
        btnSpinner = loginBtn.querySelector('.btn-spinner');
    }
    
    console.log('[CHECK] Elements found:', {
        loginForm: !!loginForm,
        usernameInput: !!usernameInput,
        passwordInput: !!passwordInput,
        loginBtn: !!loginBtn
    });
    
    // Setup input protection
    if (usernameInput) {
        usernameInput.addEventListener('input', (e) => {
            protectedUsername = e.target.value;
        });
    }
    
    if (passwordInput) {
        passwordInput.addEventListener('input', (e) => {
            protectedPassword = e.target.value;
        });
    }
    
    // Setup form submit prevention
    if (loginForm) {
        loginForm.addEventListener('submit', (e) => {
            e.preventDefault();
            e.stopPropagation();
            console.log('[FORM] Submit prevented, calling handleLogin');
            handleLogin(e);
            return false;
        });
        console.log('[+] Form submit listener attached');
    }
    
    // Setup button click
    if (loginBtn) {
        loginBtn.addEventListener('click', (e) => {
            console.log('[BUTTON] Click detected');
            e.preventDefault();
            handleLogin(e);
        });
        console.log('[+] Button click listener attached');
    }
    
    // Setup Enter key handlers
    if (usernameInput) {
        usernameInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                if (passwordInput) passwordInput.focus();
            }
        });
    }
    
    if (passwordInput) {
        passwordInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                console.log('[ENTER] Password field, calling handleLogin');
                handleLogin(e);
            }
        });
    }
    
    // Auto-focus username
    if (usernameInput) {
        usernameInput.focus();
    }
    
    // Check session
    checkSession();
    
    console.log('🔐 Login System Ready');
});
