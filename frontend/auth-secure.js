/**
 * Login page - handles auth, MFA, device fingerprinting
 */

console.log('[AUTH] Script loading...');

function getAPIURL() {
    const hostname = window.location.hostname;
    if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '') {
        return 'http://127.0.0.1:5000';
    }
    return 'https://phishing-detection-system-1.onrender.com';
}

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


function generateDeviceFingerprint() {
    const components = [
        navigator.userAgent,
        navigator.language,
        screen.width + 'x' + screen.height,
        screen.colorDepth,
        new Date().getTimezoneOffset(),
        navigator.hardwareConcurrency || 'unknown',
        navigator.platform,
        navigator.maxTouchPoints || 0,
        navigator.deviceMemory || 'unknown',
        Intl.DateTimeFormat().resolvedOptions().timeZone || 'unknown'
    ];
    
    const fingerprint = components.join('|');
    
    const cyrb53 = function(str, seed = 0) {
        let h1 = 0xdeadbeef ^ seed, h2 = 0x41c6ce57 ^ seed;
        for (let i = 0, ch; i < str.length; i++) {
            ch = str.charCodeAt(i);
            h1 = Math.imul(h1 ^ ch, 2654435761);
            h2 = Math.imul(h2 ^ ch, 1597334677);
        }
        h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507);
        h1 ^= Math.imul(h2 ^ (h2 >>> 13), 3266489909);
        h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507);
        h2 ^= Math.imul(h1 ^ (h1 >>> 13), 3266489909);
        return (4294967296 * (2097151 & h2) + (h1 >>> 0)).toString(16);
    };
    
    return cyrb53(fingerprint).padStart(16, '0');
}

function getScreenInfo() {
    return `${screen.width}x${screen.height}x${screen.colorDepth}`;
}

function getTimezone() {
    try {
        return Intl.DateTimeFormat().resolvedOptions().timeZone;
    } catch {
        return 'Unknown';
    }
}

function showMFADialog(challengeId, onSubmit) {
    // Remove existing dialog if any
    const existingDialog = document.getElementById('mfaDialog');
    if (existingDialog) existingDialog.remove();
    
    const dialog = document.createElement('div');
    dialog.id = 'mfaDialog';
    dialog.innerHTML = `
        <div class="mfa-overlay"></div>
        <div class="mfa-modal">
            <div class="mfa-header">
                <span class="mfa-icon">🔐</span>
                <h2>Two-Factor Authentication</h2>
            </div>
            <p class="mfa-description">Enter the 6-digit code from your authenticator app</p>
            <div class="mfa-input-container">
                <input type="text" id="mfaCode" class="mfa-input" maxlength="6" pattern="[0-9]*" 
                       inputmode="numeric" autocomplete="one-time-code" placeholder="000000">
            </div>
            <div class="mfa-actions">
                <button type="button" id="mfaCancelBtn" class="mfa-btn mfa-btn-cancel">Cancel</button>
                <button type="button" id="mfaSubmitBtn" class="mfa-btn mfa-btn-submit">Verify</button>
            </div>
            <p class="mfa-backup-hint">Lost your device? <a href="#" id="mfaBackupLink">Use backup code</a></p>
        </div>
    `;
    
    // Add styles if not already present
    if (!document.getElementById('mfaStyles')) {
        const styles = document.createElement('style');
        styles.id = 'mfaStyles';
        styles.textContent = `
            .mfa-overlay {
                position: fixed; top: 0; left: 0; right: 0; bottom: 0;
                background: rgba(0,0,0,0.8); z-index: 9998;
            }
            .mfa-modal {
                position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%);
                background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                border: 1px solid rgba(59, 130, 246, 0.3);
                border-radius: 16px; padding: 30px; z-index: 9999;
                min-width: 320px; text-align: center;
                box-shadow: 0 25px 50px rgba(0,0,0,0.5);
            }
            .mfa-header { margin-bottom: 20px; }
            .mfa-icon { font-size: 48px; display: block; margin-bottom: 10px; }
            .mfa-header h2 { color: #fff; margin: 0; font-size: 20px; }
            .mfa-description { color: #94a3b8; font-size: 14px; margin-bottom: 20px; }
            .mfa-input-container { margin-bottom: 20px; }
            .mfa-input {
                width: 100%; padding: 16px; font-size: 24px; text-align: center;
                letter-spacing: 8px; background: rgba(255,255,255,0.05);
                border: 2px solid rgba(59, 130, 246, 0.3); border-radius: 8px;
                color: #fff; font-family: monospace;
            }
            .mfa-input:focus { outline: none; border-color: #3b82f6; }
            .mfa-actions { display: flex; gap: 10px; margin-bottom: 15px; }
            .mfa-btn {
                flex: 1; padding: 12px; border: none; border-radius: 8px;
                font-size: 14px; font-weight: 600; cursor: pointer;
            }
            .mfa-btn-cancel { background: rgba(255,255,255,0.1); color: #94a3b8; }
            .mfa-btn-submit { background: #3b82f6; color: #fff; }
            .mfa-btn-submit:hover { background: #2563eb; }
            .mfa-backup-hint { color: #64748b; font-size: 12px; }
            .mfa-backup-hint a { color: #3b82f6; }
        `;
        document.head.appendChild(styles);
    }
    
    document.body.appendChild(dialog);
    
    const mfaInput = document.getElementById('mfaCode');
    const submitBtn = document.getElementById('mfaSubmitBtn');
    const cancelBtn = document.getElementById('mfaCancelBtn');
    
    mfaInput.focus();
    
    // Auto-submit when 6 digits entered
    mfaInput.addEventListener('input', (e) => {
        e.target.value = e.target.value.replace(/[^0-9]/g, '');
        if (e.target.value.length === 6) {
            submitBtn.click();
        }
    });
    
    submitBtn.addEventListener('click', () => {
        const code = mfaInput.value;
        if (code.length === 6) {
            dialog.remove();
            onSubmit(code);
        }
    });
    
    cancelBtn.addEventListener('click', () => {
        dialog.remove();
    });
    
    mfaInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter' && mfaInput.value.length === 6) {
            submitBtn.click();
        }
    });
}

function showSecurityAlert(alerts, anomalyScore) {
    if (!alerts || alerts.length === 0) return;
    
    const existingBanner = document.getElementById('securityAlertBanner');
    if (existingBanner) existingBanner.remove();
    
    // Create banner using safe DOM methods to prevent XSS
    const banner = document.createElement('div');
    banner.id = 'securityAlertBanner';
    
    const securityBanner = document.createElement('div');
    securityBanner.className = 'security-banner ' + (anomalyScore >= 50 ? 'warning' : 'info');
    
    const icon = document.createElement('span');
    icon.className = 'security-icon';
    icon.textContent = '[!]';
    
    const content = document.createElement('div');
    content.className = 'security-content';
    
    const strong = document.createElement('strong');
    strong.textContent = 'Security Notice';
    content.appendChild(strong);
    
    const ul = document.createElement('ul');
    alerts.forEach(function(alertText) {
        const li = document.createElement('li');
        li.textContent = alertText;  // Safe - escapes HTML automatically
        ul.appendChild(li);
    });
    content.appendChild(ul);
    
    const closeBtn = document.createElement('button');
    closeBtn.className = 'security-close';
    closeBtn.textContent = 'x';
    closeBtn.onclick = function() { banner.remove(); };
    
    securityBanner.appendChild(icon);
    securityBanner.appendChild(content);
    securityBanner.appendChild(closeBtn);
    banner.appendChild(securityBanner);
    
    if (!document.getElementById('securityBannerStyles')) {
        const styles = document.createElement('style');
        styles.id = 'securityBannerStyles';
        styles.textContent = `
            #securityAlertBanner {
                position: fixed; top: 20px; right: 20px; z-index: 9000;
                max-width: 350px; animation: slideIn 0.3s ease;
            }
            @keyframes slideIn { from { transform: translateX(100%); } to { transform: translateX(0); } }
            .security-banner {
                display: flex; align-items: flex-start; gap: 12px;
                padding: 16px; border-radius: 12px;
                backdrop-filter: blur(10px);
            }
            .security-banner.warning {
                background: rgba(251, 191, 36, 0.15);
                border: 1px solid rgba(251, 191, 36, 0.4);
            }
            .security-banner.info {
                background: rgba(59, 130, 246, 0.15);
                border: 1px solid rgba(59, 130, 246, 0.4);
            }
            .security-icon { font-size: 24px; }
            .security-content { flex: 1; color: #fff; }
            .security-content strong { display: block; margin-bottom: 8px; }
            .security-content ul { margin: 0; padding-left: 16px; font-size: 13px; color: #cbd5e1; }
            .security-content li { margin-bottom: 4px; }
            .security-close {
                background: none; border: none; color: #94a3b8;
                font-size: 20px; cursor: pointer; padding: 0;
            }
        `;
        document.head.appendChild(styles);
    }
    
    document.body.appendChild(banner);
    
    // Auto-hide after 10 seconds
    setTimeout(() => banner.remove(), 10000);
}

function addTrustDeviceOption() {
    const form = document.getElementById('loginForm');
    if (!form || document.getElementById('trustDeviceGroup')) return;
    
    const trustGroup = document.createElement('div');
    trustGroup.id = 'trustDeviceGroup';
    trustGroup.className = 'form-group trust-device-group';
    trustGroup.innerHTML = `
        <label class="trust-checkbox-label">
            <input type="checkbox" id="trustDevice" class="trust-checkbox">
            <span class="trust-checkmark"></span>
            <span class="trust-text">Trust this device for 30 days</span>
        </label>
    `;
    
    // Insert before button
    const btn = document.getElementById('loginBtn');
    if (btn) {
        form.insertBefore(trustGroup, btn);
    }
    
    if (!document.getElementById('trustDeviceStyles')) {
        const styles = document.createElement('style');
        styles.id = 'trustDeviceStyles';
        styles.textContent = `
            .trust-device-group { margin-bottom: 20px; }
            .trust-checkbox-label {
                display: flex; align-items: center; gap: 10px;
                cursor: pointer; color: #94a3b8; font-size: 13px;
            }
            .trust-checkbox { display: none; }
            .trust-checkmark {
                width: 18px; height: 18px; border: 2px solid rgba(59, 130, 246, 0.5);
                border-radius: 4px; position: relative;
            }
            .trust-checkbox:checked + .trust-checkmark {
                background: #3b82f6; border-color: #3b82f6;
            }
            .trust-checkbox:checked + .trust-checkmark::after {
                content: '✓'; position: absolute; color: #fff;
                font-size: 12px; top: -1px; left: 2px;
            }
        `;
        document.head.appendChild(styles);
    }
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
const USE_SECURE_API = true;
const API_BASE_URL = getAPIURL();

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
            
            if (currentTime < sessionData.expiry) {
                window.location.href = 'index.html';
                return true;
            } else {
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
    const expiry = currentTime + (expiresIn * 1000);
    
    const sessionData = {
        token: token,
        loginTime: currentTime,
        expiry: expiry,
        expiresAt: expiry,
        local: false
    };
    
    localStorage.setItem(SESSION_KEY, JSON.stringify(sessionData));
}

// Show error message
function showError(message) {
    errorMessage.textContent = message;
    errorMessage.classList.remove('hidden');
    
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

// Authenticate with secure backend (Amazon-level security)
async function authenticateWithBackend(username, password, mfaCode = null) {
    console.log('🔐 Attempting backend authentication with Amazon-level security...');
    console.log(`   URL: ${API_BASE_URL}/login`);
    
    const trustDevice = document.getElementById('trustDevice')?.checked || false;
    
    try {
        console.log('📤 Sending secure fetch request...');
        const response = await fetch(`${API_BASE_URL}/login`, {
            method: 'POST',
            mode: 'cors',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'X-Screen-Info': getScreenInfo(),
                'X-Timezone': getTimezone(),
                'X-Device-Fingerprint': generateDeviceFingerprint()
            },
            body: JSON.stringify({ 
                username, 
                password,
                mfa_code: mfaCode,
                trust_device: trustDevice
            })
        });
        
        console.log('📥 Response received');
        console.log(`   Status: ${response.status}`);
        
        const responseText = await response.text();
        console.log('📄 Response text:', responseText.substring(0, 200));
        
        let data;
        try {
            data = JSON.parse(responseText);
        } catch (parseError) {
            console.error('❌ JSON parse error:', parseError);
            return { success: false, message: 'Invalid response from server' };
        }
        
        console.log('📦 Parsed data:', JSON.stringify(data, null, 2));
        
        // Handle MFA requirement
        if (data.mfa_required && !mfaCode) {
            console.log('🔐 MFA required, showing dialog...');
            return {
                success: false,
                mfa_required: true,
                challenge_id: data.challenge_id,
                message: data.message,
                security: data.security
            };
        }
        
        // Handle security alerts
        if (data.security?.alerts?.length > 0) {
            showSecurityAlert(data.security.alerts, data.security.anomaly_score);
        }
        
        if (data.success) {
            console.log('✅ Authentication successful!');
            console.log('🛡️ Security info:', data.security);
            return {
                success: true,
                token: data.token,
                session_id: data.session_id,
                expires_in: data.expires_in,
                csrf_token: data.csrf_token,
                privileged: data.privileged || false,
                device_name: data.device_name || 'Unknown Device',
                username: username,
                security: data.security
            };
        } else {
            // Show remaining attempts if available
            let message = data.message || 'Authentication failed';
            if (data.remaining_attempts !== undefined) {
                message += ` (${data.remaining_attempts} attempts remaining)`;
            }
            if (data.lockout_seconds) {
                message = `Account locked. Try again in ${Math.ceil(data.lockout_seconds / 60)} minutes.`;
            }
            return { success: false, message: message };
        }
    } catch (error) {
        console.error('❌ Fetch error:', error);
        return { success: false, message: `Connection failed: ${error.message}` };
    }
}

// Handle login
async function handleLogin(e, mfaCode = null) {
    e.preventDefault();
    e.stopPropagation();
    
    console.log('🔐 Login attempt started');
    
    const username = (protectedUsername || usernameInput.value).trim();
    const password = protectedPassword || passwordInput.value;
    
    console.log('   Username (final):', username);
    console.log('   Password length:', password.length);
    
    hideError();
    
    if (!username || !password) {
        showError('⚠️ USERNAME AND PASSWORD REQUIRED');
        console.log('❌ Validation failed - empty fields');
        return;
    }
    
    console.log('✓ Validation passed, setting loading state...');
    setLoading(true);
    
    try {
        const authResult = await authenticateWithBackend(username, password, mfaCode);
        
        // Handle MFA requirement
        if (authResult.mfa_required && !mfaCode) {
            setLoading(false);
            showMFADialog(authResult.challenge_id, (code) => {
                // Retry login with MFA code
                handleLogin(e, code);
            });
            return;
        }
        
        if (authResult.success) {
            hideError();
            
            console.log('🔑 authResult received:', JSON.stringify(authResult, null, 2));
            
            storeSession(authResult);
            
            const storedSession = localStorage.getItem('phishing_detector_session');
            console.log('📦 Session in localStorage:', storedSession);
            
            btnText.textContent = 'ACCESS GRANTED';
            btnIcon.textContent = '✓';
            btnIcon.style.display = 'inline-block';
            btnSpinner.classList.add('hidden');
            
            // Show device trust confirmation
            if (authResult.security?.device_trusted) {
                console.log('🔒 Device is now trusted');
            }
            
            console.log('✅ Session stored. Privilege level:', authResult.privileged ? 'ADMIN' : 'USER');
            console.log('🚀 Redirecting to index.html in 500ms...');
            
            setTimeout(() => {
                console.log('🚀 Executing redirect now...');
                window.location.href = 'index.html';
            }, 500);
        } else {
            console.log('❌ Authentication failed:', authResult.message);
            setLoading(false);
            showError(authResult.message || '⚠️ AUTHENTICATION FAILED');
            protectedPassword = '';
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
    console.log('[+] DOM loaded, initializing Amazon-level security login system...');
    
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
    
    // Log device fingerprint for debugging
    console.log('🔒 Device Fingerprint:', generateDeviceFingerprint());
    console.log('🔐 Amazon-Level Security Login System Ready');
});

