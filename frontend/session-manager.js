/**
 * Enhanced Authentication & IP-Based Session Management
 * Enforces strict IP and device binding for security
 */

const SESSION_KEY = 'phishing_detector_session';
const SESSION_ID_KEY = 'phishing_detector_session_id';
const DEVICE_IP_KEY = 'phishing_detector_device_ip';

// Get API URL
function getAPIURL() {
    const hostname = window.location.hostname;
    
    // Local development or file:// access
    if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '') {
        return 'http://localhost:5000';
    }
    
    // Production: same-origin
    return '';
}

/**
 * Store session with IP binding and CSRF protection
 */
function storeSession(sessionData) {
    const session = {
        token: sessionData.token,
        session_id: sessionData.session_id,
        csrf_token: sessionData.csrf_token,
        username: sessionData.username,
        expires_in: sessionData.expires_in,
        expiry: new Date().getTime() + (sessionData.expires_in * 1000),
        privileged: sessionData.privileged || false,
        device_name: sessionData.device_name || 'Unknown Device',
        created_at: new Date().toISOString()
    };
    
    localStorage.setItem(SESSION_KEY, JSON.stringify(session));
    localStorage.setItem(SESSION_ID_KEY, sessionData.session_id);
    
    // Store CSRF token for form submissions
    if (sessionData.csrf_token) {
        localStorage.setItem('phishing_detector_csrf_token', sessionData.csrf_token);
    }
    
    console.log('[+] Secure session stored:', {
        username: session.username,
        privileged: session.privileged,
        device: session.device_name,
        csrf_protection: !!session.csrf_token,
        expires: new Date(session.expiry).toLocaleString()
    });
}

/**
 * Get current session
 */
function getSession() {
    try {
        const session = localStorage.getItem(SESSION_KEY);
        if (!session) return null;
        
        const parsed = JSON.parse(session);
        
        // Validate session structure
        if (!parsed || typeof parsed !== 'object') {
            console.warn('[!] Invalid session data structure');
            clearSession();
            return null;
        }
        
        return parsed;
    } catch (e) {
        console.error('[!] Error reading session:', e);
        clearSession();
        return null;
    }
}

/**
 * Get session ID for API calls
 */
function getSessionId() {
    try {
        const sessionId = localStorage.getItem(SESSION_ID_KEY);
        if (sessionId && typeof sessionId === 'string' && sessionId.length > 0) {
            return sessionId;
        }
        return null;
    } catch (e) {
        console.error('[!] Error reading session ID:', e);
        return null;
    }
}

/**
 * Check if session is still valid and not expired
 */
function isSessionValid() {
    const session = getSession();
    
    if (!session) {
        console.warn('[!] No session found');
        return false;
    }
    
    const currentTime = new Date().getTime();
    
    // Check expiration
    if (currentTime >= session.expiry) {
        console.warn('[!] Session expired');
        clearSession();
        return false;
    }
    
    return true;
}

/**
 * Check if session is privileged
 */
function isPrivileged() {
    const session = getSession();
    return session ? session.privileged : false;
}

/**
 * Get device name from session
 */
function getDeviceName() {
    const session = getSession();
    return session ? session.device_name : 'Unknown Device';
}

/**
 * Clear session securely and cleanup resources
 */
function clearSession() {
    try {
        localStorage.removeItem(SESSION_KEY);
        localStorage.removeItem(SESSION_ID_KEY);
        localStorage.removeItem(DEVICE_IP_KEY);
        localStorage.removeItem('phishing_detector_csrf_token');
        localStorage.removeItem('phishing_detector_state');
        localStorage.removeItem('phishing_detector_session_expiry');
        console.log('[+] Session cleared securely');
    } catch (e) {
        console.warn('Error clearing session:', e);
    }
}

/**
 * Validate request origin for CORS security
 */
function validateOrigin() {
    const expectedOrigins = [
        'http://localhost:3000',
        'http://127.0.0.1:3000',
        'http://127.0.0.1:5000',
        'http://localhost:5000',
        'https://phishing-detection-system-1.onrender.com'
    ];
    
    const currentOrigin = window.location.origin;
    
    if (!expectedOrigins.includes(currentOrigin)) {
        console.error('[!] ORIGIN VALIDATION FAILED:', currentOrigin);
        console.error('[!] Expected one of:', expectedOrigins);
        return false;
    }
    
    return true;
}

/**
 * Prepare Authorization headers for API calls with CSRF protection
 */
function getAuthHeaders() {
    const session = getSession();
    const sessionId = getSessionId();
    
    if (!session || !sessionId) {
        return null;
    }
    
    const headers = {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${sessionId}`,
        'X-Session-ID': sessionId,
        'Origin': window.location.origin
    };
    
    // Add CSRF token if available
    const csrfToken = localStorage.getItem('phishing_detector_csrf_token');
    if (csrfToken && typeof csrfToken === 'string' && csrfToken.length > 0) {
        headers['X-CSRF-Token'] = csrfToken;
    }
    
    return headers;
}

/**
 * Check authentication and redirect if needed
 */
function checkAuthentication() {
    // If this is the login page, don't redirect
    if (window.location.pathname.includes('secure-auth-portal.html') || 
        window.location.pathname.includes('auth-secure.html') ||
        window.location.pathname.includes('login')) {
        return true;
    }
    
    if (!isSessionValid()) {
        // Session is invalid - redirect to login
        console.warn('[!] Session invalid - redirecting to login...');
        window.location.href = '/secure-auth-portal.html?reason=session_expired';
        return false;
    }
    
    console.log('[+] Session valid for user:', getSession().username);
    return true;
}

/**
 * Make authenticated API call with session handling and origin validation
 */
async function authenticatedFetch(url, options = {}) {
    // Validate origin security
    if (!validateOrigin()) {
        console.error('[!] Invalid origin - request blocked');
        throw new Error('Origin validation failed');
    }
    
    const headers = getAuthHeaders();
    
    if (!headers) {
        console.error('[!] No valid session for API call');
        window.location.href = '/secure-auth-portal.html?reason=no_session';
        return null;
    }
    
    // Merge with provided headers
    const finalOptions = {
        ...options,
        method: options.method || 'GET',
        credentials: 'same-origin',  // Important: only send cookies for same-origin requests
        headers: {
            ...headers,
            ...(options.headers || {})
        }
    };
    
    try {
        const response = await fetch(url, finalOptions);
        
        // Validate response is defined
        if (!response) {
            throw new Error('Fetch returned null response');
        }
        
        // If unauthorized, session might be invalid
        if (response.status === 401) {
            console.warn('[!] Unauthorized - session may be invalid');
            clearSession();
            window.location.href = '/secure-auth-portal.html?reason=unauthorized';
            return null;
        }
        
        // If forbidden, user doesn't have permission
        if (response.status === 403) {
            console.warn('[!] Forbidden - access denied');
            throw new Error('Access denied (403)');
        }
        
        return response;
    } catch (error) {
        console.error('[!] API call failed:', error);
        throw error;
    }
}

/**
 * Handle privilege check for protected operations
 */
async function requirePrivilege(operation = 'Privileged Operation') {
    if (!isPrivileged()) {
        const message = `${operation} requires privileged access from an authorized device.
        
Your device (${getDeviceName()}) is not whitelisted for privileged operations.
Contact your administrator to add this device to the whitelist.`;
        
        alert(message);
        console.warn('[!] Privilege required but device not whitelisted');
        return false;
    }
    
    return true;
}

// Run authentication check on page load
document.addEventListener('DOMContentLoaded', checkAuthentication);
