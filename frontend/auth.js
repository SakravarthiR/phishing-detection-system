/**
 * Authentication Check
 * Add this to protect pages - checks if user is logged in
 */

const SESSION_KEY = 'phishing_detector_session';

function checkAuthentication() {
    const session = localStorage.getItem(SESSION_KEY);
    
    if (!session) {
        // No session found, redirect to login
        window.location.href = 'login.html';
        return false;
    }
    
    try {
        const sessionData = JSON.parse(session);
        const currentTime = new Date().getTime();
        
        // Check if session is still valid
        if (currentTime >= sessionData.expiresAt) {
            // Session expired
            localStorage.removeItem(SESSION_KEY);
            window.location.href = 'login.html';
            return false;
        }
        
        // Session is valid
        return true;
    } catch (e) {
        // Invalid session data
        localStorage.removeItem(SESSION_KEY);
        window.location.href = 'login.html';
        return false;
    }
}

// Logout function
function logout() {
    localStorage.removeItem(SESSION_KEY);
    window.location.href = 'login.html';
}

// Run authentication check
checkAuthentication();
