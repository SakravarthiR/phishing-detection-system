/**
 * Main Application Logic - Phishing URL Detector
 * Handles the URL checking form and parallax background effect
 * Optimized for low memory environments (Render 512MB)
 */

// Check authentication on page load
(function checkAuth() {
    try {
        const session = localStorage.getItem('phishing_detector_session');
        if (!session) {
            console.log('[AUTH] No session, redirecting to login');
            window.location.href = 'secure-auth-portal.html';
            return;
        }
        const parsed = JSON.parse(session);
        const now = new Date().getTime();
        if (now >= parsed.expiry) {
            console.log('[AUTH] Session expired, redirecting to login');
            localStorage.removeItem('phishing_detector_session');
            window.location.href = 'secure-auth-portal.html';
            return;
        }
        console.log('[AUTH] Session valid, user:', parsed.username);
    } catch (e) {
        console.error('[AUTH] Error checking session:', e);
        window.location.href = 'secure-auth-portal.html';
    }
})();


// Global unhandled promise rejection handler
window.addEventListener('unhandledrejection', event => {
    console.error('[UNHANDLED PROMISE REJECTION]', event.reason);
    console.error('Stack:', event.reason?.stack);
    // Prevent default error handling
    event.preventDefault();
});

// Global unhandled error handler
window.addEventListener('error', event => {
    console.error('[UNHANDLED ERROR]', event.error);
    if (event.error?.stack) {
        console.error('Stack:', event.error.stack);
    }
});

// Global event listener storage for cleanup
window._appListeners = {
    mousemove: [],
    mouseleave: [],
    click: [],
    keypress: [],
    keydown: [],
    scroll: [],
    touchstart: []
};

// Safe event listener registration with tracking
function registerEvent(target, event, handler, options = {}) {
    target.addEventListener(event, handler, options);
    if (window._appListeners[event]) {
        window._appListeners[event].push({target, handler, options});
    }
}

// Cleanup all event listeners on unload
function cleanupAllListeners() {
    Object.entries(window._appListeners).forEach(([event, listeners]) => {
        listeners.forEach(({target, handler, options}) => {
            try {
                target.removeEventListener(event, handler, options);
            } catch (e) {
                console.warn(`Failed to remove listener for ${event}:`, e);
            }
        });
    });
}

// Register cleanup on unload
window.addEventListener('beforeunload', cleanupAllListeners, {once: true});

// Throttle function for performance
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

// 3D Parallax Background Effect (throttled for performance)
const parallaxHandler = throttle((e) => {
    const parallaxBg = document.querySelector('.parallax-bg');
    if (!parallaxBg) return;
    
    const mouseX = e.clientX / window.innerWidth;
    const mouseY = e.clientY / window.innerHeight;
    
    const moveX = (mouseX - 0.5) * 20;
    const moveY = (mouseY - 0.5) * 20;
    
    parallaxBg.style.transform = `translate(${moveX}px, ${moveY}px) scale(1.02)`;
}, 50); // Throttle to 50ms

document.addEventListener('mousemove', parallaxHandler);

// Interactive Button Animation (3D tilt effect - throttled)
const buttonTiltHandler = throttle((e) => {
    document.querySelectorAll('.scanner-link-btn, .back-to-phishing-btn').forEach(btn => {
        const rect = btn.getBoundingClientRect();
        const btnCenterX = rect.left + rect.width / 2;
        const btnCenterY = rect.top + rect.height / 2;
        
        const distX = e.clientX - btnCenterX;
        const distY = e.clientY - btnCenterY;
        const distance = Math.sqrt(distX * distX + distY * distY);
        
        // Only apply effect when cursor is near button (within 150px)
        if (distance < 150) {
            const angle = Math.atan2(distY, distX);
            const mx = Math.cos(angle) * (150 - distance) / 150 * 15;
            const my = Math.sin(angle) * (150 - distance) / 150 * 15;
            
            btn.style.transform = `translate(${mx * 0.15}px, ${my * 0.3}px) rotate3d(${-my * 0.1}, ${mx * 0.1}, 0, 8deg)`;
            btn.classList.add('glow-active');
            
            const span = btn.querySelector('span');
            if (span) {
                span.style.transform = `translate(${mx * 0.025}px, ${my * 0.075}px)`;
            }
        } else {
            btn.style.transform = 'translate(0px, 0px) rotate3d(0, 0, 0, 0deg)';
            btn.classList.remove('glow-active');
            const span = btn.querySelector('span');
            if (span) {
                span.style.transform = 'translate(0px, 0px)';
            }
        }
    });
}, 50); // Throttle to 50ms

document.addEventListener('mousemove', buttonTiltHandler);

const mouseLeaveHandler = () => {
    document.querySelectorAll('.scanner-link-btn, .back-to-phishing-btn').forEach(btn => {
        btn.style.transform = 'translate(0px, 0px) rotate3d(0, 0, 0, 0deg)';
        btn.classList.remove('glow-active');
        const span = btn.querySelector('span');
        if (span) {
            span.style.transform = 'translate(0px, 0px)';
        }
    });
};

document.addEventListener('mouseleave', mouseLeaveHandler);

// Cursor Circle Tracking with mix-blend-mode effect (memory-optimized)
(() => {
    const cursorCircle = document.querySelector('.cursor-circle');
    if (!cursorCircle) return;
    
    const buttons = document.querySelectorAll('.scanner-link-btn, .back-to-phishing-btn');
    
    // Track cursor position (throttled)
    const cursorHandler = throttle((e) => {
        cursorCircle.style.left = (e.pageX - 20) + 'px';
        cursorCircle.style.top = (e.pageY - 20) + 'px';
    }, 30);
    
    document.addEventListener('mousemove', cursorHandler);
    
    // Add mix-blend-mode effect on button hover
    buttons.forEach(btn => {
        btn.addEventListener('mouseenter', function() {
            cursorCircle.classList.add('active');
            document.body.classList.add('mix-blend-active');
        }, {once: false, passive: true});
        
        btn.addEventListener('mouseleave', function() {
            cursorCircle.classList.remove('active');
            document.body.classList.remove('mix-blend-active');
        }, {once: false, passive: true});
    });
})();

// Configuration
// Detect environment and set API URL accordingly
function getAPIURL() {
    const hostname = window.location.hostname;
    
    // If running from file:// or localhost, use local backend
    if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '') {
        return 'http://localhost:5000';
    }
    
    // Production: same-origin (empty for relative URLs)
    return '';
}

const API_BASE_URL = getAPIURL();
const REQUEST_TIMEOUT = 60000; // 60 seconds for Render cold start
const USE_SECURE_API = true; // Use JWT authentication

// OPTIMIZED FOR 50 CONCURRENT USERS
// Connection pooling: reuse fetch connections
const FETCH_POOL_SIZE = 25; // 25 concurrent requests (2 workers x 25)
let activeRequests = 0;
const requestQueue = [];

// Keep-alive headers for connection reuse
const DEFAULT_FETCH_HEADERS = {
    'Connection': 'keep-alive',
    'Cache-Control': 'max-age=3600'
};

console.log('[+] API URL: ' + API_BASE_URL);
console.log('[+] Environment: ' + window.location.hostname);
console.log('[+] Connection pool size: ' + FETCH_POOL_SIZE);

// DOM Elements
let urlInput, checkBtn, btnText, btnLoader;
let resultsSection, resultsCard, errorSection;
let resultHeader, resultIcon, resultLabel, resultUrl;
let resultProbability, resultClassification;
let progressBar, resultReason, threatIndicators;
let errorMessage, dismissError;
let securityFeatures, structureFeatures, characterFeatures;
let domainFeatures, advancedFeatures;

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    console.log('[*] App loading...');
    init();
});

/**
 * Initialize the application
 */
function init() {
    console.log('[+] Initializing phishing detector...');
    
    // Get DOM elements
    urlInput = document.getElementById('urlInput');
    checkBtn = document.getElementById('checkBtn');
    btnText = document.getElementById('btnText');
    btnLoader = document.getElementById('btnLoader');
    
    console.log('[DEBUG] URL input element:', urlInput);
    console.log('[DEBUG] Current value:', urlInput ? urlInput.value : 'null');
    
    resultsSection = document.getElementById('resultsSection');
    resultsCard = document.getElementById('resultsCard');
    errorSection = document.getElementById('errorSection');
    
    resultHeader = document.getElementById('resultHeader');
    resultIcon = document.getElementById('resultIcon');
    resultLabel = document.querySelector('#resultLabel');
    resultUrl = document.getElementById('resultUrl');
    
    // Validate result display elements
    if (!resultsSection || !resultLabel || !resultUrl) {
        console.warn('[WARNING] Result display elements missing');
    }
    
    resultProbability = document.getElementById('resultProbability');
    resultClassification = document.getElementById('resultClassification');
    progressBar = document.getElementById('progressBar');
    resultReason = document.getElementById('resultReason');
    threatIndicators = document.getElementById('threatIndicators');
    
    errorMessage = document.getElementById('errorMessage');
    dismissError = document.getElementById('dismissError');
    
    securityFeatures = document.getElementById('securityFeatures');
    structureFeatures = document.getElementById('structureFeatures');
    characterFeatures = document.getElementById('characterFeatures');
    domainFeatures = document.getElementById('domainFeatures');
    advancedFeatures = document.getElementById('advancedFeatures');
    
    // Event listeners
    checkBtn.addEventListener('click', checkURL);
    urlInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') checkURL();
    });
    if (dismissError) {
        dismissError.addEventListener('click', hideError);
    }
    
    // Add logout button listener
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', logout);
    }
    
    console.log('[+] App initialized successfully');
}

// Session management variables - REMOVED TO FIX TEXT DISAPPEARING ISSUE
// The session auto-save/restore was interfering with user input

// Removed functions:
// - initializeSessionManagement()
// - saveSessionState()
// - restoreSessionState()
// - checkSessionExpiry()
// - updateSessionExpiry()
// - resetInactivityTimer()
// - clearSessionData()
// - showInactivityWarning()

/**
 * Get JWT token from localStorage
 * Matches discovery-engine.js pattern
 */
function getAuthToken() {
    const session = localStorage.getItem('phishing_detector_session');
    if (!session) {
        console.warn('⚠️ No session found');
        return null;
    }
    
    try {
        const sessionData = JSON.parse(session);
        if (sessionData.token && sessionData.expiry > Date.now()) {
            return sessionData.token;
        } else {
            console.warn('⚠️ Token expired');
            localStorage.removeItem('phishing_detector_session');
            return null;
        }
    } catch (e) {
        console.error('⚠️ Session parse error:', e);
        return null;
    }
}

/**
 * Check URL for phishing threats
 */
// Request batching for 50 concurrent users
async function queuedFetch(url, options = {}) {
    // Wait if pool is full
    while (activeRequests >= FETCH_POOL_SIZE) {
        await new Promise(resolve => setTimeout(resolve, 50));
    }
    
    activeRequests++;
    try {
        return await fetch(url, {
            ...options,
            headers: {
                ...DEFAULT_FETCH_HEADERS,
                ...(options.headers || {})
            }
        });
    } finally {
        activeRequests--;
    }
}

async function checkURL() {
    const url = urlInput.value.trim();
    
    // Validate input
    if (!url) {
        console.warn('⚠️ No URL provided');
        alert('Please enter a URL');
        return;
    }
    
    console.log('[*] Checking URL:', url);
    
    // Add protocol if missing
    let fullURL = url;
    if (!url.match(/^https?:\/\//)) {
        fullURL = 'https://' + url;
    }
    
    console.log('[>] Full URL:', fullURL);
    
    // Update UI
    hideError();
    hideResults();
    setLoading(true);
    showLoading();
    
    try {
        // Get auth token
        const token = getAuthToken();
        console.log('[AUTH] Token:', token ? 'Present' : 'Missing');
        
        // Call API
        console.log('[API] Calling checkPhishing()...');
        const result = await checkPhishing(fullURL);
        
        // Display results
        console.log('[+] Result received, displaying...');
        displayResults(result);
        
    } catch (error) {
        console.error('❌ Error in checkURL:', error.message);
        showError(error.message);
    } finally {
        setLoading(false);
        hideLoading();
    }
}

/**
 * Call phishing checker API
 */
async function checkPhishing(url) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT);
    
    try {
        const headers = {
            'Content-Type': 'application/json',
        };
        
        // Add JWT token if using secure API
        if (USE_SECURE_API) {
            const token = getAuthToken();
            if (token) {
                headers['Authorization'] = `Bearer ${token}`;
            }
        }
        
        // Use queuedFetch for connection pooling with 50 concurrent users
        const response = await queuedFetch(`${API_BASE_URL}/predict`, {
            method: 'POST',
            headers: headers,
            body: JSON.stringify({ url: url }),
            signal: controller.signal
        });
        
        clearTimeout(timeoutId);
        
        console.log('[RESPONSE] Status:', response.status, '| Active requests:', activeRequests);
        
        // If auth fails, redirect to login
        if (response.status === 401 && USE_SECURE_API) {
            console.warn('Token expired - back to login');
            window.location.href = 'secure-auth-portal.html';
            return null;  // Stop execution after redirect
        }
        
        if (!response.ok) {
            console.error('❌ API Error:', response.status, response.statusText);
            let errorMsg = `API Error ${response.status}: ${response.statusText}`;
            
            try {
                const errorData = await response.json();
                errorMsg = errorData.message || errorData.error || errorMsg;
                console.error('Error data from API:', errorData);
            } catch (e) {
                console.error('Could not parse JSON error response');
                // Try to get text response
                try {
                    const text = await response.text();
                    console.error('Error response text:', text);
                    if (text && text.length < 200) {
                        errorMsg = text;
                    }
                } catch (e2) {
                    // Couldn't read response
                }
            }
            
            throw new Error(errorMsg);
        }
        
        const data = await response.json();
        console.log('[+] API Response received:', data);
        return data;
        
    } catch (error) {
        console.error('Exception caught:', error.name, error.message);
        if (error.name === 'AbortError') {
            throw new Error('Request took too long - please try again');
        }
        // Handle network errors (Failed to fetch)
        if (error.message === 'Failed to fetch') {
            throw new Error('Network error - check your connection or try again in a moment');
        }
        throw error;
    }
}

/**
 * Display the phishing analysis results
 */
function displayResults(data) {
    // Set result status
    const isPhishing = data.label === 1 || data.prediction === 'phishing';
    const confidence = data.confidence_percent || Math.round((data.probability || 0) * 100);
    
    // Ensure confidence is between 0-100
    const displayConfidence = Math.max(0, Math.min(100, confidence));
    
    // Use professional risk assessment if available
    const riskData = data.risk_assessment || {};
    const riskLevel = riskData.risk_level || 'UNKNOWN';
    const riskCategory = riskData.risk_category || 'Analysis Pending';
    const riskDescription = riskData.description || 'Analysis completed';
    const riskDetails = riskData.details || '';
    const riskRecommendation = riskData.recommendation || '';
    const riskColor = riskData.color || '#666666';
    
    // Update card appearance with professional colors
    resultHeader.style.borderLeftColor = riskColor;
    resultIcon.textContent = riskData.risk_level && riskData.risk_level.includes('CRITICAL') ? '🚨' : 
                              riskData.risk_level && riskData.risk_level.includes('HIGH') ? '⚠️' :
                              riskData.risk_level && riskData.risk_level.includes('MEDIUM') ? '⚠️' :
                              riskData.risk_level && riskData.risk_level.includes('LOW') ? '✓' :
                              isPhishing ? '🚨' : '✅';
    
    // Professional title
    resultLabel.textContent = riskCategory || (isPhishing ? 'PHISHING' : 'LEGITIMATE');
    resultLabel.style.color = riskColor;
    resultsCard.style.borderColor = riskColor;
    
    // Set result details
    resultUrl.textContent = data.url;
    resultUrl.title = data.url;
    resultProbability.textContent = `${displayConfidence}%`;
    resultClassification.textContent = riskDescription;
    
    // Set progress bar with professional color and animation
    if (!progressBar) {
        console.error('[ERROR] progressBar element not found');
        return;
    }
    progressBar.style.width = `${displayConfidence}%`;
    progressBar.style.backgroundColor = riskColor;
    const progressText = progressBar.querySelector('.progress-text');
    if (progressText) {
        progressText.textContent = `${displayConfidence}%`;
    }
    
    // Set detailed reason
    resultReason.textContent = riskDetails || data.reason || 'Analysis completed. URL appears to be legitimate based on available intelligence.';
    
    // Clear threat indicators
    threatIndicators.innerHTML = '';
    
    // Create safe element instead of innerHTML for threat content
    const threatContainer = document.createElement('div');
    
    // THREAT LEVEL
    if (riskData.risk_level) {
        const threatSection = document.createElement('div');
        threatSection.className = 'threat-assessment-section';
        
        const threatHeader = document.createElement('div');
        threatHeader.className = 'threat-header';
        threatHeader.style.borderLeftColor = riskColor;
        threatHeader.style.backgroundColor = riskColor + '15';
        
        const threatTitle = document.createElement('div');
        threatTitle.className = 'threat-title';
        threatTitle.textContent = 'THREAT LEVEL:';
        
        const threatValue = document.createElement('div');
        threatValue.className = 'threat-value';
        threatValue.style.color = riskColor;
        threatValue.textContent = riskData.risk_level;
        
        const threatCategory = document.createElement('div');
        threatCategory.className = 'threat-category';
        threatCategory.textContent = riskData.risk_category;
        
        threatHeader.appendChild(threatTitle);
        threatHeader.appendChild(threatValue);
        threatHeader.appendChild(threatCategory);
        threatSection.appendChild(threatHeader);
        threatContainer.appendChild(threatSection);
    }
    
    // RECOMMENDATION
    if (riskRecommendation) {
        const recSection = document.createElement('div');
        recSection.className = 'recommendation-section';
        recSection.style.borderLeftColor = riskColor;
        recSection.style.backgroundColor = riskColor + '15';
        
        const recTitle = document.createElement('div');
        recTitle.className = 'section-title';
        recTitle.style.color = riskColor;
        recTitle.textContent = 'RECOMMENDATION:';
        
        const recContent = document.createElement('div');
        recContent.className = 'section-content';
        recContent.textContent = riskRecommendation;
        
        recSection.appendChild(recTitle);
        recSection.appendChild(recContent);
        threatContainer.appendChild(recSection);
    }
    
    // SUGGESTED ACTIONS
    if (riskData.actions && Array.isArray(riskData.actions) && riskData.actions.length > 0) {
        const actionsSection = document.createElement('div');
        actionsSection.className = 'actions-section';
        actionsSection.style.borderLeftColor = riskColor;
        actionsSection.style.backgroundColor = riskColor + '15';
        
        const actionsTitle = document.createElement('div');
        actionsTitle.className = 'section-title';
        actionsTitle.style.color = riskColor;
        actionsTitle.textContent = 'SUGGESTED ACTIONS:';
        
        const actionsList = document.createElement('ul');
        actionsList.className = 'actions-list';
        riskData.actions.forEach(action => {
            const li = document.createElement('li');
            li.textContent = action;
            actionsList.appendChild(li);
        });
        
        actionsSection.appendChild(actionsTitle);
        actionsSection.appendChild(actionsList);
        threatContainer.appendChild(actionsSection);
    }
    
    // SERVER STATUS
    if (data.website_status) {
        const isReachable = data.website_status.is_reachable || data.website_status.is_live;
        const statusCode = data.website_status.status_code || '---';
        const serverStatus = isReachable ? 'Online' : 'Offline';
        
        const statusSection = document.createElement('div');
        statusSection.className = 'server-status-section';
        statusSection.style.borderLeftColor = '#0099ff';
        statusSection.style.backgroundColor = '#0099ff15';
        
        const statusLabel = document.createElement('span');
        statusLabel.className = 'status-label';
        statusLabel.textContent = 'Server Status:';
        
        const statusValue = document.createElement('span');
        statusValue.className = 'status-value';
        statusValue.textContent = serverStatus + ' (HTTP ' + statusCode + ')';
        
        statusSection.appendChild(statusLabel);
        statusSection.appendChild(statusValue);
        threatContainer.appendChild(statusSection);
    }
    
    // CONFIDENCE LEVEL
    const confidenceSection = document.createElement('div');
    confidenceSection.className = 'confidence-section';
    confidenceSection.style.borderLeftColor = riskColor;
    confidenceSection.style.backgroundColor = riskColor + '15';
    
    const confLabel = document.createElement('span');
    confLabel.className = 'confidence-label';   
    confLabel.textContent = 'Confidence Level:';
    
    const confValue = document.createElement('span');
    confValue.className = 'confidence-value';
    confValue.style.color = riskColor;
    confValue.textContent = riskData.confidence_level || (displayConfidence > 80 ? 'HIGH' : displayConfidence > 50 ? 'MEDIUM' : 'LOW');
    
    confidenceSection.appendChild(confLabel);
    confidenceSection.appendChild(confValue);
    threatContainer.appendChild(confidenceSection);
    
    threatIndicators.appendChild(threatContainer);
    
    // Add threat detail tables for advanced threat detection data
    const threatDetails = document.createElement('div');
    threatDetails.className = 'threat-details-tables';
    
    // Threat Indicators
    if (data.features && data.features.threat_indicators && Array.isArray(data.features.threat_indicators) && data.features.threat_indicators.length > 0) {
        const indicatorsSection = document.createElement('div');
        indicatorsSection.className = 'threat-table-section';
        
        const title = document.createElement('h4');
        title.className = 'threat-table-title';
        title.textContent = 'Threat Indicators';
        indicatorsSection.appendChild(title);
        
        const table = document.createElement('table');
        table.className = 'threat-table';
        const tbody = document.createElement('tbody');
        
        data.features.threat_indicators.forEach(indicator => {
            const row = document.createElement('tr');
            const cell = document.createElement('td');
            cell.className = 'indicator-item';
            cell.textContent = indicator;
            row.appendChild(cell);
            tbody.appendChild(row);
        });
        
        table.appendChild(tbody);
        indicatorsSection.appendChild(table);
        threatDetails.appendChild(indicatorsSection);
    }
    
    // Risk Indicators
    if (data.features && data.features.threat_risk_indicators && Array.isArray(data.features.threat_risk_indicators) && data.features.threat_risk_indicators.length > 0) {
        const riskSection = document.createElement('div');
        riskSection.className = 'threat-table-section';
        
        const title = document.createElement('h4');
        title.className = 'threat-table-title';
        title.textContent = 'Risk Indicators';
        riskSection.appendChild(title);
        
        const table = document.createElement('table');
        table.className = 'threat-table';
        const tbody = document.createElement('tbody');
        
        data.features.threat_risk_indicators.forEach(indicator => {
            const row = document.createElement('tr');
            const cell = document.createElement('td');
            cell.className = 'indicator-item';
            cell.textContent = indicator;
            row.appendChild(cell);
            tbody.appendChild(row);
        });
        
        table.appendChild(tbody);
        riskSection.appendChild(table);
        threatDetails.appendChild(riskSection);
    }
    
    // Threat Scan Score
    if (data.features && data.features.threat_scan_score !== undefined && data.features.threat_scan_score !== null) {
        const scoreSection = document.createElement('div');
        scoreSection.className = 'threat-table-section';
        
        const title = document.createElement('h4');
        title.className = 'threat-table-title';
        title.textContent = 'Threat Scan Score';
        scoreSection.appendChild(title);
        
        const table = document.createElement('table');
        table.className = 'threat-table';
        const tbody = document.createElement('tbody');
        
        const row = document.createElement('tr');
        const labelCell = document.createElement('td');
        labelCell.className = 'score-label';
        labelCell.textContent = 'Overall Risk Score:';
        const valueCell = document.createElement('td');
        valueCell.className = 'score-value';
        valueCell.textContent = (data.features.threat_scan_score * 100).toFixed(1) + '%';
        
        row.appendChild(labelCell);
        row.appendChild(valueCell);
        tbody.appendChild(row);
        
        table.appendChild(tbody);
        scoreSection.appendChild(table);
        threatDetails.appendChild(scoreSection);
    }
    
    // Technologies Detected
    if (data.features && data.features.threat_technologies && Array.isArray(data.features.threat_technologies) && data.features.threat_technologies.length > 0) {
        const techSection = document.createElement('div');
        techSection.className = 'threat-table-section';
        
        const title = document.createElement('h4');
        title.className = 'threat-table-title';
        title.textContent = 'Technologies Detected';
        techSection.appendChild(title);
        
        const table = document.createElement('table');
        table.className = 'threat-table';
        const tbody = document.createElement('tbody');
        
        data.features.threat_technologies.forEach(tech => {
            const row = document.createElement('tr');
            const cell = document.createElement('td');
            cell.className = 'tech-item';
            cell.textContent = tech;
            row.appendChild(cell);
            tbody.appendChild(row);
        });
        
        table.appendChild(tbody);
        techSection.appendChild(table);
        threatDetails.appendChild(techSection);
    }
    
    // HTTP Headers
    if (data.features && data.features.threat_http_headers && typeof data.features.threat_http_headers === 'object' && Object.keys(data.features.threat_http_headers).length > 0) {
        const headersSection = document.createElement('div');
        headersSection.className = 'threat-table-section';
        
        const title = document.createElement('h4');
        title.className = 'threat-table-title';
        title.textContent = 'HTTP Headers';
        headersSection.appendChild(title);
        
        const table = document.createElement('table');
        table.className = 'threat-table';
        
        const thead = document.createElement('thead');
        const headerRow = document.createElement('tr');
        const th1 = document.createElement('th');
        th1.textContent = 'Header';
        const th2 = document.createElement('th');
        th2.textContent = 'Value';
        headerRow.appendChild(th1);
        headerRow.appendChild(th2);
        thead.appendChild(headerRow);
        table.appendChild(thead);
        
        const tbody = document.createElement('tbody');
        for (const [key, value] of Object.entries(data.features.threat_http_headers)) {
            const row = document.createElement('tr');
            const keyCell = document.createElement('td');
            keyCell.className = 'header-key';
            keyCell.textContent = key;
            const valueCell = document.createElement('td');
            valueCell.className = 'header-value';
            valueCell.textContent = String(value).substring(0, 50);
            row.appendChild(keyCell);
            row.appendChild(valueCell);
            tbody.appendChild(row);
        }
        
        table.appendChild(tbody);
        headersSection.appendChild(table);
        threatDetails.appendChild(headersSection);
    }
    
    // SSL Certificate Info
    if (data.features && data.features.threat_ssl_info && typeof data.features.threat_ssl_info === 'object' && Object.keys(data.features.threat_ssl_info).length > 0) {
        const sslSection = document.createElement('div');
        sslSection.className = 'threat-table-section';
        
        const title = document.createElement('h4');
        title.className = 'threat-table-title';
        title.textContent = 'SSL/TLS Certificate';
        sslSection.appendChild(title);
        
        const table = document.createElement('table');
        table.className = 'threat-table';
        
        const thead = document.createElement('thead');
        const headerRow = document.createElement('tr');
        const th1 = document.createElement('th');
        th1.textContent = 'Property';
        const th2 = document.createElement('th');
        th2.textContent = 'Value';
        headerRow.appendChild(th1);
        headerRow.appendChild(th2);
        thead.appendChild(headerRow);
        table.appendChild(thead);
        
        const tbody = document.createElement('tbody');
        for (const [key, value] of Object.entries(data.features.threat_ssl_info)) {
            const row = document.createElement('tr');
            const keyCell = document.createElement('td');
            keyCell.className = 'ssl-key';
            keyCell.textContent = key;
            const valueCell = document.createElement('td');
            valueCell.className = 'ssl-value';
            valueCell.textContent = String(value).substring(0, 50);
            row.appendChild(keyCell);
            row.appendChild(valueCell);
            tbody.appendChild(row);
        }
        
        table.appendChild(tbody);
        sslSection.appendChild(table);
        threatDetails.appendChild(sslSection);
    }
    
    // Server Information
    if (data.features && data.features.threat_server_info && typeof data.features.threat_server_info === 'object' && Object.keys(data.features.threat_server_info).length > 0) {
        const serverSection = document.createElement('div');
        serverSection.className = 'threat-table-section';
        
        const title = document.createElement('h4');
        title.className = 'threat-table-title';
        title.textContent = 'Server Information';
        serverSection.appendChild(title);
        
        const table = document.createElement('table');
        table.className = 'threat-table';
        
        const thead = document.createElement('thead');
        const headerRow = document.createElement('tr');
        const th1 = document.createElement('th');
        th1.textContent = 'Property';
        const th2 = document.createElement('th');
        th2.textContent = 'Value';
        headerRow.appendChild(th1);
        headerRow.appendChild(th2);
        thead.appendChild(headerRow);
        table.appendChild(thead);
        
        const tbody = document.createElement('tbody');
        for (const [key, value] of Object.entries(data.features.threat_server_info)) {
            const row = document.createElement('tr');
            const keyCell = document.createElement('td');
            keyCell.className = 'server-key';
            keyCell.textContent = key;
            const valueCell = document.createElement('td');
            valueCell.className = 'server-value';
            valueCell.textContent = String(value).substring(0, 50);
            row.appendChild(keyCell);
            row.appendChild(valueCell);
            tbody.appendChild(row);
        }
        
        table.appendChild(tbody);
        serverSection.appendChild(table);
        threatDetails.appendChild(serverSection);
    }
    
    // Vulnerabilities (if any)
    if (data.features && data.features.threat_vulnerabilities && Array.isArray(data.features.threat_vulnerabilities) && data.features.threat_vulnerabilities.length > 0) {
        const vulnSection = document.createElement('div');
        vulnSection.className = 'threat-table-section threat-vulnerability-section';
        
        const title = document.createElement('h4');
        title.className = 'threat-table-title';
        title.textContent = 'Vulnerabilities Detected';
        vulnSection.appendChild(title);
        
        const table = document.createElement('table');
        table.className = 'threat-table';
        const tbody = document.createElement('tbody');
        
        data.features.threat_vulnerabilities.forEach(vuln => {
            const row = document.createElement('tr');
            const cell = document.createElement('td');
            cell.className = 'vulnerability-item';
            cell.textContent = vuln;
            row.appendChild(cell);
            tbody.appendChild(row);
        });
        
        table.appendChild(tbody);
        vulnSection.appendChild(table);
        threatDetails.appendChild(vulnSection);
    }
    
    // Append threat details tables if any content was added
    if (threatDetails.innerHTML.trim()) {
        threatIndicators.appendChild(threatDetails);
    }
    
    // Add PhishTank badge if verified (separate)
    if (data.phishtank_verified && data.phishtank_data) {
        const badge = document.createElement('div');
        badge.className = 'phishtank-badge';
        badge.style.borderLeftColor = '#ff0000';
        badge.style.backgroundColor = '#ff000015';
        
        const badgeStrong = document.createElement('strong');
        badgeStrong.style.color = '#ff0000';
        badgeStrong.textContent = '[VERIFIED PHISHING]';
        
        const badgeId = document.createElement('span');
        badgeId.textContent = ' ID: ' + (data.phishtank_data.phish_id || 'N/A');
        
        badge.appendChild(badgeStrong);
        badge.appendChild(badgeId);
        threatIndicators.appendChild(badge);
    }
    
    // Display features
    if (data.features && Object.keys(data.features).length > 0) {
        displayFeatures(data.features);
    }
    
    // Add to history
    addToHistory(data.url, data.label || (data.prediction === 'phishing' ? 1 : 0), data.probability || 0);
    
    showResults();
}

/**
 * Display advanced feature analysis (37 ML features)
 */
function displayFeatures(features) {
    // Clear previous features
    securityFeatures.innerHTML = '';
    structureFeatures.innerHTML = '';
    characterFeatures.innerHTML = '';
    domainFeatures.innerHTML = '';
    advancedFeatures.innerHTML = '';
    
    if (!features || Object.keys(features).length === 0) {
        const p = document.createElement('p');
        p.textContent = 'No detailed features available';
        advancedFeatures.appendChild(p);
        return;
    }
    
    // Categorize and display features with better formatting
    for (const [key, value] of Object.entries(features)) {
        // Skip threat-related features - they have their own dedicated tables
        if (key.startsWith('threat_') || key === 'content_score' || key.startsWith('content_')) {
            continue;
        }
        
        const featureEl = document.createElement('div');
        featureEl.className = 'feature-item';
        
        // Format key name
        const formattedKey = formatFeatureName(key);
        
        // Format value with type-specific handling
        let formattedValue = formatFeatureValue(value);
        
        const keySpan = document.createElement('span');
        keySpan.className = 'feature-name';
        keySpan.textContent = formattedKey;
        
        const valueSpan = document.createElement('span');
        valueSpan.className = 'feature-value';
        valueSpan.textContent = formattedValue;
        
        featureEl.appendChild(keySpan);
        featureEl.appendChild(valueSpan);
        
        // Categorize by key name
        const lowerKey = key.toLowerCase();
        
        if (lowerKey.includes('phishing') || lowerKey.includes('suspicious') || lowerKey.includes('malicious') || 
            lowerKey.includes('spam') || lowerKey.includes('fraud')) {
            securityFeatures.appendChild(featureEl);
        } else if (lowerKey.includes('url') || lowerKey.includes('scheme') || lowerKey.includes('port') || 
                   lowerKey.includes('path') || lowerKey.includes('query') || lowerKey.includes('protocol')) {
            structureFeatures.appendChild(featureEl);
        } else if (lowerKey.includes('entropy') || lowerKey.includes('char') || lowerKey.includes('length') || 
                   lowerKey.includes('count') || lowerKey.includes('distribution')) {
            characterFeatures.appendChild(featureEl);
        } else if (lowerKey.includes('domain') || lowerKey.includes('ip') || lowerKey.includes('dns') || 
                   lowerKey.includes('host') || lowerKey.includes('subdomain')) {
            domainFeatures.appendChild(featureEl);
        } else {
            advancedFeatures.appendChild(featureEl);
        }
    }
}

/**
 * Format feature name for display
 */
function formatFeatureName(name) {
    return name
        .replace(/_/g, ' ')
        .replace(/([A-Z])/g, ' $1')
        .replace(/\b\w/g, char => char.toUpperCase())
        .trim();
}

/**
 * Format feature value for display
 * Shows actual numeric values, not YES/NO conversions
 */
function formatFeatureValue(value) {
    if (typeof value === 'boolean') {
        return value ? 'Yes' : 'No';
    }
    if (typeof value === 'number') {
        // If it's a decimal between 0-1 (actual probability), show as percentage
        if (value > 0 && value < 1 && value !== Math.floor(value)) {
            return (value * 100).toFixed(1) + '%';
        }
        // For all other numbers (including 0, 1, 2, etc), show the actual value
        // Only show decimals if needed
        if (Number.isInteger(value) || value === Math.floor(value)) {
            return value.toFixed(0);
        }
        return value.toFixed(2);
    }
    if (Array.isArray(value)) {
        return value.join(', ') || '(None)';
    }
    return String(value);
}

/**
 * Display subdomain information
 */
function displaySubdomainInfo(subdomainInfo) {
    if (!subdomainInfo || !Array.isArray(subdomainInfo)) return;
    
    advancedSubdomainTableBody.innerHTML = '';
    
    subdomainInfo.forEach(subdomain => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${subdomain.name || '--'}</td>
            <td>${subdomain.ip || '--'}</td>
            <td>${subdomain.cloudflare ? 'Yes' : 'No'}</td>
        `;
        advancedSubdomainTableBody.appendChild(row);
    });
}

/**
 * UI Helper Functions
 */
function showLoading() {
    checkBtn.disabled = true;
    btnText.style.display = 'none';
    btnLoader.classList.remove('hidden');
}

function hideLoading() {
    checkBtn.disabled = false;
    btnText.style.display = 'inline';
    btnLoader.classList.add('hidden');
}

function showResults() {
    resultsSection.classList.remove('hidden');
    // Session state saving removed - was causing input field issues
}

function hideResults() {
    resultsSection.classList.add('hidden');
}

function showError(message) {
    if (errorMessage) {
        errorMessage.textContent = message;
    }
    if (errorSection) {
        errorSection.classList.remove('hidden');
    }
}

function hideError() {
    if (errorSection) {
        errorSection.classList.add('hidden');
    }
}

/**
 * Helper functions
 */
function setLoading(loading) {
    if (loading) {
        checkBtn.disabled = true;
    } else {
        checkBtn.disabled = false;
    }
}

/**
 * Scan History Management (optimized for low memory)
 */
const HISTORY_KEY = 'phishing_scan_history';
const MAX_HISTORY_ITEMS = 10; // Reduced from 20 to save memory

function addToHistory(url, label, confidence) {
    try {
        // Get existing history
        let history = JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
        
        // Check if this URL already exists in history
        const duplicateIndex = history.findIndex(item => item.fullUrl === url);
        
        // If duplicate exists, remove it (we'll add it again at the top)
        if (duplicateIndex !== -1) {
            history.splice(duplicateIndex, 1);
        }
        
        // Add new entry at the beginning (most recent first)
        const entry = {
            url: url.substring(0, 25) + (url.length > 25 ? '...' : ''),
            type: label === 1 ? 'Phishing' : 'Legit',
            confidence: Math.round(confidence * 100),
            timestamp: new Date().toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'}),
            fullUrl: url,
            isPhishing: label === 1,
            predictionData: {
                label: label,
                probability: confidence,
                prediction: label === 1 ? 'phishing' : 'legitimate'
            }
        };
        
        history.unshift(entry);
        
        // Keep only last 10 items to save memory
        history = history.slice(0, MAX_HISTORY_ITEMS);
        
        // Save to localStorage with size check
        const historyJson = JSON.stringify(history);
        if (historyJson.length > 50000) {
            // If history is too large, truncate to 5 items
            history = history.slice(0, 5);
        }
        
        localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
        localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
        
        // Update display
        updateHistoryDisplay();
        
    } catch (e) {
        console.error('Error adding to history:', e);
    }
}

function updateHistoryDisplay() {
    try {
        const history = JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
        const historyTableBody = document.getElementById('historyTableBody');
        const historyTableContainer = document.querySelector('.history-table-container');
        const historySidebar = document.querySelector('.scan-history-sidebar-main');
        
        if (!historyTableBody) return;
        
        // Get history list and empty state
        const historyList = document.getElementById('historyList');
        const emptyState = historyList ? historyList.querySelector('.history-empty') : null;
        
        if (history.length === 0) {
            historyTableBody.innerHTML = '';
            
            // Hide entire sidebar when no history
            if (historySidebar) {
                historySidebar.style.display = 'none';
            }
            return;
        }
        
        // Show sidebar and table container when history exists
        if (historySidebar) {
            historySidebar.style.display = 'block';
        }
        if (emptyState) {
            emptyState.style.display = 'none';
        }
        if (historyTableContainer) {
            historyTableContainer.style.display = 'block';
        }
        
        // Clear table
        historyTableBody.innerHTML = '';
        
        // Build table rows safely
        history.forEach((item, index) => {
            const row = document.createElement('tr');
            row.title = 'Click to view results: ' + item.fullUrl;
            
            const urlCell = document.createElement('td');
            urlCell.className = 'history-url';
            urlCell.textContent = item.url;
            urlCell.style.cursor = 'pointer';
            urlCell.onclick = function() { displayHistoryResult(index); };
            
            const deleteCell = document.createElement('td');
            deleteCell.className = 'history-delete-btn';
            deleteCell.textContent = '✕';
            deleteCell.title = 'Delete this scan';
            deleteCell.style.cursor = 'pointer';
            deleteCell.onclick = function() { deleteHistoryItem(index); };
            
            row.appendChild(urlCell);
            row.appendChild(deleteCell);
            historyTableBody.appendChild(row);
        });
        
    } catch (e) {
        console.error('Error updating history display:', e);
    }
}

function displayHistoryResult(index) {
    try {
        const history = JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
        const item = history[index];
        
        if (!item) return;
        
        console.log('[+] Rescanning URL from history:', item.fullUrl);
        
        // Set the URL in input field and trigger a fresh scan
        const urlInput = document.getElementById('urlInput');
        if (urlInput) {
            urlInput.value = item.fullUrl;
            // Trigger the check function to rescan
            checkURL();
        }
        
    } catch (e) {
        console.error('Error rescanning history result:', e);
    }
}

function deleteHistoryItem(index) {
    try {
        let history = JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
        const item = history[index];
        
        if (confirm('Delete this scan from history?\n\n' + item.fullUrl)) {
            history.splice(index, 1);
            localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
            updateHistoryDisplay();
            console.log('[+] History item deleted: ' + item.fullUrl);
        }
        
    } catch (e) {
        console.error('Error deleting history item:', e);
    }
}

function clearHistory() {
    if (confirm('Clear all scan history?')) {
        try {
            // Add animation to button
            const clearBtn = document.getElementById('clearHistoryBtn');
            if (clearBtn && !clearBtn.classList.contains('delete')) {
                clearBtn.classList.add('delete');
            }
            
            // Clear history after animation starts
            setTimeout(() => {
                localStorage.removeItem(HISTORY_KEY);
                updateHistoryDisplay();
                
                console.log('[+] History cleared');
            }, 500);
            
            // Remove animation class after animation completes
            setTimeout(() => {
                if (clearBtn && clearBtn.classList.contains('delete')) {
                    clearBtn.classList.remove('delete');
                }
            }, 3200);
            
        } catch (e) {
            console.error('Error clearing history:', e);
        }
    }
}

// Initialize history on page load
document.addEventListener('DOMContentLoaded', () => {
    updateHistoryDisplay();
    
    // Add clear history button listener
    const clearBtn = document.getElementById('clearHistoryBtn');
    if (clearBtn) {
        clearBtn.addEventListener('click', clearHistory);
    }
});

/**
 * Logout function - Clear session and redirect
 */
function logout() {
    try {
        // Clear all phishing detector session data
        localStorage.removeItem('phishing_detector_session');
        localStorage.removeItem(SESSION_EXPIRY_KEY);
        localStorage.removeItem(SESSION_STATE_KEY);
        
        // Clear session storage completely
        sessionStorage.clear();
        
        // Redirect to landing page
        window.location.href = 'index.html';
    } catch (e) {
        console.error('Logout error:', e);
        // Force redirect anyway
        window.location.href = 'index.html';
    }
}

console.log('[+] App.js loaded and ready');
