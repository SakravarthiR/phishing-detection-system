/**
 * main app logic - phishing URL detector
 * handles URL checking form and 3D parallax background
 * matches discovery-engine.js pattern
 */

// 3D parallax background stuff
document.addEventListener('mousemove', (e) => {
    const parallaxBg = document.querySelector('.parallax-bg');
    if (!parallaxBg) return;
    
    const mouseX = e.clientX / window.innerWidth;
    const mouseY = e.clientY / window.innerHeight;
    
    const moveX = (mouseX - 0.5) * 20;
    const moveY = (mouseY - 0.5) * 20;
    
    parallaxBg.style.transform = `translate(${moveX}px, ${moveY}px) scale(1.02)`;
});

// config stuff
const API_BASE_URL = 'https://phishing-detection-system-1.onrender.com';
const REQUEST_TIMEOUT = 30000; // 30 seconds
const USE_SECURE_API = true; // use JWT auth

// DOM stuff
let urlInput, checkBtn, btnText, btnSpinner;
let resultsSection, resultsCard, errorSection;
let resultHeader, resultIcon, resultLabel, resultUrl;
let resultProbability, resultClassification;
let progressBar, resultReason, threatIndicators;
let errorMessage, dismissError;
let securityFeatures, structureFeatures, characterFeatures;
let domainFeatures, advancedFeatures;

// run when page loads
document.addEventListener('DOMContentLoaded', () => {
    console.log('app loading...');
    init();
});

/**
 * initialize the app
 */
function init() {
    console.log('initializing phishing detector...');
    
    // get DOM elements
    urlInput = document.getElementById('urlInput');
    checkBtn = document.getElementById('checkBtn');
    btnText = document.getElementById('btnText');
    btnSpinner = document.getElementById('btnSpinner');
    
    resultsSection = document.getElementById('resultsSection');
    resultsCard = document.getElementById('resultsCard');
    errorSection = document.getElementById('errorSection');
    
    resultHeader = document.getElementById('resultHeader');
    resultIcon = document.getElementById('resultIcon');
    resultLabel = document.querySelector('#resultLabel');
    resultUrl = document.getElementById('resultUrl');
    
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
    
    // event listeners
    checkBtn.addEventListener('click', checkURL);
    urlInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') checkURL();
    });
    if (dismissError) {
        dismissError.addEventListener('click', hideError);
    }
    
    // set up session stuff with inactivity timeout
    initializeSessionManagement();
    
    // restore previous session if still valid
    restoreSessionState();
    
    console.log('app initialized successfully');
}

// session management stuff
let inactivityTimer = null;
const INACTIVITY_TIMEOUT = 30 * 60 * 1000; // 30 minutes
const SESSION_EXPIRY_KEY = 'phishing_detector_session_expiry';
const SESSION_STATE_KEY = 'phishing_detector_state';

/**
 * set up session management with inactivity tracking
 */
function initializeSessionManagement() {
    // set initial session expiry time (30 min from now)
    updateSessionExpiry();
    
    // track user activity (keyboard, mouse, scroll, touch)
    document.addEventListener('mousemove', resetInactivityTimer);
    document.addEventListener('keydown', resetInactivityTimer);
    document.addEventListener('click', resetInactivityTimer);
    document.addEventListener('scroll', resetInactivityTimer);
    document.addEventListener('touchstart', resetInactivityTimer);
    
    // save session state every 5 seconds
    setInterval(saveSessionState, 5000);
    
    // save when leaving page
    window.addEventListener('beforeunload', saveSessionState);
    
    // check session on load
    checkSessionExpiry();
    
    // check session every minute
    setInterval(checkSessionExpiry, 60000);
    
    console.log('session management initialized (30-minute inactivity timeout)');
}

/**
 * Reset inactivity timer on user activity
 */
function resetInactivityTimer() {
    updateSessionExpiry();
}

/**
 * Update session expiry time to 30 minutes from now
 */
function updateSessionExpiry() {
    try {
        const expiryTime = Date.now() + INACTIVITY_TIMEOUT;
        localStorage.setItem(SESSION_EXPIRY_KEY, expiryTime.toString());
    } catch (e) {
        console.error('Error updating session expiry:', e);
    }
}

/**
 * Check if session has expired due to inactivity
 */
function checkSessionExpiry() {
    try {
        const expiryTime = localStorage.getItem(SESSION_EXPIRY_KEY);
        if (!expiryTime) {
            // No session expiry set, initialize it
            updateSessionExpiry();
            return;
        }
        
        const now = Date.now();
        if (now > parseInt(expiryTime)) {
            // Session expired - clear all session data
            clearSessionData();
            showInactivityWarning();
        }
    } catch (e) {
        console.error('Error checking session expiry:', e);
    }
}

/**
 * Clear all session data
 */
function clearSessionData() {
    try {
        localStorage.removeItem(SESSION_EXPIRY_KEY);
        localStorage.removeItem(SESSION_STATE_KEY);
        localStorage.removeItem('phishing_detector_session');
        console.log('✅ Session cleared due to inactivity');
    } catch (e) {
        console.error('Error clearing session data:', e);
    }
}

/**
 * Show warning that session has expired
 */
function showInactivityWarning() {
    // Clear the UI
    if (resultsSection) {
        resultsSection.style.display = 'none';
    }
    if (urlInput) {
        urlInput.value = '';
    }
    
    // Show error message
    showError('Session expired due to inactivity (30 minutes). Please refresh the page to continue.');
    
    // Optionally, auto-reload after showing warning
    setTimeout(() => {
        location.reload();
    }, 3000);
}

/**
 * Save current page state to localStorage for session persistence
 */
function saveSessionState() {
    try {
        // Only save if session is still valid
        const expiryTime = localStorage.getItem(SESSION_EXPIRY_KEY);
        if (!expiryTime || Date.now() > parseInt(expiryTime)) {
            return; // Don't save if session expired
        }
        
        const sessionState = {
            timestamp: Date.now(),
            lastActivityTime: Date.now(),
            url: urlInput ? urlInput.value : '',
            resultsVisible: resultsSection ? resultsSection.style.display !== 'none' : false,
            currentResult: {
                label: resultLabel ? resultLabel.textContent : '',
                url: resultUrl ? resultUrl.textContent : '',
                probability: resultProbability ? resultProbability.textContent : '',
                classification: resultClassification ? resultClassification.textContent : '',
                reason: resultReason ? resultReason.textContent : '',
            },
            scrollPosition: window.scrollY,
        };
        
        localStorage.setItem(SESSION_STATE_KEY, JSON.stringify(sessionState));
    } catch (e) {
        console.error('Error saving session state:', e);
    }
}

/**
 * Restore previous page state from localStorage (only if session is valid)
 */
function restoreSessionState() {
    try {
        // First check if session has expired
        const expiryTime = localStorage.getItem(SESSION_EXPIRY_KEY);
        if (!expiryTime || Date.now() > parseInt(expiryTime)) {
            // Session expired - clear everything
            clearSessionData();
            return;
        }
        
        const savedState = localStorage.getItem(SESSION_STATE_KEY);
        if (!savedState) return;
        
        const state = JSON.parse(savedState);
        
        // Restore previous URL input
        if (state.url && urlInput) {
            urlInput.value = state.url;
        }
        
        // Restore results if they were visible
        if (state.resultsVisible && state.currentResult) {
            setTimeout(() => {
                // Restore result display
                if (resultLabel && state.currentResult.label) {
                    resultLabel.textContent = state.currentResult.label;
                }
                if (resultUrl && state.currentResult.url) {
                    resultUrl.textContent = state.currentResult.url;
                }
                if (resultProbability && state.currentResult.probability) {
                    resultProbability.textContent = state.currentResult.probability;
                }
                if (resultClassification && state.currentResult.classification) {
                    resultClassification.textContent = state.currentResult.classification;
                }
                if (resultReason && state.currentResult.reason) {
                    resultReason.textContent = state.currentResult.reason;
                }
                
                // Show results section
                if (resultsSection) {
                    resultsSection.style.display = 'block';
                }
                
                // Restore scroll position
                window.scrollTo(0, state.scrollPosition);
                
                console.log('✅ Session state restored (user returned within 30 min inactivity timeout)');
            }, 100);
        }
    } catch (e) {
        console.error('Error restoring session state:', e);
    }
}

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
async function checkURL() {
    const url = urlInput.value.trim();
    
    // Validate input
    if (!url) {
        console.warn('⚠️ No URL provided');
        alert('Please enter a URL');
        return;
    }
    
    console.log('🔍 Checking URL:', url);
    
    // Add protocol if missing
    let fullURL = url;
    if (!url.match(/^https?:\/\//)) {
        fullURL = 'https://' + url;
    }
    
    console.log('📨 Full URL:', fullURL);
    
    // Update UI
    hideError();
    hideResults();
    setLoading(true);
    showLoading();
    
    try {
        // Get auth token
        const token = getAuthToken();
        console.log('🔐 Token:', token ? 'Present' : 'Missing');
        
        // Call API
        console.log('📞 Calling checkPhishing()...');
        const result = await checkPhishing(fullURL);
        
        // Display results
        console.log('✅ Result received, displaying...');
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
        
        const response = await fetch(`${API_BASE_URL}/predict`, {
            method: 'POST',
            headers: headers,
            body: JSON.stringify({ url: url }),
            signal: controller.signal
        });
        
        clearTimeout(timeoutId);
        
        console.log('📊 Response status:', response.status);
        
        // If auth fails, redirect to login
        if (response.status === 401 && USE_SECURE_API) {
            console.warn('Token expired - back to login');
            window.location.href = 'secure-auth-portal.html';
            throw new Error('Authentication required');
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
        console.log('✅ API Response received:', data);
        return data;
        
    } catch (error) {
        console.error('Exception caught:', error.name, error.message);
        if (error.name === 'AbortError') {
            throw new Error('Request took too long - please try again');
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
    
    // Set progress bar with professional color
    progressBar.style.width = `${displayConfidence}%`;
    progressBar.style.backgroundColor = riskColor;
    
    // Set detailed reason
    resultReason.textContent = riskDetails || data.reason || 'Analysis completed. URL appears to be legitimate based on available intelligence.';
    
    // Clear threat indicators
    threatIndicators.innerHTML = '';
    
    // Build compact threat assessment section
    let threatHTML = '';
    
    // THREAT LEVEL
    if (riskData.risk_level) {
        threatHTML += `
            <div class="threat-assessment-section">
                <div class="threat-header" style="border-left-color: ${riskColor}; background-color: ${riskColor}15">
                    <div class="threat-title">THREAT LEVEL:</div>
                    <div class="threat-value" style="color: ${riskColor}">${riskData.risk_level}</div>
                    <div class="threat-category">${riskData.risk_category}</div>
                </div>
        `;
    }
    
    // RECOMMENDATION
    if (riskRecommendation) {
        threatHTML += `
            <div class="recommendation-section" style="border-left-color: ${riskColor}; background-color: ${riskColor}15">
                <div class="section-title" style="color: ${riskColor}">RECOMMENDATION:</div>
                <div class="section-content">${riskRecommendation}</div>
            </div>
        `;
    }
    
    // SUGGESTED ACTIONS
    if (riskData.actions && Array.isArray(riskData.actions) && riskData.actions.length > 0) {
        threatHTML += `
            <div class="actions-section" style="border-left-color: ${riskColor}; background-color: ${riskColor}15">
                <div class="section-title" style="color: ${riskColor}">SUGGESTED ACTIONS:</div>
                <ul class="actions-list">
                    ${riskData.actions.map(action => `<li>${action}</li>`).join('')}
                </ul>
            </div>
        `;
    }
    
    // SERVER STATUS
    if (data.website_status) {
        const isReachable = data.website_status.is_reachable || data.website_status.is_live;
        const statusCode = data.website_status.status_code || '---';
        const serverStatus = isReachable ? 'Online' : 'Offline';
        threatHTML += `
            <div class="server-status-section" style="border-left-color: #0099ff; background-color: #0099ff15">
                <span class="status-label">Server Status:</span>
                <span class="status-value">${serverStatus} (HTTP ${statusCode})</span>
            </div>
        `;
    }
    
    // CONFIDENCE LEVEL
    threatHTML += `
        <div class="confidence-section" style="border-left-color: ${riskColor}; background-color: ${riskColor}15">
            <span class="confidence-label">Confidence Level:</span>
            <span class="confidence-value" style="color: ${riskColor}">${riskData.confidence_level || (displayConfidence > 80 ? 'HIGH' : displayConfidence > 50 ? 'MEDIUM' : 'LOW')}</span>
        </div>
    `;
    
    if (threatHTML) {
        threatHTML += '</div>';  // Close threat-assessment-section
        threatIndicators.innerHTML = threatHTML;
    }
    
    // Add threat detail tables for advanced threat detection data
    const threatDetails = document.createElement('div');
    threatDetails.className = 'threat-details-tables';
    
    // Threat Indicators
    if (data.features && data.features.threat_indicators && Array.isArray(data.features.threat_indicators) && data.features.threat_indicators.length > 0) {
        const indicatorsTable = `
            <div class="threat-table-section">
                <h4 class="threat-table-title">Threat Indicators</h4>
                <table class="threat-table">
                    <tbody>
                        ${data.features.threat_indicators.map((indicator, idx) => `<tr><td class="indicator-item">${indicator}</td></tr>`).join('')}
                    </tbody>
                </table>
            </div>
        `;
        threatDetails.innerHTML += indicatorsTable;
    }
    
    // Risk Indicators
    if (data.features && data.features.threat_risk_indicators && Array.isArray(data.features.threat_risk_indicators) && data.features.threat_risk_indicators.length > 0) {
        const riskTable = `
            <div class="threat-table-section">
                <h4 class="threat-table-title">Risk Indicators</h4>
                <table class="threat-table">
                    <tbody>
                        ${data.features.threat_risk_indicators.map((indicator, idx) => `<tr><td class="indicator-item">${indicator}</td></tr>`).join('')}
                    </tbody>
                </table>
            </div>
        `;
        threatDetails.innerHTML += riskTable;
    }
    
    // Threat Scan Score
    if (data.features && data.features.threat_scan_score !== undefined && data.features.threat_scan_score !== null) {
        const scanScoreTable = `
            <div class="threat-table-section">
                <h4 class="threat-table-title">Threat Scan Score</h4>
                <table class="threat-table">
                    <tbody>
                        <tr><td class="score-label">Overall Risk Score:</td><td class="score-value">${(data.features.threat_scan_score * 100).toFixed(1)}%</td></tr>
                    </tbody>
                </table>
            </div>
        `;
        threatDetails.innerHTML += scanScoreTable;
    }
    
    // Technologies Detected
    if (data.features && data.features.threat_technologies && Array.isArray(data.features.threat_technologies) && data.features.threat_technologies.length > 0) {
        const techTable = `
            <div class="threat-table-section">
                <h4 class="threat-table-title">Technologies Detected</h4>
                <table class="threat-table">
                    <tbody>
                        ${data.features.threat_technologies.map((tech, idx) => `<tr><td class="tech-item">${tech}</td></tr>`).join('')}
                    </tbody>
                </table>
            </div>
        `;
        threatDetails.innerHTML += techTable;
    }
    
    // HTTP Headers
    if (data.features && data.features.threat_http_headers && typeof data.features.threat_http_headers === 'object' && Object.keys(data.features.threat_http_headers).length > 0) {
        const headerRows = Object.entries(data.features.threat_http_headers).map(([key, value]) => 
            `<tr><td class="header-key">${key}</td><td class="header-value">${String(value).substring(0, 50)}</td></tr>`
        ).join('');
        const headersTable = `
            <div class="threat-table-section">
                <h4 class="threat-table-title">HTTP Headers</h4>
                <table class="threat-table">
                    <thead><tr><th>Header</th><th>Value</th></tr></thead>
                    <tbody>
                        ${headerRows}
                    </tbody>
                </table>
            </div>
        `;
        threatDetails.innerHTML += headersTable;
    }
    
    // SSL Certificate Info
    if (data.features && data.features.threat_ssl_info && typeof data.features.threat_ssl_info === 'object' && Object.keys(data.features.threat_ssl_info).length > 0) {
        const sslRows = Object.entries(data.features.threat_ssl_info).map(([key, value]) => 
            `<tr><td class="ssl-key">${key}</td><td class="ssl-value">${String(value).substring(0, 50)}</td></tr>`
        ).join('');
        const sslTable = `
            <div class="threat-table-section">
                <h4 class="threat-table-title">SSL/TLS Certificate</h4>
                <table class="threat-table">
                    <thead><tr><th>Property</th><th>Value</th></tr></thead>
                    <tbody>
                        ${sslRows}
                    </tbody>
                </table>
            </div>
        `;
        threatDetails.innerHTML += sslTable;
    }
    
    // Server Information
    if (data.features && data.features.threat_server_info && typeof data.features.threat_server_info === 'object' && Object.keys(data.features.threat_server_info).length > 0) {
        const serverRows = Object.entries(data.features.threat_server_info).map(([key, value]) => 
            `<tr><td class="server-key">${key}</td><td class="server-value">${String(value).substring(0, 50)}</td></tr>`
        ).join('');
        const serverTable = `
            <div class="threat-table-section">
                <h4 class="threat-table-title">Server Information</h4>
                <table class="threat-table">
                    <thead><tr><th>Property</th><th>Value</th></tr></thead>
                    <tbody>
                        ${serverRows}
                    </tbody>
                </table>
            </div>
        `;
        threatDetails.innerHTML += serverTable;
    }
    
    // Vulnerabilities (if any)
    if (data.features && data.features.threat_vulnerabilities && Array.isArray(data.features.threat_vulnerabilities) && data.features.threat_vulnerabilities.length > 0) {
        const vulnTable = `
            <div class="threat-table-section threat-vulnerability-section">
                <h4 class="threat-table-title">Vulnerabilities Detected</h4>
                <table class="threat-table">
                    <tbody>
                        ${data.features.threat_vulnerabilities.map((vuln, idx) => `<tr><td class="vulnerability-item">${vuln}</td></tr>`).join('')}
                    </tbody>
                </table>
            </div>
        `;
        threatDetails.innerHTML += vulnTable;
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
        badge.innerHTML = `<strong style="color: #ff0000">[VERIFIED PHISHING]</strong> ID: ${data.phishtank_data.phish_id}`;
        threatIndicators.appendChild(badge);
    }
    
    // Display features
    if (data.features && Object.keys(data.features).length > 0) {
        displayFeatures(data.features);
    }
    
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
        advancedFeatures.innerHTML = '<p>No detailed features available</p>';
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
        
        featureEl.innerHTML = `<span class="feature-name">${formattedKey}</span><span class="feature-value">${formattedValue}</span>`;
        
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
        return value ? '[YES]' : '[NO]';
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
        return value.join(', ') || '[EMPTY]';
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
    btnSpinner.classList.remove('hidden');
}

function hideLoading() {
    checkBtn.disabled = false;
    btnText.style.display = 'inline';
    btnSpinner.classList.add('hidden');
}

function showResults() {
    resultsSection.classList.remove('hidden');
    // Save session state when results are shown
    saveSessionState();
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

console.log('✅ App.js loaded and ready');
