/**
 * Main Application Logic - Phishing URL Detector
 * Handles the URL checking form and parallax background effect
 */

// Configuration
const API_BASE_URL = 'https://phishing-detection-system-1.onrender.com';
const REQUEST_TIMEOUT = 30000; // 30 seconds
const SESSION_KEY = 'phishing_detector_session';

// DOM Elements
let urlInput, checkBtn, btnText, btnSpinner;
let resultsSection, resultsCard, errorSection;
let resultHeader, resultIcon, resultLabel, resultUrl;
let resultProbability, resultClassification;
let progressBar, resultReason, threatIndicators;
let errorMessage, dismissError;
let advancedSubdomainTable, advancedSubdomainTableBody;
let securityFeatures, structureFeatures, characterFeatures;
let domainFeatures, advancedFeatures;

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    try {
        // Check if user is authenticated - if not, redirect to login
        const hasAuth = checkAuthentication();
        console.log('🔐 Authentication check:', hasAuth ? 'PASSED' : 'FAILED');
        
        if (!hasAuth) {
            console.log('⚠️ Not authenticated, redirecting to login...');
            window.location.href = 'secure-auth-portal.html';
            return;
        }
        
        // Initialize the app
        console.log('✅ Initializing URL checker app...');
        init();
        setupParallax();
        console.log('✅ App initialized successfully');
        
    } catch (error) {
        console.error('❌ App initialization error:', error);
        // Show error to user
        alert('Error initializing app: ' + error.message);
    }
});

/**
 * Check if user has valid authentication token
 */
function checkAuthentication() {
    try {
        const session = localStorage.getItem(SESSION_KEY);
        if (!session) return false;
        
        const sessionData = JSON.parse(session);
        const currentTime = new Date().getTime();
        
        // Check if session is still valid
        if (currentTime < sessionData.expiry && sessionData.token) {
            return true;
        } else {
            // Session expired
            localStorage.removeItem(SESSION_KEY);
            return false;
        }
    } catch (e) {
        return false;
    }
}

function init() {
    try {
        // Get DOM elements
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
        
        advancedSubdomainTableBody = document.getElementById('advancedSubdomainTableBody');
        securityFeatures = document.getElementById('securityFeatures');
        structureFeatures = document.getElementById('structureFeatures');
        characterFeatures = document.getElementById('characterFeatures');
        domainFeatures = document.getElementById('domainFeatures');
        advancedFeatures = document.getElementById('advancedFeatures');
        
        // Validate critical elements
        if (!urlInput || !checkBtn || !resultsSection || !errorSection) {
            throw new Error('Critical DOM elements not found');
        }
        
        console.log('✅ All DOM elements loaded successfully');
        
        // Event listeners
        checkBtn.addEventListener('click', checkURL);
        urlInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') checkURL();
        });
        if (dismissError) {
            dismissError.addEventListener('click', hideError);
        }
        
        console.log('✅ Event listeners attached');
        
    } catch (error) {
        console.error('❌ Init error:', error);
        throw error;
    }
}

/**
 * Setup 3D Parallax Background Effect
 */
function setupParallax() {
    try {
        const parallaxBg = document.querySelector('.parallax-bg');
        
        if (!parallaxBg) {
            console.warn('⚠️ Parallax background element not found');
            return;
        }
        
        console.log('✅ Parallax background found, setting up effect...');
        
        document.addEventListener('mousemove', (e) => {
            const mouseX = e.clientX / window.innerWidth;
            const mouseY = e.clientY / window.innerHeight;
            
            const moveX = (mouseX - 0.5) * 20; // Adjust intensity
            const moveY = (mouseY - 0.5) * 20;
            
            parallaxBg.style.transform = `translate(${moveX}px, ${moveY}px) scale(1.02)`;
        });
        
        console.log('✅ Parallax effect enabled');
        
    } catch (error) {
        console.error('❌ Parallax setup error:', error);
    }
}

/**
 * Check URL for phishing threats
 */
async function checkURL() {
    console.log('🔍 Check URL clicked');
    
    const url = urlInput.value.trim();
    
    // Validate input
    if (!url) {
        console.warn('⚠️ No URL provided');
        showError('Please enter a URL');
        return;
    }
    
    console.log('📝 URL entered:', url);
    
    // Add protocol if missing
    let fullURL = url;
    if (!url.match(/^https?:\/\//)) {
        fullURL = 'https://' + url;
    }
    
    console.log('📨 Full URL to check:', fullURL);
    
    // Show loading state
    showLoading();
    hideError();
    hideResults();
    
    try {
        const token = getAuthToken();
        console.log('🔐 Token status:', token ? 'Present (' + token.length + ' chars)' : 'Missing');
        
        // Call backend API
        console.log('🌐 Calling API:', `${API_BASE_URL}/predict`);
        
        const response = await fetch(`${API_BASE_URL}/predict`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ url: fullURL })
        });
        
        console.log('📊 API Response status:', response.status);
        
        if (!response.ok) {
            if (response.status === 401) {
                console.error('❌ Authentication failed (401)');
                // Clear session and redirect to login
                localStorage.removeItem(SESSION_KEY);
                window.location.href = 'secure-auth-portal.html';
                return;
            }
            
            // Try to get error message from response
            let errorMsg = `API Error: ${response.statusText}`;
            try {
                const errorData = await response.json();
                errorMsg = errorData.message || errorData.error || errorMsg;
            } catch (e) {
                // Response isn't JSON, use generic message
            }
            
            console.error('❌ API Error:', errorMsg);
            throw new Error(errorMsg);
        }
        
        const data = await response.json();
        console.log('✅ Analysis complete:', data);
        displayResults(data, fullURL);
        
    } catch (error) {
        console.error('❌ Error:', error);
        const token = getAuthToken();
        console.error('Token status:', token ? 'Present' : 'Missing');
        if (token) {
            console.error('Token preview:', token.substring(0, 20) + '...');
        }
        showError(`Error checking URL: ${error.message}`);
    } finally {
        hideLoading();
    }
}

/**
 * Display the phishing analysis results
 */
function displayResults(data, url) {
    // Set result status
    const isPhishing = data.label === 1 || data.prediction === 'phishing';
    const confidence = Math.round((data.probability || 0) * 100);
    
    // Update card color and icon based on result
    if (isPhishing) {
        resultHeader.style.borderLeftColor = '#ff0000';
        resultIcon.textContent = '🚨';
        resultLabel.textContent = 'PHISHING DETECTED';
        resultLabel.style.color = '#ff0000';
        resultsCard.style.borderColor = '#ff0000';
    } else {
        resultHeader.style.borderLeftColor = '#00ff00';
        resultIcon.textContent = '✅';
        resultLabel.textContent = 'LEGITIMATE';
        resultLabel.style.color = '#00ff00';
        resultsCard.style.borderColor = '#00ff00';
    }
    
    // Set URL
    resultUrl.textContent = url;
    resultUrl.title = url; // Full URL in tooltip
    
    // Set probability and classification
    resultProbability.textContent = `${confidence}%`;
    resultClassification.textContent = isPhishing ? 'PHISHING' : 'LEGITIMATE';
    
    // Set progress bar
    progressBar.style.width = `${confidence}%`;
    progressBar.style.backgroundColor = isPhishing ? '#ff0000' : '#00ff00';
    
    // Set reason/analysis
    resultReason.textContent = data.reason || 'No additional analysis available';
    
    // Display PhishTank verification status if available
    if (data.phishtank_verified) {
        const phishtankBadge = document.createElement('div');
        phishtankBadge.className = 'phishtank-badge';
        phishtankBadge.innerHTML = `
            <strong>[*] VERIFIED BY PHISHTANK</strong><br/>
            Phish ID: ${data.phishtank_data.phish_id}<br/>
            Target: ${data.phishtank_data.target}<br/>
            Submitted: ${new Date(data.phishtank_data.submission_time).toLocaleString()}<br/>
            <a href="${data.phishtank_data.detail_url}" target="_blank" rel="noopener">[View Details]</a>
        `;
        threatIndicators.appendChild(phishtankBadge);
    }
    
    // Display website status
    if (data.website_status) {
        const statusBadge = document.createElement('div');
        statusBadge.className = 'website-status-badge';
        statusBadge.innerHTML = `
            <strong>[SERVER]</strong> 
            Status: ${data.website_status.is_live ? '🟢 LIVE' : '🔴 OFFLINE'}<br/>
            Response Time: ${data.website_status.response_time || 'N/A'}ms
        `;
        threatIndicators.appendChild(statusBadge);
    }
    
    // Display confidence level
    const confidenceBadge = document.createElement('div');
    confidenceBadge.className = 'confidence-badge';
    const confidenceText = data.confidence ? data.confidence.toUpperCase().replace('_', ' ') : 'UNKNOWN';
    confidenceBadge.textContent = `Confidence: ${confidenceText}`;
    threatIndicators.appendChild(confidenceBadge);
    
    // Display scan timestamp
    const timestampBadge = document.createElement('div');
    timestampBadge.className = 'timestamp-badge';
    timestampBadge.textContent = `Scanned: ${new Date(data.scanned_at).toLocaleString()}`;
    threatIndicators.appendChild(timestampBadge);
    
    // Display advanced features if available
    if (data.features && Object.keys(data.features).length > 0) {
        displayFeatures(data.features);
    } else {
        // If no features but has prediction, show basic info
        if (data.phishtank_verified) {
            securityFeatures.innerHTML = '<div class="feature-item"><span class="feature-name">Source</span><span class="feature-value">PhishTank Database</span></div>';
        }
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
 */
function formatFeatureValue(value) {
    if (typeof value === 'boolean') {
        return value ? '✓ YES' : '✗ NO';
    }
    if (typeof value === 'number') {
        // Check if it's a probability (0-1)
        if (value >= 0 && value <= 1) {
            return (value * 100).toFixed(1) + '%';
        }
        // Round other numbers to 2 decimals
        return value.toFixed(2);
    }
    if (Array.isArray(value)) {
        return value.join(', ') || '(empty)';
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
}

function hideResults() {
    resultsSection.classList.add('hidden');
}

function showError(message) {
    errorMessage.textContent = message;
    errorSection.classList.remove('hidden');
}

function hideError() {
    errorSection.classList.add('hidden');
}

/**
 * Get authentication token from localStorage
 */
function getAuthToken() {
    try {
        const session = localStorage.getItem(SESSION_KEY);
        if (!session) return '';
        
        const sessionData = JSON.parse(session);
        return sessionData.token || '';
    } catch (e) {
        console.error('Error retrieving token:', e);
        return '';
    }
}
