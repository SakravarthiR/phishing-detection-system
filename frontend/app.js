/**
 * Main Application Logic - Phishing URL Detector
 * Handles the URL checking form and parallax background effect
 * Matches discovery-engine.js pattern for consistency
 */

// 3D Parallax Background Effect
document.addEventListener('mousemove', (e) => {
    const parallaxBg = document.querySelector('.parallax-bg');
    if (!parallaxBg) return;
    
    const mouseX = e.clientX / window.innerWidth;
    const mouseY = e.clientY / window.innerHeight;
    
    const moveX = (mouseX - 0.5) * 20;
    const moveY = (mouseY - 0.5) * 20;
    
    parallaxBg.style.transform = `translate(${moveX}px, ${moveY}px) scale(1.02)`;
});

// Configuration
const API_BASE_URL = 'https://phishing-detection-system-1.onrender.com';
const REQUEST_TIMEOUT = 30000; // 30 seconds
const USE_SECURE_API = true; // Use JWT authentication

// DOM Elements
let urlInput, checkBtn, btnText, btnSpinner;
let resultsSection, resultsCard, errorSection;
let resultHeader, resultIcon, resultLabel, resultUrl;
let resultProbability, resultClassification;
let progressBar, resultReason, threatIndicators;
let errorMessage, dismissError;
let securityFeatures, structureFeatures, characterFeatures;
let domainFeatures, advancedFeatures;

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    console.log('� App loading...');
    init();
});

/**
 * Initialize the application
 */
function init() {
    console.log('✅ Initializing phishing detector...');
    
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
    
    console.log('✅ App initialized successfully');
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
    
    // Update card appearance
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
    
    // Set result details
    resultUrl.textContent = data.url;
    resultUrl.title = data.url;
    resultProbability.textContent = `${confidence}%`;
    resultClassification.textContent = isPhishing ? 'PHISHING' : 'LEGITIMATE';
    
    // Set progress bar
    progressBar.style.width = `${Math.min(confidence, 100)}%`;
    progressBar.style.backgroundColor = isPhishing ? '#ff0000' : '#00ff00';
    
    // Set reason
    resultReason.textContent = data.reason || 'No additional analysis available';
    
    // Clear threat indicators
    threatIndicators.innerHTML = '';
    
    // Add PhishTank badge
    if (data.phishtank_verified) {
        const badge = document.createElement('div');
        badge.className = 'phishtank-badge';
        badge.innerHTML = `[*] VERIFIED BY PHISHTANK - ID: ${data.phishtank_data.phish_id}`;
        threatIndicators.appendChild(badge);
    }
    
    // Add website status
    if (data.website_status) {
        const badge = document.createElement('div');
        badge.className = 'website-status-badge';
        const status = data.website_status.is_live ? '🟢 LIVE' : '🔴 OFFLINE';
        badge.innerHTML = `[SERVER] ${status}`;
        threatIndicators.appendChild(badge);
    }
    
    // Add confidence level badge
    const confBadge = document.createElement('div');
    confBadge.className = 'confidence-badge';
    confBadge.textContent = `Confidence: ${data.confidence_level ? data.confidence_level.toUpperCase() : 'MEDIUM'}`;
    threatIndicators.appendChild(confBadge);
    
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
        return value ? '[YES]' : '[NO]';
    }
    if (typeof value === 'number') {
        // Check if it's a boolean flag (0 or 1)
        if (value === 0 || value === 1) {
            return value === 1 ? '[YES]' : '[NO]';
        }
        // Check if it's a probability/rate (0-1 range for counts)
        if (value > 0 && value <= 1 && value !== Math.floor(value)) {
            return (value * 100).toFixed(1) + '%';
        }
        // Check if it's already a percentage-like value (high numbers like 100)
        if (value >= 100) {
            return value.toFixed(0);
        }
        // Round other numbers to 2 decimals
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
