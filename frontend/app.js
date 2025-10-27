/**
 * Main Application Logic - Phishing URL Detector
 * Handles the URL checking form and parallax background effect
 */

// Configuration
const API_BASE_URL = 'https://phishing-detection-system-1.onrender.com';
const REQUEST_TIMEOUT = 30000; // 30 seconds

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
    init();
    setupParallax();
});

function init() {
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
    
    // Event listeners
    checkBtn.addEventListener('click', checkURL);
    urlInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') checkURL();
    });
    dismissError.addEventListener('click', hideError);
}

/**
 * Setup 3D Parallax Background Effect
 */
function setupParallax() {
    document.addEventListener('mousemove', (e) => {
        const parallaxBg = document.querySelector('.parallax-bg');
        if (!parallaxBg) return;
        
        const mouseX = e.clientX / window.innerWidth;
        const mouseY = e.clientY / window.innerHeight;
        
        const moveX = (mouseX - 0.5) * 20; // Adjust intensity
        const moveY = (mouseY - 0.5) * 20;
        
        parallaxBg.style.transform = `translate(${moveX}px, ${moveY}px) scale(1.02)`;
    });
}

/**
 * Check URL for phishing threats
 */
async function checkURL() {
    const url = urlInput.value.trim();
    
    // Validate input
    if (!url) {
        showError('Please enter a URL');
        return;
    }
    
    // Add protocol if missing
    let fullURL = url;
    if (!url.match(/^https?:\/\//)) {
        fullURL = 'https://' + url;
    }
    
    // Show loading state
    showLoading();
    hideError();
    hideResults();
    
    try {
        // Call backend API
        const response = await fetch(`${API_BASE_URL}/predict`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${getAuthToken()}`
            },
            body: JSON.stringify({ url: fullURL }),
            timeout: REQUEST_TIMEOUT
        });
        
        if (!response.ok) {
            if (response.status === 401) {
                throw new Error('Authentication failed - please log in again');
            }
            throw new Error(`API Error: ${response.statusText}`);
        }
        
        const data = await response.json();
        displayResults(data, fullURL);
        
    } catch (error) {
        console.error('❌ Error:', error);
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
    
    // Update card color based on result
    if (isPhishing) {
        resultHeader.style.borderLeftColor = '#ff0000';
        resultIcon.textContent = '🚨';
        resultLabel.textContent = 'PHISHING DETECTED';
        resultLabel.style.color = '#ff0000';
    } else {
        resultHeader.style.borderLeftColor = '#00ff00';
        resultIcon.textContent = '✅';
        resultLabel.textContent = 'LEGITIMATE';
        resultLabel.style.color = '#00ff00';
    }
    
    // Set URL
    resultUrl.textContent = url;
    
    // Set probability and classification
    resultProbability.textContent = `${confidence}%`;
    resultClassification.textContent = isPhishing ? 'PHISHING' : 'LEGITIMATE';
    
    // Set progress bar
    progressBar.style.width = `${confidence}%`;
    progressBar.style.backgroundColor = isPhishing ? '#ff0000' : '#00ff00';
    
    // Set reason/analysis
    resultReason.textContent = data.reason || 'No additional analysis available';
    
    // Display threat indicators if available
    if (data.threat_indicators && Array.isArray(data.threat_indicators)) {
        threatIndicators.innerHTML = '';
        data.threat_indicators.forEach(threat => {
            const badge = document.createElement('span');
            badge.className = 'threat-badge';
            badge.textContent = threat;
            threatIndicators.appendChild(badge);
        });
    }
    
    // Display advanced features if available
    if (data.features) {
        displayFeatures(data.features);
    }
    
    // Display subdomain info if available
    if (data.subdomain_info) {
        displaySubdomainInfo(data.subdomain_info);
    }
    
    showResults();
}

/**
 * Display advanced feature analysis
 */
function displayFeatures(features) {
    // Clear previous features
    securityFeatures.innerHTML = '';
    structureFeatures.innerHTML = '';
    characterFeatures.innerHTML = '';
    domainFeatures.innerHTML = '';
    advancedFeatures.innerHTML = '';
    
    // Categorize and display features
    for (const [key, value] of Object.entries(features)) {
        const featureEl = document.createElement('div');
        featureEl.className = 'feature-item';
        featureEl.innerHTML = `<span class="feature-name">${key}:</span><span class="feature-value">${value}</span>`;
        
        // Categorize by key name
        if (key.includes('phishing') || key.includes('suspicious') || key.includes('malicious')) {
            securityFeatures.appendChild(featureEl);
        } else if (key.includes('url') || key.includes('scheme') || key.includes('port')) {
            structureFeatures.appendChild(featureEl);
        } else if (key.includes('entropy') || key.includes('char') || key.includes('length')) {
            characterFeatures.appendChild(featureEl);
        } else if (key.includes('domain') || key.includes('ip') || key.includes('dns')) {
            domainFeatures.appendChild(featureEl);
        } else {
            advancedFeatures.appendChild(featureEl);
        }
    }
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
    return localStorage.getItem('auth_token') || '';
}
