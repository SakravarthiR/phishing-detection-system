/**
 * Scanner page logic - handles URL scanning and subdomain checks.
 * 
 * Added the parallax effect because why not, makes it look cooler.
 * The subdomain scanner was inspired by c99.nl but way more integrated.
 */

// 3D Parallax Background Effect for Scanner
document.addEventListener('mousemove', (e) => {
    const parallaxBg = document.querySelector('.parallax-bg-scanner');
    if (!parallaxBg) return;
    
    const mouseX = e.clientX / window.innerWidth;
    const mouseY = e.clientY / window.innerHeight;
    
    const moveX = (mouseX - 0.5) * 40; // Adjust intensity (40px max)
    const moveY = (mouseY - 0.5) * 40;
    
    parallaxBg.style.transform = `translate(${moveX}px, ${moveY}px) scale(1.05)`;
});

// Configuration
const API_BASE_URL = 'https://api.phishingdetector.systems';
const REQUEST_TIMEOUT = 120000; // 2 minutes for subdomain scanning
const USE_SECURE_API = true; // Set to true to use secure_api.py (JWT auth required)

// DOM Elements
let domainInput, scanBtn, btnText, btnSpinner;
let loadingSection, errorSection, resultsSection;
let domainName, subdomainCount, mostUsedIp, mostUsedCount, scanTime;
let scanDate, uniqueIps, cloudflareCount;
let ipStatsList, subdomainTableBody, exportBtn;
let errorMessage;
let historyList, clearHistoryBtn;

// Scan history storage
const STORAGE_KEY = 'scanner_history';
let scanHistory = [];

// Initialize
function init() {
    // Get DOM elements
    domainInput = document.getElementById('domainInput');
    scanBtn = document.getElementById('scanBtn');
    btnText = scanBtn.querySelector('.btn-text');
    btnSpinner = scanBtn.querySelector('.btn-spinner');
    
    loadingSection = document.getElementById('loadingSection');
    errorSection = document.getElementById('errorSection');
    resultsSection = document.getElementById('resultsSection');
    
    domainName = document.getElementById('domainName');
    subdomainCount = document.getElementById('subdomainCount');
    mostUsedIp = document.getElementById('mostUsedIp');
    mostUsedCount = document.getElementById('mostUsedCount');
    scanTime = document.getElementById('scanTime');
    
    scanDate = document.getElementById('scanDate');
    uniqueIps = document.getElementById('uniqueIps');
    cloudflareCount = document.getElementById('cloudflareCount');
    
    ipStatsList = document.getElementById('ipStatsList');
    subdomainTableBody = document.getElementById('subdomainTableBody');
    exportBtn = document.getElementById('exportBtn');
    errorMessage = document.getElementById('errorMessage');
    
    historyList = document.getElementById('historyList');
    clearHistoryBtn = document.getElementById('clearHistoryBtn');
    
    // Event listeners
    scanBtn.addEventListener('click', startScan);
    domainInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') startScan();
    });
    exportBtn.addEventListener('click', exportToCSV);
    clearHistoryBtn.addEventListener('click', clearAllHistory);
    
    // Load scan history
    loadScanHistory();
    renderHistory();
}

/**
 * Start the subdomain scan.
 * Does validation, cleans up the input, then hits the API.
 */
async function startScan() {
    const domain = domainInput.value.trim();
    
    // Basic validation
    if (!domain) {
        alert('Dude, you need to enter a domain first');
        return;
    }
    
    // Strip out http://, www., and any path stuff
    const cleanDomain = domain
        .replace(/^https?:\/\//, '')
        .replace(/^www\./, '')
        .split('/')[0];  // Remove anything after the first slash
    
    console.log(`Starting scan for: ${cleanDomain}`);
    
    // Update UI
    hideError();
    hideResults();
    setLoading(true);
    showLoading();
    
    try {
        // Call API
        const result = await scanSubdomains(cleanDomain);
        
        // Display results
        displayResults(result);
        
    } catch (error) {
        showError(error.message);
    } finally {
        setLoading(false);
        hideLoading();
    }
}

/**
 * Call subdomain scanner API
 */
async function scanSubdomains(domain) {
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
        
        const response = await fetch(`${API_BASE_URL}/scan-subdomains`, {
            method: 'POST',
            headers: headers,
            body: JSON.stringify({ url: domain }),
            signal: controller.signal
        });
        
        clearTimeout(timeoutId);
        
        // If auth fails, kick them back to login
        if (response.status === 401 && USE_SECURE_API) {
            console.warn('Token expired or invalid - back to login you go');
            window.location.href = '/secure-auth-portal.html';
            throw new Error('Authentication required');
        }
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.message || 'Scan failed');
        }
        
        const data = await response.json();
        return data;
        
    } catch (error) {
        if (error.name === 'AbortError') {
            throw new Error('Scan took too long - probably a huge domain with tons of subdomains');
        }
        throw error;
    }
}

/**
 * Grab JWT token from localStorage.
 * Returns null if token is expired or doesn't exist.
 */
function getAuthToken() {
    const session = localStorage.getItem('phishing_detector_session');
    if (!session) return null;
    
    try {
        const sessionData = JSON.parse(session);
        if (sessionData.token && sessionData.expiry > Date.now()) {
            return sessionData.token;
        } else {
            // Token's dead, clean it up
            localStorage.removeItem('phishing_detector_session');
            return null;
        }
    } catch (e) {
        return null;
    }
}

/**
 * Display scan results
 */
function displayResults(data) {
    console.log('Scan results:', data);
    
    // Show results section
    resultsSection.classList.remove('hidden');
    
    // Summary cards
    domainName.textContent = data.domain;
    subdomainCount.textContent = data.subdomain_count;
    mostUsedIp.textContent = data.most_used_ip || 'N/A';
    mostUsedCount.textContent = data.most_used_ip_count 
        ? `Used by ${data.most_used_ip_count} subdomains`
        : '';
    scanTime.textContent = `${data.scan_time}s`;
    
    // Statistics
    scanDate.textContent = data.scan_date;
    uniqueIps.textContent = data.unique_ips;
    cloudflareCount.textContent = data.cloudflare_count;
    
    // IP Statistics
    displayIpStats(data.ip_statistics);
    
    // Subdomains Table
    displaySubdomainsTable(data.subdomains);
    
    // Add to history
    addToHistory(data);
    
    // Scroll to results
    resultsSection.scrollIntoView({ behavior: 'smooth' });
}

/**
 * Display IP statistics
 */
function displayIpStats(ipStats) {
    ipStatsList.innerHTML = '';
    
    if (!ipStats || Object.keys(ipStats).length === 0) {
        ipStatsList.innerHTML = '<p style="text-align: center; color: #6b7280; padding: 2rem;">No IP statistics available</p>';
        return;
    }
    
    // Show top 10 IPs
    const topIps = Object.entries(ipStats).slice(0, 10);
    
    topIps.forEach(([ip, count]) => {
        const item = document.createElement('div');
        item.className = 'ip-stat-item';
        item.innerHTML = `
            <span class="ip-stat-address">${ip}</span>
            <span class="ip-stat-count">${count}x</span>
        `;
        ipStatsList.appendChild(item);
    });
}

/**
 * Display subdomains in table
 */
function displaySubdomainsTable(subdomains) {
    subdomainTableBody.innerHTML = '';
    
    // Update table count
    const tableCount = document.getElementById('tableCount');
    if (tableCount) {
        tableCount.textContent = subdomains && subdomains.length > 0 
            ? `${subdomains.length} result${subdomains.length !== 1 ? 's' : ''}`
            : '0 results';
    }
    
    if (!subdomains || subdomains.length === 0) {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td colspan="5" style="text-align: center; padding: 3rem; color: #94a3b8; font-size: 1.1rem;">
                <div style="opacity: 0.5; margin-bottom: 0.5rem; font-size: 3rem;">🔍</div>
                <div style="font-weight: 600;">No subdomains found</div>
                <div style="font-size: 0.9rem; margin-top: 0.5rem;">Try scanning a different domain</div>
            </td>
        `;
        subdomainTableBody.appendChild(row);
        return;
    }
    
    subdomains.forEach((sub, index) => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${index + 1}</td>
            <td><span class="advanced-subdomain-name">${sub.subdomain}</span></td>
            <td><span class="advanced-subdomain-full">${sub.full_domain}</span></td>
            <td><span class="advanced-subdomain-ip">${sub.ip || 'N/A'}</span></td>
            <td style="text-align: center;">
                <span class="cloudflare-status ${sub.cloudflare}">${sub.cloudflare}</span>
            </td>
        `;
        subdomainTableBody.appendChild(row);
    });
}

/**
 * Export results to CSV
 */
function exportToCSV() {
    const domain = domainName.textContent;
    const rows = Array.from(subdomainTableBody.querySelectorAll('tr'));
    
    if (rows.length === 0) {
        alert('No data to export');
        return;
    }
    
    // CSV header
    let csv = 'Number,Subdomain,Full Domain,IP Address,Cloudflare\n';
    
    // CSV rows
    rows.forEach(row => {
        const cells = Array.from(row.querySelectorAll('td'));
        if (cells.length === 5) {
            const number = cells[0].textContent;
            const subdomain = cells[1].textContent;
            const fullDomain = cells[2].textContent;
            const ip = cells[3].textContent;
            const cloudflare = cells[4].textContent.trim();
            
            csv += `${number},"${subdomain}","${fullDomain}","${ip}","${cloudflare}"\n`;
        }
    });
    
    // Download CSV
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    const url = URL.createObjectURL(blob);
    
    link.setAttribute('href', url);
    link.setAttribute('download', `subdomains_${domain}_${Date.now()}.csv`);
    link.style.visibility = 'hidden';
    
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    
    console.log('CSV exported successfully');
}

/**
 * Show loading state
 */
function showLoading() {
    loadingSection.classList.remove('hidden');
}

/**
 * Hide loading state
 */
function hideLoading() {
    loadingSection.classList.add('hidden');
}

/**
 * Show error message
 */
function showError(message) {
    errorMessage.textContent = message;
    errorSection.classList.remove('hidden');
}

/**
 * Hide error message
 */
function hideError() {
    errorSection.classList.add('hidden');
}

/**
 * Hide results
 */
function hideResults() {
    resultsSection.classList.add('hidden');
}

/**
 * Set loading state for button
 */
function setLoading(loading) {
    scanBtn.disabled = loading;
    domainInput.disabled = loading;
    
    if (loading) {
        btnText.classList.add('hidden');
        btnSpinner.classList.remove('hidden');
    } else {
        btnText.classList.remove('hidden');
        btnSpinner.classList.add('hidden');
    }
}

/**
 * Load scan history from localStorage
 */
function loadScanHistory() {
    try {
        const stored = localStorage.getItem(STORAGE_KEY);
        scanHistory = stored ? JSON.parse(stored) : [];
    } catch (error) {
        console.error('Failed to load history:', error);
        scanHistory = [];
    }
}

/**
 * Save scan history to localStorage
 */
function saveScanHistory() {
    try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(scanHistory));
    } catch (error) {
        console.error('Failed to save history:', error);
    }
}

/**
 * Add scan to history
 */
function addToHistory(scanData) {
    const historyItem = {
        id: Date.now(),
        domain: scanData.domain,
        subdomainCount: scanData.subdomain_count,
        uniqueIps: scanData.unique_ips,
        cloudflareCount: scanData.cloudflare_count,
        scanTime: scanData.scan_time,
        timestamp: new Date().toISOString(),
        data: scanData // Store full scan data
    };
    
    // Remove duplicate if exists
    scanHistory = scanHistory.filter(item => item.domain !== scanData.domain);
    
    // Add to beginning
    scanHistory.unshift(historyItem);
    
    // Keep only last 10 scans
    if (scanHistory.length > 10) {
        scanHistory = scanHistory.slice(0, 10);
    }
    
    saveScanHistory();
    renderHistory();
}

/**
 * Render scan history
 */
function renderHistory() {
    if (!scanHistory || scanHistory.length === 0) {
        historyList.innerHTML = `
            <div class="history-empty">
                <div class="empty-icon">🔍</div>
                <p class="empty-text">No scan history yet</p>
                <p class="empty-hint">Start scanning domains to see history</p>
            </div>
        `;
        return;
    }
    
    historyList.innerHTML = scanHistory.map(item => {
        const timeAgo = getTimeAgo(new Date(item.timestamp));
        return `
            <div class="history-item" data-id="${item.id}">
                <div class="history-item-header">
                    <div class="history-domain">${item.domain}</div>
                    <button class="history-delete" onclick="deleteHistoryItem(${item.id})" title="Delete">
                        ❌
                    </button>
                </div>
                <div class="history-stats">
                    <div class="history-stat">
                        <span class="stat-icon">🔀</span>
                        <span class="stat-value">${item.subdomainCount}</span>
                    </div>
                    <div class="history-stat">
                        <span class="stat-icon">🌐</span>
                        <span class="stat-value">${item.uniqueIps}</span>
                    </div>
                    <div class="history-stat">
                        <span class="stat-icon">⚡</span>
                        <span class="stat-value">${item.scanTime}</span>
                    </div>
                </div>
                <div class="history-time">
                    <span class="time-icon">🕐</span>
                    <span>${timeAgo}</span>
                </div>
            </div>
        `;
    }).join('');
    
    // Add click listeners to history items
    document.querySelectorAll('.history-item').forEach(item => {
        item.addEventListener('click', (e) => {
            if (!e.target.classList.contains('history-delete')) {
                const id = parseInt(item.dataset.id);
                loadHistoryItem(id);
            }
        });
    });
}

/**
 * Load history item and display results
 */
function loadHistoryItem(id) {
    const item = scanHistory.find(h => h.id === id);
    if (item && item.data) {
        domainInput.value = item.domain;
        displayResults(item.data);
        
        // Scroll to results
        resultsSection.scrollIntoView({ behavior: 'smooth' });
    }
}

/**
 * Delete history item
 */
window.deleteHistoryItem = function(id) {
    event.stopPropagation(); // Prevent triggering history item click
    scanHistory = scanHistory.filter(item => item.id !== id);
    saveScanHistory();
    renderHistory();
}

/**
 * Clear all history
 */
function clearAllHistory() {
    if (confirm('Are you sure you want to clear all scan history?')) {
        scanHistory = [];
        saveScanHistory();
        renderHistory();
    }
}

/**
 * Get time ago string
 */
function getTimeAgo(date) {
    const seconds = Math.floor((new Date() - date) / 1000);
    
    if (seconds < 60) return 'Just now';
    
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `${minutes}m ago`;
    
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours}h ago`;
    
    const days = Math.floor(hours / 24);
    if (days < 7) return `${days}d ago`;
    
    return date.toLocaleDateString();
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}
