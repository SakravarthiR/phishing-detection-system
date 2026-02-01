/**
 * Scanner page logic - handles URL scanning and subdomain checks.
 * 
 * Added the parallax effect because why not, makes it look cooler.
 * The subdomain scanner was inspired by c99.nl but way more integrated.
 */

// 3D Parallax Background Effect for Scanner + Interactive Button Animation + Cursor Circle
// Consolidated mouse handlers to prevent memory leaks from duplicate listeners
(() => {
    const parallaxBg = document.querySelector('.parallax-bg-scanner');
    const cursorCircle = document.querySelector('.cursor-circle');
    const buttons = document.querySelectorAll('.scanner-link-btn, .back-to-phishing-btn');
    
    // Single mousemove handler for all effects
    function handleMouseMove(e) {
        // Parallax effect
        if (parallaxBg) {
            const mouseX = e.clientX / window.innerWidth;
            const mouseY = e.clientY / window.innerHeight;
            const moveX = (mouseX - 0.5) * 40;
            const moveY = (mouseY - 0.5) * 40;
            parallaxBg.style.transform = `translate(${moveX}px, ${moveY}px) scale(1.05)`;
        }
        
        // Cursor circle tracking
        if (cursorCircle) {
            cursorCircle.style.left = (e.pageX - 20) + 'px';
            cursorCircle.style.top = (e.pageY - 20) + 'px';
        }
        
        // Button tilt effect
        buttons.forEach(btn => {
            const rect = btn.getBoundingClientRect();
            const btnCenterX = rect.left + rect.width / 2;
            const btnCenterY = rect.top + rect.height / 2;
            
            const distX = e.clientX - btnCenterX;
            const distY = e.clientY - btnCenterY;
            const distance = Math.sqrt(distX * distX + distY * distY);
            
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
    }
    
    // Mouseleave handler
    function handleMouseLeave() {
        buttons.forEach(btn => {
            btn.style.transform = 'translate(0px, 0px) rotate3d(0, 0, 0, 0deg)';
            const span = btn.querySelector('span');
            if (span) {
                span.style.transform = 'translate(0px, 0px)';
            }
        });
        
        if (cursorCircle) {
            cursorCircle.classList.remove('active');
        }
        if (document.body) {
            document.body.classList.remove('mix-blend-active');
        }
    }
    
    // Register handlers (will be tracked by app.js)
    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('mouseleave', handleMouseLeave);
    
    // Add button-specific hover effects
    buttons.forEach(btn => {
        btn.addEventListener('mouseenter', function() {
            if (cursorCircle) {
                cursorCircle.classList.add('active');
                document.body.classList.add('mix-blend-active');
            }
        });
        
        btn.addEventListener('mouseleave', function() {
            if (cursorCircle) {
                cursorCircle.classList.remove('active');
            }
            if (document.body) {
                document.body.classList.remove('mix-blend-active');
            }
        });
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
    
    // Production deployment
    return 'https://phishing-detection-system-1.onrender.com';
}

const API_BASE_URL = getAPIURL();
const REQUEST_TIMEOUT = 120000; // 2 minutes for subdomain scanning
const USE_SECURE_API = true; // Set to true to enable JWT auth

console.log('[+] API URL: ' + API_BASE_URL);
console.log('[+] Environment: ' + window.location.hostname);

// DOM Elements
let domainInput, scanBtn, btnText, btnLoader;
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
    btnText = document.getElementById('scanBtnText');
    btnLoader = document.getElementById('scanBtnLoader');
    
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
    
    // Add logout button listener
    const logoutBtnScanner = document.getElementById('logoutBtnScanner');
    if (logoutBtnScanner) {
        logoutBtnScanner.addEventListener('click', logout);
    }
    
    // Add retry button listener
    const retryBtn = document.getElementById('retryBtn');
    if (retryBtn) {
        retryBtn.addEventListener('click', function() { location.reload(); });
    }
    
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
        alert('Please enter a domain');
        return;
    }
    
    // Strip out http://, www., and any path stuff
    const cleanDomain = domain
        .replace(/^https?:\/\//, '')
        .replace(/^www\./, '')
        .split('/')[0];
    
    // Update UI - show loading immediately
    hideError();
    hideResults();
    showLoading();
    
    try {
        const result = await scanSubdomains(cleanDomain);
        displayResults(result);
        
    } catch (error) {
        console.error('[ERROR] Scan failed:', error);
        showError(error.message);
    } finally {
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
            if (!token) {
                console.warn('[!] No auth token found - redirecting to login');
                window.location.href = '/secure-auth-portal.html';
                throw new Error('Authentication required - please login first');
            }
            headers['Authorization'] = `Bearer ${token}`;
            console.log('[+] Auth token added to request');
            console.log('[DEBUG] Token:', token.substring(0, 50) + '...');
        }
        
        console.log(`[>] Making request to ${API_BASE_URL}/scan-subdomains`);
        console.log('[DEBUG] Full URL:', `${API_BASE_URL}/scan-subdomains`);
        console.log('[DEBUG] Headers:', headers);
        const response = await fetch(`${API_BASE_URL}/scan-subdomains`, {
            method: 'POST',
            headers: headers,
            body: JSON.stringify({ url: domain }),
            signal: controller.signal
        });
        
        clearTimeout(timeoutId);
        
        console.log(`[*] Response status: ${response.status}`);
        
        // If auth fails, kick them back to login
        if (response.status === 401 && USE_SECURE_API) {
            console.warn('Token expired or invalid - back to login you go');
            window.location.href = '/secure-auth-portal.html';
            throw new Error('Authentication required - please login again');
        }
        
        if (!response.ok) {
            let errorMessage = 'Scan failed';
            try {
                const errorData = await response.json();
                errorMessage = errorData.message || errorData.error || 'Scan failed';
            } catch (parseError) {
                console.warn('Could not parse error response:', parseError);
                errorMessage = `HTTP ${response.status}: ${response.statusText}`;
            }
            throw new Error(errorMessage);
        }
        
        const data = await response.json();
        console.log('[+] Scan completed successfully');
        return data;
        
    } catch (error) {
        if (error.name === 'AbortError') {
            console.error('[!] Request timeout');
            throw new Error('Scan took too long (2 minutes) - probably a huge domain with tons of subdomains');
        }
        console.error('[!] Scan error:', error.message);
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
        const p = document.createElement('p');
        p.style.textAlign = 'center';
        p.style.color = '#6b7280';
        p.style.padding = '2rem';
        p.textContent = 'No IP statistics available';
        ipStatsList.appendChild(p);
        return;
    }
    
    // Show top 10 IPs
    const topIps = Object.entries(ipStats).slice(0, 10);
    
    topIps.forEach(([ip, count]) => {
        const item = document.createElement('div');
        item.className = 'ip-stat-item';
        
        const addrSpan = document.createElement('span');
        addrSpan.className = 'ip-stat-address';
        addrSpan.textContent = ip;
        
        const countSpan = document.createElement('span');
        countSpan.className = 'ip-stat-count';
        countSpan.textContent = count + 'x';
        
        item.appendChild(addrSpan);
        item.appendChild(countSpan);
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
        if (subdomains && subdomains.length > 0) {
            tableCount.textContent = subdomains.length + ' result' + (subdomains.length !== 1 ? 's' : '');
        } else {
            tableCount.textContent = '0 results';
        }
    }
    
    if (!subdomains || subdomains.length === 0) {
        const row = document.createElement('tr');
        const cell = document.createElement('td');
        cell.colSpan = 5;
        cell.style.textAlign = 'center';
        cell.style.padding = '3rem';
        cell.style.color = '#94a3b8';
        cell.style.fontSize = '1.1rem';
        
        const icon = document.createElement('div');
        icon.style.opacity = '0.5';
        icon.style.marginBottom = '0.5rem';
        icon.style.fontSize = '3rem';
        icon.textContent = '?';
        
        const title = document.createElement('div');
        title.style.fontWeight = '600';
        title.textContent = 'No subdomains found';
        
        const hint = document.createElement('div');
        hint.style.fontSize = '0.9rem';
        hint.style.marginTop = '0.5rem';
        hint.textContent = 'Try scanning a different domain';
        
        cell.appendChild(icon);
        cell.appendChild(title);
        cell.appendChild(hint);
        row.appendChild(cell);
        subdomainTableBody.appendChild(row);
        return;
    }
    
    subdomains.forEach((sub, index) => {
        const row = document.createElement('tr');
        
        const numCell = document.createElement('td');
        numCell.textContent = (index + 1).toString();
        
        const nameCell = document.createElement('td');
        const nameSpan = document.createElement('span');
        nameSpan.className = 'advanced-subdomain-name';
        nameSpan.textContent = sub.subdomain || '';
        nameCell.appendChild(nameSpan);
        
        const fullCell = document.createElement('td');
        const fullSpan = document.createElement('span');
        fullSpan.className = 'advanced-subdomain-full';
        fullSpan.textContent = sub.full_domain || '';
        fullCell.appendChild(fullSpan);
        
        const ipCell = document.createElement('td');
        const ipSpan = document.createElement('span');
        ipSpan.className = 'advanced-subdomain-ip';
        ipSpan.textContent = sub.ip || 'N/A';
        ipCell.appendChild(ipSpan);
        
        const cfCell = document.createElement('td');
        cfCell.style.textAlign = 'center';
        const cfSpan = document.createElement('span');
        cfSpan.className = 'cloudflare-status ' + (sub.cloudflare || '');
        cfSpan.textContent = sub.cloudflare || '';
        cfCell.appendChild(cfSpan);
        
        row.appendChild(numCell);
        row.appendChild(nameCell);
        row.appendChild(fullCell);
        row.appendChild(ipCell);
        row.appendChild(cfCell);
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
    scanBtn.disabled = true;
    btnText.style.display = 'none';
    btnLoader.classList.remove('hidden');
    loadingSection.classList.remove('hidden');
}

/**
 * Hide loading state
 */
function hideLoading() {
    scanBtn.disabled = false;
    btnText.style.display = 'inline';
    btnLoader.classList.add('hidden');
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
    
    // Also add to localStorage for the table display
    addScanToHistory(scanData.domain, scanData.subdomain_count, scanData.scan_time * 1000);
    renderHistory();
}

/**
 * Render scan history - DISABLED (using new table format instead)
 */
function renderHistory() {
    // Old card-based history display disabled
    // New table display is handled by updateScanHistoryDisplay()
    return;
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
        try {
            // Add animation to button
            const clearBtn = document.getElementById('clearHistoryBtn');
            if (clearBtn && !clearBtn.classList.contains('delete')) {
                clearBtn.classList.add('delete');
            }
            
            // Clear history after animation starts
            setTimeout(() => {
                localStorage.removeItem(HISTORY_KEY);
                updateScanHistoryDisplay();
                console.log('[+] All scan history cleared');
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

/**
 * Scan History Management
 */
const HISTORY_KEY = 'subdomain_scan_history';
const MAX_HISTORY_ITEMS = 20;

function addScanToHistory(domain, foundCount, scanTimeMs) {
    try {
        let history = JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
        
        // Check if this domain already exists in history
        const duplicateIndex = history.findIndex(item => item.fullDomain === domain);
        
        // If duplicate exists, remove it (we'll add it again at the top)
        if (duplicateIndex !== -1) {
            history.splice(duplicateIndex, 1);
            console.log('[+] Removed duplicate domain from history:', domain);
        }
        
        const entry = {
            domain: domain.substring(0, 25) + (domain.length > 25 ? '...' : ''),
            found: foundCount,
            scanTime: Math.round(scanTimeMs / 1000),
            timestamp: new Date().toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'}),
            fullDomain: domain,
            // Store scan data for later display
            scanData: {
                subdomain_count: foundCount,
                scan_time: scanTimeMs / 1000
            }
        };
        
        history.unshift(entry);
        history = history.slice(0, MAX_HISTORY_ITEMS);
        
        localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
        updateScanHistoryDisplay();
        
    } catch (e) {
        console.error('Error adding to scan history:', e);
    }
}

function updateScanHistoryDisplay() {
    try {
        const history = JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
        const historyTableBody = document.getElementById('historyTableBody');
        const historyTableContainer = document.querySelector('.history-table-container-scanner');
        const historySidebar = document.querySelector('.scan-history-sidebar-main');
        
        if (!historyTableBody) return;
        
        // Clear table
        historyTableBody.innerHTML = '';
        
        // Get empty state element
        const historyList = document.getElementById('historyList');
        const emptyState = historyList ? historyList.querySelector('.history-empty') : null;
        
        if (history.length === 0) {
            // Hide entire sidebar when no history
            if (historySidebar) {
                historySidebar.style.display = 'none';
            }
            return;
        }
        
        // Show sidebar and hide empty state when history exists
        if (historySidebar) {
            historySidebar.style.display = 'block';
        }
        if (emptyState) {
            emptyState.style.display = 'none';
        }
        if (historyTableContainer) {
            historyTableContainer.style.display = 'block';
        }
        
        // Build table rows safely
        history.forEach((item, index) => {
            const row = document.createElement('tr');
            row.title = 'Click to view: ' + item.fullDomain + ' - Found ' + item.found + ' subdomains';
            
            const domainCell = document.createElement('td');
            domainCell.className = 'scan-domain';
            domainCell.textContent = item.domain;
            domainCell.style.cursor = 'pointer';
            domainCell.onclick = function() { displayScanHistory(index); };
            
            const deleteCell = document.createElement('td');
            deleteCell.className = 'scan-delete-btn';
            deleteCell.textContent = '✕';
            deleteCell.title = 'Delete this scan';
            deleteCell.style.cursor = 'pointer';
            deleteCell.style.textAlign = 'center';
            deleteCell.onclick = function(e) { 
                e.stopPropagation();
                deleteScanHistoryItem(index); 
            };
            
            row.appendChild(domainCell);
            row.appendChild(deleteCell);
            historyTableBody.appendChild(row);
        });
        
    } catch (e) {
        console.error('Error updating scan history display:', e);
    }
}

function displayScanHistory(index) {
    try {
        const history = JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
        const item = history[index];
        
        if (!item) return;
        
        console.log('[+] Displaying scan history:', item);
        console.log('[>] Domain: ' + item.fullDomain);
        console.log('[>] Subdomains found: ' + item.found);
        console.log('[>] Scan time: ' + item.scanTime + 's');
        
        // Hide input and loading sections, show results
        const inputSection = document.querySelector('.scanner-input-section');
        const loadingSection = document.getElementById('loadingSection');
        const resultsSection = document.getElementById('resultsSection');
        
        if (inputSection) inputSection.classList.add('hidden');
        if (loadingSection) loadingSection.classList.add('hidden');
        if (resultsSection) resultsSection.classList.remove('hidden');
        
        // Update domain name
        const domainNameEl = document.getElementById('domainName');
        if (domainNameEl) domainNameEl.textContent = item.fullDomain;
        
        // Update subdomain count
        const subdomainCountEl = document.getElementById('subdomainCount');
        if (subdomainCountEl) subdomainCountEl.textContent = item.found;
        
        // Update scan time
        const scanTimeEl = document.getElementById('scanTime');
        if (scanTimeEl) scanTimeEl.textContent = item.scanTime + 's';
        
        // Display subdomains table
        const resultsTableBody = document.getElementById('resultsTableBody');
        if (resultsTableBody && item.subdomains) {
            resultsTableBody.innerHTML = '';
            item.subdomains.forEach(subdomain => {
                const row = document.createElement('tr');
                row.innerHTML = `<td>${subdomain}</td>`;
                resultsTableBody.appendChild(row);
            });
        }
        
        // Scroll to results
        if (resultsSection) {
            resultsSection.scrollIntoView({ behavior: 'smooth' });
        }
        
    } catch (e) {
        console.error('Error displaying scan history:', e);
    }
}

function deleteScanHistoryItem(index) {
    try {
        const history = JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
        const item = history[index];
        
        if (!item) {
            console.warn('[-] Scan history item not found');
            return;
        }
        
        // Ask for confirmation before deleting
        if (confirm(`Delete scan for: ${item.fullDomain}?`)) {
            history.splice(index, 1);
            localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
            updateScanHistoryDisplay();
            console.log('[+] Scan history item deleted:', item.fullDomain);
        }
    } catch (e) {
        console.error('Error deleting scan history item:', e);
    }
}

function clearScanHistory() {
    if (confirm('Clear all scan history?')) {
        try {
            localStorage.removeItem(HISTORY_KEY);
            updateScanHistoryDisplay();
            console.log('[+] Scan history cleared');
        } catch (e) {
            console.error('Error clearing scan history:', e);
        }
    }
}

// Initialize history on page load
document.addEventListener('DOMContentLoaded', () => {
    updateScanHistoryDisplay();
    
    const clearBtn = document.getElementById('clearHistoryBtn');
    if (clearBtn) {
        clearBtn.addEventListener('click', clearScanHistory);
    }
});

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}

/**
 * Logout function - Clear session and redirect
 */
function logout() {
    try {
        // Clear all phishing detector session data
        localStorage.removeItem('phishing_detector_session');
        
        // Clear session storage
        sessionStorage.clear();
        
        // Redirect to tracking eyes page
        window.location.href = 'tracking-eyes.html';
    } catch (e) {
        console.error('Logout error:', e);
        // Force redirect anyway
        window.location.href = 'tracking-eyes.html';
    }
}
