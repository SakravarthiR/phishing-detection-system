# Backend Modules & Algorithms - Detailed Documentation

## Table of Contents
1. [secure_api.py](#secure_apipy)
2. [phish_detector.py](#phish_detectorpy)
3. [good_security.py](#good_securitypy)
4. [advanced_security.py](#advanced_securitypy)
5. [subdomain_scanner.py](#subdomain_scannerpy)
6. [phishtank_integration.py](#phishtank_integrationpy)
7. [memory_optimizer.py](#memory_optimizerpy)

---

## secure_api.py
- **Purpose:** Main Flask API server. Handles routing, authentication, prediction, and security middleware.
- **Key Functions:**
  - `@app.route('/predict')`: Receives URL, authenticates, checks PhishTank, extracts features, runs ML, applies rules, returns result.
  - `@app.route('/login')`: Authenticates user, returns JWT.
  - `@app.route('/subdomain-scan')`: Triggers subdomain scan.
  - CORS, rate limiting, and security headers applied globally.
  - Loads ML model at startup (`initialize_model`).

## phish_detector.py
- **Purpose:** Core ML engine, feature extraction, model loading, and prediction logic.
- **Key Functions:**
  - `extract_features(url)`: Extracts 40+ features from URL (length, symbols, TLD, entropy, etc.).
  - `predict_url(url, model)`: Runs Random Forest model, applies rule-based overrides, returns label, probability, and features.
  - `get_top_feature(features_dict)`: Explains the most suspicious feature(s) for a given URL.
  - `get_professional_risk_assessment(prob, label, features)`: Returns a detailed risk assessment and recommendations.
  - `load_model()`: Loads the trained ML model from disk.
  - **Algorithms:**
    - Random Forest Classifier (scikit-learn)
    - Heuristic rules for critical red flags
    - Feature extraction using regex, string analysis, and statistical methods

## good_security.py
- **Purpose:** Implements password security, TOTP MFA, device trust, anomaly detection, and account lockout.
- **Key Classes/Functions:**
  - `PasswordSecurity`: Password strength scoring (length, variety, uniqueness)
  - `TOTPManager`: Generates and verifies TOTP codes for MFA
  - `DeviceTrustManager`: Manages trusted devices
  - `AccountLockout`: Locks accounts after repeated failed logins
  - `AnomalyDetector`: Detects suspicious login patterns
  - `SecurityChallenge`: Issues additional challenges for risky logins
  - `enable_mfa`, `verify_mfa`, `is_mfa_enabled`: MFA management

## advanced_security.py
- **Purpose:** DDoS protection, IP whitelisting/blocking, request rate tracking.
- **Key Class:**
  - `DDoSProtection`:
    - `get_client_fingerprint(request)`: Identifies unique clients
    - `is_whitelisted(ip)`, `is_blocked(ip)`: IP allow/block logic
    - `check_request_rate(ip)`: Rate limiting
    - `block_ip(ip, reason)`: Blocks abusive IPs
    - `handle_violation(ip, type)`: Responds to security violations
    - `cleanup_old_data()`: Periodic cleanup
    - `get_security_stats()`: Returns current stats

## subdomain_scanner.py
- **Purpose:** Discovers subdomains using DNS, SSL, and brute-force.
- **Key Class:**
  - `SubdomainScanner`:
    - `check_cloudflare(ip)`: Detects Cloudflare-protected IPs
    - `check_subdomain_exists(sub, base)`: Checks if subdomain is live
    - `get_certificate_subdomains(domain)`: Extracts subdomains from SSL certs
    - `try_dns_zone_transfer(domain)`: Attempts DNS zone transfer
    - `get_dns_records(domain)`: Gathers subdomains from DNS
    - `bruteforce_subdomains(base, wordlist)`: Brute-force discovery

## phishtank_integration.py
- **Purpose:** Syncs and queries PhishTank database for known phishing URLs.
- **Key Functions:**
  - `check_phishtank(url)`: Checks if URL is in PhishTank
  - `get_phishtank_db()`: Loads/syncs PhishTank data (auto-updates every 6 hours)

## memory_optimizer.py
- **Purpose:** Manages memory usage and cleanup for efficient operation.
- **Key Functions:**
  - `cleanup_memory()`: Frees unused memory
  - `get_memory_usage()`: Reports current memory usage
  - `memory_efficient(f)`: Decorator for memory-optimized functions

---

Each module is documented with detailed comments in the code. For algorithm specifics, see the `phish_detector.py` feature extraction and prediction logic, and the `good_security.py` for security mechanisms.
