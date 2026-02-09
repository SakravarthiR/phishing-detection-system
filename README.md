Phishing Detection System

Hey hii this my phishing detection project i make this for my college and for learning machine learnig also. It detect fake and phishing links and give u safe or not safe result. 😅

About

So i make this project coz phishing is like super danger now days and many people get fooled by fake website and link. I want to make somthing which use AI and ML to find that scam link fast.

I am just 1st yr student, but i learn python and flask littile bit and i try to make something real one not just theory.

What it Do

Scan the url u give and check many rule like 40+ things

It see in PhishTank data base also (they have 15k+ bad sites)

Check if url have sus things like “@” or too much dot

Check sub domain also if it fake

Have Ddos protect also coz one time i crash my server lol

Features
Smart detect

ML model trained on 11k urls (took too much time 😭)

Detect type like g00gle.com instead of google.com

Detect fake domain (.tk .ml and all)

Give confidence score like how sure the model is

Threat Database

I use PhishTank free api

It auto update every 6 hr

Show who target site and when it added

Security

JWT token for login

Rate limit (so nobody spam my api)

Ddos protect

XSS and SQL injection block

IP whitelist for localhost test

Tech stack

Backend:
Python 3.11, Flask 3.0, Scikit Learn, JWT, Gunicorn

Frontend:
HTML, JS (no react only pure js), CSS3 with glass look

Infra:
Ubuntu server, Nginx, LetsEncrypt SSL, systemd service

Security part:
bcrypt password hash, headers protect, input check etc.

How it Work
1. User put url in site  
2. Frontend send it with token to backend  
3. Backend check phishtank, rules, and ML model  
4. Give result back with confidence  
5. Show Safe / Suspicious / Danger


Model check many thing like length, dots, symbol, age of domain, tld like .com or .tk, ssl valid or not etc.

Setup (for run local)
[//]
# Phishing Detection System - Comprehensive Documentation

## Table of Contents
1. Introduction
2. System Architecture
3. Technology Stack
4. Algorithms & Detection Logic
5. Security Features & Best Practices
6. API Design & Endpoints
7. Frontend Structure & User Flow
8. Deployment & Infrastructure
9. Maintenance & Operations
10. Glossary

---

## 1. Introduction

The Phishing Detection System is a full-stack, production-grade platform for detecting, analyzing, and mitigating phishing threats. It leverages advanced machine learning, heuristic analysis, and real-time threat intelligence to provide robust protection. Designed for extensibility, security, and clarity, it is suitable for both enterprise and educational use.

---


## 2. System Architecture

### High-Level Overview
- **Backend (API & ML Engine):** Python (Flask), scikit-learn, custom security modules
- **Frontend (UI):** HTML5, Vanilla JavaScript, CSS3 (no frameworks)
- **Infrastructure:** Ubuntu, Nginx, Gunicorn, LetsEncrypt SSL, systemd, UFW firewall

### Architecture Diagram

```mermaid
graph TD
		A[User (Browser)] -->|1. Submit URL| B[Frontend (HTML/JS)]
		B -->|2. API Request (JWT)| C[Backend API (Flask)]
		C -->|3. Auth & Security Checks| D[Security Middleware]
		D -->|4. Threat Intel| E[PhishTank Integration]
		D -->|5. Feature Extraction| F[Feature Extractor]
		F -->|6. ML Prediction| G[Random Forest Model]
		D -->|7. Heuristic Rules| H[Heuristic Engine]
		G -->|8. Result| I[Result Aggregator]
		H -->|8. Result| I
		E -->|8. Result| I
		I -->|9. Response| B
		B -->|10. Display Result| A
		C -->|Optional: Subdomain Scan| J[Subdomain Scanner]
		J -->|Results| I
		C -->|Memory Mgmt| K[Memory Optimizer]
		D -->|DDoS/Rate Limiting| L[Advanced Security]
```

### Data Flow
1. User submits a URL via the frontend.
2. Frontend sends request (with JWT) to backend `/api/scan`.
3. Backend authenticates, checks PhishTank, extracts features, runs ML, applies heuristics.
4. Backend returns result, explanation, and feature breakdown.
5. Frontend displays result and explanation to user.

### Backend Modules
- `secure_api.py`: Flask API, routing, authentication, middleware
- `phish_detector.py`: ML model, feature extraction, prediction
- `good_security.py`: Passwords, TOTP MFA, device trust, anomaly detection
- `advanced_security.py`: DDoS, rate limiting, IP whitelisting
- `subdomain_scanner.py`: Subdomain discovery (DNS, SSL, brute-force)
- `phishtank_integration.py`: PhishTank sync/query
- `memory_optimizer.py`: Memory management

---

## 4. Algorithms & Detection Logic

### 4.1 Feature Extraction (`phish_detector.py`)
- **40+ Features:**
	- URL length, number of dots/hyphens, special characters
	- Use of IP address, suspicious TLDs, URL encoding
	- Entropy (Shannon), subdomain patterns, port numbers
	- Path analysis, URL shorteners, punycode, brand typosquatting
- **Implementation:**
	- Regex, tldextract, custom entropy calculation, DNS lookups

### 4.2 Machine Learning (How ML Works)
- **Model:** Random Forest Classifier (scikit-learn)
- **Training Data:** 11,000+ labeled URLs (legitimate and phishing)
- **Feature Vector:** Each URL is converted to a vector of 40+ numerical/categorical features.
- **Training:**
	- The Random Forest is trained on labeled data, learning patterns that distinguish phishing from legitimate URLs.
	- Model is serialized with joblib and loaded at API startup.
- **Prediction Flow:**
	1. Extract features from input URL.
	2. Pass feature vector to Random Forest model.
	3. Model outputs label (0=legit, 1=phishing) and probability/confidence score.
	4. If critical heuristic rules are triggered (see below), they override the ML result for safety.
- **Why Random Forest?**
	- Handles high-dimensional, mixed-type data well.
	- Robust to overfitting, interpretable feature importances.
	- Fast inference for real-time API use.

### 4.3 Heuristic Rules
- **Overrides ML if triggered:**
	- Raw IP in URL
	- "@" symbol in URL
	- Punycode, suspicious TLDs, excessive hyphens
	- Known URL shorteners
- **Purpose:** Catch obvious phishing missed by ML, reduce false negatives

### 4.4 Threat Intelligence
- **PhishTank Integration:**
	- Syncs every 6 hours (cron/systemd timer)
	- Local cache for fast lookup
	- If URL found, immediately flagged as phishing

### 4.5 Subdomain Scanning (`subdomain_scanner.py`)
- **Techniques:**
	- DNS A/CNAME/MX lookups
	- SSL certificate transparency logs
	- Brute-force with wordlists
	- Cloudflare detection, zone transfer attempts

### 4.6 Password & MFA Security (`good_security.py`)
- **Password Strength:** Length, variety, uniqueness, blacklist check
- **MFA:** TOTP (RFC 6238), pyotp, QR code provisioning
- **Device Trust:** Fingerprinting (UA, IP, device ID), anomaly detection
- **Account Lockout:** After N failed attempts, time-based lock

### 4.7 DDoS & Rate Limiting (`advanced_security.py`)
- **Per-IP Rate Limiting:** 30 requests/minute (configurable)
- **DDoS Protection:** Request tracking, IP blocklist/whitelist
- **Implementation:** In-memory counters, persistent blocklist

---

## 3. Technology Stack

### Backend
- **Language:** Python 3.11
- **Framework:** Flask 3.0
- **ML:** scikit-learn (Random Forest), joblib (model serialization)
- **Security:** bcrypt, PyJWT, pyotp
- **Web Server:** Gunicorn (WSGI)
- **Threat Intelligence:** PhishTank API, local cache

### Frontend
- **HTML5, CSS3:** Responsive, glassmorphism UI
- **JavaScript:** Vanilla JS (no frameworks)
- **Security:** Input validation, HTTPS-only requests, JWT in localStorage

### Infrastructure
- **OS:** Ubuntu 20.04+
- **Web Server:** Nginx (reverse proxy, SSL, static files)
- **SSL:** LetsEncrypt (auto-renew)
- **Firewall:** UFW (ports 80/443 only)
- **Process Management:** systemd

---

## 4. Algorithms & Detection Logic

### 4.1 Feature Extraction (`phish_detector.py`)
- **40+ Features:**
	- URL length, number of dots/hyphens, special characters
	- Use of IP address, suspicious TLDs, URL encoding
	- Entropy (Shannon), subdomain patterns, port numbers
	- Path analysis, URL shorteners, punycode, brand typosquatting
- **Implementation:**
	- Regex, tldextract, custom entropy calculation, DNS lookups

### 4.2 Machine Learning
- **Model:** Random Forest Classifier (scikit-learn)
- **Training:** 11,000+ labeled URLs (legit/phishing)
- **Input:** Feature vector from extractor
- **Output:** Label (0=legit, 1=phishing), probability/confidence
- **Model Storage:** joblib serialization, loaded at API startup

### 4.3 Heuristic Rules
- **Overrides ML if triggered:**
	- Raw IP in URL
	- "@" symbol in URL
	- Punycode, suspicious TLDs, excessive hyphens
	- Known URL shorteners
- **Purpose:** Catch obvious phishing missed by ML, reduce false negatives

### 4.4 Threat Intelligence
- **PhishTank Integration:**
	- Syncs every 6 hours (cron/systemd timer)
	- Local cache for fast lookup
	- If URL found, immediately flagged as phishing

### 4.5 Subdomain Scanning (`subdomain_scanner.py`)
- **Techniques:**
	- DNS A/CNAME/MX lookups
	- SSL certificate transparency logs
	- Brute-force with wordlists
	- Cloudflare detection, zone transfer attempts

### 4.6 Password & MFA Security (`good_security.py`)
- **Password Strength:** Length, variety, uniqueness, blacklist check
- **MFA:** TOTP (RFC 6238), pyotp, QR code provisioning
- **Device Trust:** Fingerprinting (UA, IP, device ID), anomaly detection
- **Account Lockout:** After N failed attempts, time-based lock

### 4.7 DDoS & Rate Limiting (`advanced_security.py`)
- **Per-IP Rate Limiting:** 30 requests/minute (configurable)
- **DDoS Protection:** Request tracking, IP blocklist/whitelist
- **Implementation:** In-memory counters, persistent blocklist

---

## 5. Security Features & Best Practices

- **JWT Authentication:**
	- 24hr expiry, signed with strong secret
	- Stored in localStorage (frontend)
- **Password Hashing:** bcrypt (salted, 12+ rounds)
- **TOTP MFA:** Optional, enforced for admins
- **Rate Limiting:** Per-IP, prevents brute-force/API abuse
- **DDoS Protection:** Request tracking, IP blocking, whitelisting
- **Input Sanitization:**
	- All user input validated (backend & frontend)
	- Prevents XSS, SQLi, command injection
- **Security Headers:**
	- Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options, Content-Security-Policy
- **No Backend File Exposure:**
	- Nginx blocks access to backend files, .env, etc.
- **HTTPS Only:**
	- All API and frontend requests over HTTPS
- **Environment Variables:**
	- Secrets, DB paths, and API keys stored in `.env` (never committed)
- **Logging & Monitoring:**
	- Logs all auth, scan, and error events
	- Monitors for suspicious activity

---

## 6. API Design & Endpoints

### Authentication
- `POST /api/login` — Authenticates user, returns JWT
	- Input: `{ username, password }`
	- Output: `{ token }`

### Phishing Scan
- `POST /api/scan` — Scans URL, returns result
	- Headers: `Authorization: Bearer <jwt_token>`
	- Input: `{ url }`
	- Output: `{ label, prediction, probability, reason, features, website_status }`

### Subdomain Scan
- `POST /api/subdomain-scan` — Discovers subdomains
	- Headers: `Authorization: Bearer <jwt_token>`
	- Input: `{ domain }`
	- Output: `{ subdomains: [ ... ] }`

### Health Check
- `GET /api/health` — Returns `{ status: "ok" }`

### Error Handling
- All errors return JSON with `error` and `message` fields
- Custom error pages: 403, 404, 500 (frontend)

---

## 7. Frontend Structure & User Flow

### Files
- `index.html`: Main entry, URL input, result display
- `app.js`: Auth, form handling, API calls, result rendering
- `auth-secure.js`: Login, JWT storage, session expiry
- `discovery-engine.js`: Subdomain scan UI
- `auth-portal-styles.css`, `professional.css`: Modern, glassmorphism UI
- `secure-auth-portal.html`: Login page
- `phishing-detector.html`: Standalone scan page
- `403.html`, `404.html`, `500.html`: Error pages

### User Flow
1. User visits site, redirected to login if not authenticated
2. On login, JWT stored in localStorage
3. User enters URL, submits scan
4. Result (Safe/Suspicious/Danger) with explanation displayed
5. User can scan for subdomains
6. Session expiry and logout handled automatically

### Security
- JWT checked on every page load and API request
- All API requests use HTTPS
- Input validation on all forms
- No sensitive data in frontend code

---

## 8. Deployment & Infrastructure

### Local Setup
1. Clone repo
2. `python -m venv .venv && source .venv/bin/activate`
3. `pip install -r backend/requirements.txt`
4. Copy `.env.example` to `.env`, set secrets
5. `python backend/secure_api.py`
6. Open `frontend/index.html` in browser

### Production
- Use `deploy.sh` for Ubuntu VPS
- Nginx as reverse proxy, SSL, static files
- Gunicorn for backend
- LetsEncrypt SSL (auto-renew)
- UFW firewall (ports 80/443 only)
- systemd for process management

### Security Checklist
- [x] No backend files exposed
- [x] Env variables hidden
- [x] HTTPS enforced
- [x] Firewall enabled
- [x] PhishTank DB auto-updates
- [x] Rate limiting & DDoS protection
- [x] JWT expiry, bcrypt passwords
- [x] Security headers

---

## 9. Maintenance & Operations
- **PhishTank DB:** Auto-updates every 6 hours
- **Dependencies:** Regularly update via `pip install --upgrade -r backend/requirements.txt`
- **SSL:** LetsEncrypt auto-renew (check cron/systemd)
- **Logs:** Monitor for errors, suspicious activity
- **Backups:** Regularly back up config, user data, and `.env`

---

## 10. Glossary
- **Phishing:** Fraudulent attempt to obtain sensitive info
- **Random Forest:** Ensemble ML classifier
- **Feature Extraction:** Converting raw URL to numerical features
- **Heuristic Rule:** Manually defined logic for obvious phishing
- **JWT:** Secure, stateless authentication token
- **TOTP:** Time-based One-Time Password for MFA
- **DDoS:** Distributed Denial of Service attack
- **Punycode:** Encoding for internationalized domain names
- **Entropy:** Measure of randomness in domain names

---

For code details, see comments in backend modules and frontend JS. Designed for clarity, security, and extensibility. For interview/demo: Emphasizes security, modularity, and production-readiness.