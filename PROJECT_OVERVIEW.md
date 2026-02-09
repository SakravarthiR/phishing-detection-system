# Phishing Detection System - Full Project Documentation

## Table of Contents
1. [Project Overview](#project-overview)
2. [Backend Architecture](#backend-architecture)
3. [Algorithms & Detection Logic](#algorithms--detection-logic)
4. [Frontend Structure & Flow](#frontend-structure--flow)
5. [Security Features](#security-features)
6. [API Endpoints](#api-endpoints)
7. [Deployment & Infrastructure](#deployment--infrastructure)

---

## Project Overview

This project is a comprehensive phishing detection system that combines machine learning, heuristic rules, and threat intelligence to identify malicious URLs. It is designed for both educational and practical use, providing a secure, scalable, and user-friendly platform for detecting phishing threats.

- **Tech Stack:**
  - Backend: Python 3.11, Flask 3.0, scikit-learn, Gunicorn
  - Frontend: HTML, JavaScript (no frameworks), CSS3
  - Infra: Ubuntu, Nginx, LetsEncrypt SSL, systemd

- **Key Features:**
  - ML-based phishing detection (Random Forest)
  - 40+ handcrafted URL features
  - PhishTank threat intelligence integration
  - Subdomain discovery and analysis
  - JWT authentication, rate limiting, DDoS protection
  - Password strength scoring, TOTP MFA
  - Modern, lightweight frontend

---

## Backend Architecture

### Main Components
- **secure_api.py:** Main Flask API, handles routing, authentication, prediction, and security middleware.
- **phish_detector.py:** Core ML engine, feature extraction, model loading, and prediction logic.
- **good_security.py:** Password security, TOTP MFA, device trust, anomaly detection, and account lockout.
- **advanced_security.py:** DDoS protection, IP whitelisting/blocking, request rate tracking.
- **subdomain_scanner.py:** Discovers subdomains using DNS, SSL, and brute-force.
- **phishtank_integration.py:** Syncs and queries PhishTank database for known phishing URLs.
- **memory_optimizer.py:** Manages memory usage and cleanup for efficient operation.

### Data Flow
1. **User submits URL** via frontend.
2. **API receives request** (`/api/scan`):
   - Authenticates user (JWT)
   - Checks PhishTank for known threats
   - Extracts 40+ features from URL
   - Runs ML model (Random Forest)
   - Applies rule-based overrides for critical red flags
   - Returns result, confidence, and explanation
3. **Frontend displays result** to user.

---

## Algorithms & Detection Logic

### 1. Feature Extraction (`phish_detector.py`)
- Extracts 40+ features, including:
  - URL length, number of dots/hyphens, special characters
  - Use of IP address, suspicious TLDs, URL encoding
  - Entropy, subdomain patterns, port numbers, path analysis
  - Use of URL shorteners, punycode, brand typosquatting

### 2. Machine Learning
- **Random Forest Classifier** (scikit-learn)
  - Trained on 11,000+ labeled URLs
  - Input: Feature vector from URL
  - Output: Label (0=legit, 1=phishing), probability/confidence

### 3. Rule-Based Overrides
- Critical red flags override ML if present:
  - Raw IP in URL
  - "@" symbol in URL
  - Punycode, suspicious TLDs, excessive hyphens
  - Known URL shorteners

### 4. Threat Intelligence
- **PhishTank Integration:**
  - Checks if URL is in PhishTank database
  - If found, immediately flagged as phishing
  - PhishTank DB auto-updates every 6 hours

### 5. Subdomain Scanning (`subdomain_scanner.py`)
- Discovers subdomains via:
  - DNS records
  - SSL certificate transparency logs
  - Brute-force with wordlists
  - Checks for Cloudflare, zone transfers, and more

### 6. Password & MFA Security (`good_security.py`)
- Password strength scoring (length, variety, uniqueness)
- TOTP-based MFA (Time-based One-Time Passwords)
- Device fingerprinting and trust management
- Account lockout and anomaly detection

### 7. DDoS & Rate Limiting (`advanced_security.py`)
- Per-IP rate limiting (e.g., 30 requests/minute)
- DDoS protection via request tracking and IP blocking
- IP whitelisting for trusted sources

---

## Frontend Structure & Flow

- **index.html:** Main entry point, URL input form, result display
- **app.js:** Handles authentication, form submission, API calls, and result rendering
- **auth-secure.js:** Manages login, JWT storage, and session expiry
- **discovery-engine.js:** Handles subdomain scan requests and displays results
- **auth-portal-styles.css / professional.css:** Modern glassmorphism UI, responsive design
- **secure-auth-portal.html:** Login page for secure access
- **phishing-detector.html:** Standalone phishing scan page
- **Error pages:** 403, 404, 500 for user feedback

### User Flow
1. User logs in (JWT stored in localStorage)
2. User enters URL to scan
3. Frontend sends request to backend with JWT
4. Displays result (Safe / Suspicious / Danger) with explanation
5. Optionally, user can scan for subdomains

---

## Security Features

- **JWT Authentication:** Secure login, 24hr expiry, token in localStorage
- **Password Hashing:** bcrypt for all stored passwords
- **TOTP MFA:** Optional two-factor authentication for users
- **Rate Limiting:** Per-IP, prevents API abuse
- **DDoS Protection:** Request tracking, IP blocking, whitelisting
- **Input Sanitization:** Prevents XSS, SQLi, and other injection attacks
- **Security Headers:** Strict headers set for all responses
- **No Backend File Exposure:** Sensitive files and environment variables are hidden

---

## API Endpoints

- **POST `/api/login`**
  - Input: `{ username, password }`
  - Output: `{ token }`
  - Authenticates user, returns JWT

- **POST `/api/scan`**
  - Input: `{ url }`
  - Output: `{ label, prediction, probability, reason, features, website_status }`
  - Scans URL, returns result and explanation

- **POST `/api/subdomain-scan`**
  - Input: `{ domain }`
  - Output: `{ subdomains: [ ... ] }`
  - Returns discovered subdomains

- **GET `/api/health`**
  - Output: `{ status: "ok" }`
  - Health check endpoint

---

## Deployment & Infrastructure

- **Local Setup:**
  1. Clone repo
  2. `python -m venv .venv && source .venv/bin/activate`
  3. `pip install -r backend/requirements.txt`
  4. Copy `.env.example` to `.env`
  5. `python backend/secure_api.py`
  6. Open `frontend/index.html` in browser

- **Production Deployment:**
  - Use provided `deploy.sh` for Ubuntu VPS
  - Installs Nginx, SSL, firewall, and systemd service
  - Backend served via Gunicorn, frontend via Nginx static files

- **Security Checklist:**
  - No backend files exposed
  - Environment variables hidden
  - HTTPS enforced
  - Firewall enabled
  - Regular PhishTank DB updates

---

## Glossary & Definitions

- **Phishing:** Fraudulent attempt to obtain sensitive information by disguising as a trustworthy entity.
- **Random Forest:** An ensemble ML algorithm using multiple decision trees for classification.
- **Feature Extraction:** Process of converting raw URL into numerical features for ML.
- **Heuristic Rule:** Manually defined logic to catch obvious phishing patterns.
- **JWT (JSON Web Token):** Secure token for stateless authentication.
- **TOTP (Time-based One-Time Password):** Algorithm for generating temporary codes for MFA.
- **DDoS (Distributed Denial of Service):** Attack that floods a service with traffic.
- **Punycode:** Encoding for internationalized domain names, often abused for phishing.
- **Entropy:** Measure of randomness, used to detect suspicious domain names.

---

For further details, see the code comments in each backend module and the frontend JS files. This documentation covers all major components and their roles in the project.
