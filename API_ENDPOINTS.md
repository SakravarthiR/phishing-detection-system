# API Endpoints & Usage - Detailed Documentation

## Table of Contents
1. [Authentication](#authentication)
2. [Phishing Scan](#phishing-scan)
3. [Subdomain Scan](#subdomain-scan)
4. [Health Check](#health-check)
5. [API Response Examples](#api-response-examples)

---

## Authentication

### POST `/api/login`
- **Description:** Authenticates user and returns a JWT token.
- **Request Body:**
  ```json
  {
    "username": "user",
    "password": "password"
  }
  ```
- **Response:**
  ```json
  {
    "token": "<jwt_token>"
  }
  ```
- **Notes:**
  - Token is required for all protected endpoints.
  - Token expires after 24 hours.

---

## Phishing Scan

### POST `/api/scan`
- **Description:** Scans a URL for phishing threats using ML, heuristics, and PhishTank.
- **Headers:**
  - `Authorization: Bearer <jwt_token>`
- **Request Body:**
  ```json
  {
    "url": "https://example.com"
  }
  ```
- **Response:**
  ```json
  {
    "url": "https://example.com",
    "label": 0,
    "prediction": "legitimate",
    "probability": 0.02,
    "probability_percent": 2.0,
    "reason": "APPEARS LEGITIMATE - No suspicious features detected.",
    "features": { ... },
    "website_status": { ... }
  }
  ```
- **Notes:**
  - `label`: 0 = legitimate, 1 = phishing
  - `probability`: Confidence score (0.0 to 1.0)
  - `features`: Detailed feature breakdown
  - `website_status`: Live status, SSL info, etc.

---

## Subdomain Scan

### POST `/api/subdomain-scan`
- **Description:** Discovers subdomains for a given domain.
- **Headers:**
  - `Authorization: Bearer <jwt_token>`
- **Request Body:**
  ```json
  {
    "domain": "example.com"
  }
  ```
- **Response:**
  ```json
  {
    "subdomains": [
      "mail.example.com",
      "login.example.com"
    ]
  }
  ```

---

## Health Check

### GET `/api/health`
- **Description:** Returns API health status.
- **Response:**
  ```json
  {
    "status": "ok"
  }
  ```

---

## API Response Examples

### Phishing Detected
```json
{
  "url": "http://192.168.1.1/login-verify-account",
  "label": 1,
  "prediction": "phishing",
  "probability": 0.99,
  "probability_percent": 99.0,
  "reason": "⚠️ VERIFIED PHISHING by PhishTank | Target: PayPal | Phish ID: 123456",
  "features": { ... },
  "website_status": { ... },
  "phishtank_verified": true,
  "phishtank_data": {
    "phish_id": 123456,
    "target": "PayPal",
    "submission_time": "2026-02-01T12:00:00Z",
    "verification_time": "2026-02-01T13:00:00Z",
    "detail_url": "https://phishtank.com/phish_detail.php?phish_id=123456"
  }
}
```

### Legitimate Site
```json
{
  "url": "https://www.google.com",
  "label": 0,
  "prediction": "legitimate",
  "probability": 0.01,
  "probability_percent": 1.0,
  "reason": "APPEARS LEGITIMATE - No suspicious features detected.",
  "features": { ... },
  "website_status": { ... }
}
```

---

For more details, see the code in `secure_api.py` and the frontend JS modules for request/response handling.