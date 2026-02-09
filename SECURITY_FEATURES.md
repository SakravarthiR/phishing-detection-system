# Security Features & Protections - Detailed Documentation

## Table of Contents
1. [Authentication & Authorization](#authentication--authorization)
2. [Password Security](#password-security)
3. [Multi-Factor Authentication (MFA)](#multi-factor-authentication-mfa)
4. [Rate Limiting & DDoS Protection](#rate-limiting--ddos-protection)
5. [Input Sanitization & Validation](#input-sanitization--validation)
6. [Threat Intelligence Integration](#threat-intelligence-integration)
7. [Session Management](#session-management)
8. [Security Headers & File Protections](#security-headers--file-protections)
9. [Logging & Monitoring](#logging--monitoring)

---

## Authentication & Authorization
- **JWT (JSON Web Token):**
  - Used for stateless authentication.
  - Token issued on login, stored in localStorage, expires after 24 hours.
  - All protected API endpoints require a valid JWT.
- **Role-based access:**
  - Admin endpoints require elevated privileges (future extension).

## Password Security
- **bcrypt Hashing:**
  - All user passwords are hashed with bcrypt before storage.
  - No plaintext passwords are ever stored or transmitted.
- **Password Strength Scoring:**
  - Enforced via `PasswordSecurity` class (length, variety, uniqueness).
  - Weak passwords are rejected at registration.

## Multi-Factor Authentication (MFA)
- **TOTP (Time-based One-Time Password):**
  - Optional for users, enforced for admins.
  - TOTP secrets generated and verified using `TOTPManager`.
  - Backup codes provided for account recovery.

## Rate Limiting & DDoS Protection
- **Per-IP Rate Limiting:**
  - 30 requests/minute per IP (configurable).
  - Implemented via Flask-Limiter and custom logic in `advanced_security.py`.
- **DDoS Protection:**
  - Tracks request rates, concurrent connections, and attack patterns.
  - IPs exceeding limits are temporarily or permanently blocked.
  - IP whitelisting for trusted sources (e.g., localhost).

## Input Sanitization & Validation
- **Strict input validation:**
  - All user inputs (URLs, domains, credentials) are sanitized.
  - Prevents XSS, SQL injection, and command injection.
- **Output encoding:**
  - All user-facing outputs are properly encoded to prevent injection attacks.

## Threat Intelligence Integration
- **PhishTank Database:**
  - URLs checked against PhishTank for known phishing threats.
  - PhishTank DB auto-updates every 6 hours.
- **Heuristic & ML-based detection:**
  - 40+ features and rule-based overrides catch new/unknown threats.

## Session Management
- **JWT expiry:**
  - Tokens expire after 24 hours, requiring re-authentication.
- **Session auto-logout:**
  - Expired or invalid tokens trigger logout and redirect to login page.
- **Device fingerprinting:**
  - Optionally used to detect new or suspicious devices.

## Security Headers & File Protections
- **Strict security headers:**
  - CORS, Content-Type, X-Frame-Options, X-XSS-Protection, etc.
- **No backend file exposure:**
  - Sensitive files and environment variables are hidden from public access.
- **HTTPS enforced in production:**
  - All API and frontend traffic is encrypted.

## Logging & Monitoring
- **Security event logging:**
  - All login attempts, failed logins, and suspicious activities are logged.
- **Audit trails:**
  - Key security events are recorded for future review.
- **Monitoring:**
  - Health checks and error logs for system monitoring.

---

For more details, see the `good_security.py`, `advanced_security.py`, and `secure_api.py` modules. Security is enforced at every layer of the application, following best practices for modern web apps.