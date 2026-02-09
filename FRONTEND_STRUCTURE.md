# Frontend Structure & Flow - Detailed Documentation

## Table of Contents
1. [File Overview](#file-overview)
2. [Main User Flow](#main-user-flow)
3. [Key JavaScript Modules](#key-javascript-modules)
4. [UI/UX Design](#uiux-design)
5. [Session & Security Handling](#session--security-handling)
6. [Error Handling](#error-handling)

---

## File Overview
- **index.html:** Main entry point, URL input, result display.
- **app.js:** Core logic for authentication, form handling, API calls, and result rendering.
- **auth-secure.js:** Handles login, JWT storage, session expiry, and redirects.
- **discovery-engine.js:** Manages subdomain scan requests and displays results.
- **auth-portal-styles.css / professional.css:** Modern, glassmorphism-inspired UI, responsive design.
- **secure-auth-portal.html:** Login page for secure access.
- **phishing-detector.html:** Standalone phishing scan page.
- **403.html, 404.html, 500.html:** Custom error pages for user feedback.
- **images/**: Contains icons, backgrounds, and branding assets.

---

## Main User Flow
1. **Login:**
   - User visits the site. If not authenticated, redirected to `secure-auth-portal.html`.
   - User enters credentials. On success, JWT is stored in localStorage.
2. **Phishing Scan:**
   - User enters a URL in the form on `index.html`.
   - `app.js` sends the URL and JWT to the backend `/api/scan` endpoint.
   - Receives result: label (safe/suspicious/danger), confidence, explanation, and features.
   - UI displays result with icon, color, and detailed explanation.
3. **Subdomain Scan:**
   - User can enter a domain for subdomain discovery.
   - `discovery-engine.js` sends request to `/api/subdomain-scan` and displays results.
4. **Session Management:**
   - JWT expiry is checked on every page load. Expired sessions redirect to login.
   - Manual logout clears session and redirects.

---

## Key JavaScript Modules
- **app.js:**
  - Handles DOMContentLoaded event to initialize app.
  - Manages authentication check, form submission, and API communication.
  - Parses and displays API responses, including error handling.
  - Implements request batching for high concurrency.
- **auth-secure.js:**
  - Manages login form, JWT storage, and session expiry.
  - Handles redirects for unauthenticated or expired sessions.
- **discovery-engine.js:**
  - Handles subdomain scan form and API calls.
  - Renders subdomain results in a user-friendly format.

---

## UI/UX Design
- **Modern glassmorphism look:**
  - Uses CSS3 gradients, blur, and transparency for a professional appearance.
  - Responsive layout for desktop and mobile.
- **Result Display:**
  - Large icons and color-coded results (green=safe, yellow=suspicious, red=danger).
  - Detailed explanations and feature breakdowns for each scan.
- **Accessibility:**
  - Keyboard navigation and ARIA labels for important elements.

---

## Session & Security Handling
- **JWT stored in localStorage:**
  - Checked on every page load and API request.
  - Expired tokens trigger logout and redirect.
- **No sensitive data in frontend code.**
- **All API requests use HTTPS in production.**
- **Input validation:**
  - URL/domain inputs are sanitized before sending to backend.

---

## Error Handling
- **Custom error pages:**
  - 403 (Forbidden), 404 (Not Found), 500 (Server Error) for user feedback.
- **Global JS error handlers:**
  - Catches unhandled promise rejections and displays user-friendly messages.
- **API error responses:**
  - Displayed in the UI with clear explanations.

---

For further details, see code comments in each JS file. The frontend is designed for clarity, security, and ease of use, with a focus on providing actionable feedback to users.