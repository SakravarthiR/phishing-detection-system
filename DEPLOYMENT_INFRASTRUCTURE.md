# Deployment & Infrastructure - Detailed Documentation

## Table of Contents
1. [Local Development Setup](#local-development-setup)
2. [Production Deployment](#production-deployment)
3. [Infrastructure Components](#infrastructure-components)
4. [Security Checklist](#security-checklist)
5. [Maintenance & Updates](#maintenance--updates)

---

## Local Development Setup

1. **Clone the repository:**
   ```sh
   git clone https://github.com/yourusername/phishing-detector.git
   cd phishing-detector
   ```
2. **Create and activate a virtual environment:**
   ```sh
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```
3. **Install dependencies:**
   ```sh
   pip install -r backend/requirements.txt
   ```
4. **Configure environment:**
   - Copy `.env.example` to `.env` and set required variables (e.g., secret keys, DB paths).
5. **Run the backend server:**
   ```sh
   python backend/secure_api.py
   ```
6. **Open the frontend:**
   - Open `frontend/index.html` in your browser.

---

## Production Deployment

- **Recommended OS:** Ubuntu Server (tested on 20.04+)
- **Automated Deployment:**
  - Use `deployment/deploy.sh` (if available) for one-command setup:
    ```sh
    chmod +x deployment/deploy.sh
    ./deployment/deploy.sh
    ```
  - Installs Nginx, Gunicorn, Python, SSL (LetsEncrypt), firewall, and systemd service.
- **Manual Steps:**
  1. Set up Python environment and install dependencies as above.
  2. Configure Gunicorn to serve the Flask app (`backend/secure_api.py`).
  3. Configure Nginx as a reverse proxy for Gunicorn and to serve static frontend files.
  4. Obtain and install SSL certificates (LetsEncrypt recommended).
  5. Set up firewall (e.g., UFW) to allow only necessary ports (80, 443).
  6. Enable and start systemd services for Gunicorn and Nginx.

---

## Infrastructure Components

- **Backend:**
  - Python 3.11, Flask 3.0, Gunicorn (WSGI server)
- **Frontend:**
  - Static files (HTML, JS, CSS) served by Nginx
- **Web Server:**
  - Nginx (reverse proxy, SSL termination, static file serving)
- **SSL:**
  - LetsEncrypt for free, automated SSL certificates
- **Firewall:**
  - UFW or similar, only ports 80/443 open
- **Systemd:**
  - Manages Gunicorn and Nginx as services

---

## Security Checklist

- [x] No backend files exposed to the web
- [x] Environment variables and secrets are hidden
- [x] HTTPS enforced for all traffic
- [x] Firewall enabled, only necessary ports open
- [x] Regular PhishTank DB updates (every 6 hours)
- [x] Rate limiting and DDoS protection enabled
- [x] JWT tokens expire after 24 hours
- [x] Passwords hashed with bcrypt
- [x] Security headers set in all responses

---

## Maintenance & Updates

- **PhishTank DB:** Auto-updates every 6 hours (no manual action needed)
- **Dependencies:**
  - Regularly update Python packages via `pip install --upgrade -r backend/requirements.txt`
- **SSL Certificates:**
  - LetsEncrypt certificates auto-renew (check cron jobs or systemd timers)
- **Logs & Monitoring:**
  - Monitor logs for errors, suspicious activity, and system health
- **Backups:**
  - Regularly back up configuration files, user data, and environment variables

---

For more details, see the `README.md` and deployment scripts in the repository.