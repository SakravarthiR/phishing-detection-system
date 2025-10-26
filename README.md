# Phishing Detection System

<div align="center">

![Python](https://img.shields.io/badge/Python-3.11-blue)
![Flask](https://img.shields.io/badge/Flask-3.0-green)
![Machine Learning](https://img.shields.io/badge/ML-Scikit--learn-orange)
![Security](https://img.shields.io/badge/Security-Hardened-red)
![License](https://img.shields.io/badge/License-MIT-yellow)

**AI-powered phishing detector with real-time threat intelligence**

[Live Demo](#) | [Documentation](#features) | [Report Issue](https://github.com/yourusername/phishing-detector/issues)

</div>

---

## What's Inside

- [About](#about)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [How It Works](#how-it-works)
- [Setup](#setup)
- [Deployment](#deployment)
- [API Docs](#api-docs)
- [Security](#security)
- [Screenshots](#screenshots)
- [Contributing](#contributing)

---

## About

I built this because phishing attacks are getting way too good these days. Needed something that could catch both known threats AND new ones using machine learning.

### Why This Exists
- Phishing is still the #1 way hackers get in (90% of breaches)
- Most free tools suck or are too slow
- Wanted to learn ML + build something actually useful
- Also a portfolio project but it actually works lol

### What It Does
- Scans URLs for sketchy patterns (40+ different checks)
- Cross-references with PhishTank's 15k+ known phishing sites
- Custom rules for obvious red flags (like URLs with @ symbols...)
- Subdomain scanner to find hidden attack vectors
- DDoS protection because people are mean  

---

## Features

### Smart Detection
- ML model trained on 11,000+ URLs (took forever to train)
- Detects typosquatting (like g00gle.com instead of google.com)
- Catches suspicious TLDs (.tk, .ml, all that sketchy stuff)
- Real-time confidence scores

### Threat Database
- Integrated PhishTank's verified phishing database
- Auto-updates every 6 hours (cached locally so it's fast)
- Instant matching for known threats
- Shows you when the phish was reported and who's being targeted

### Subdomain Scanner
- Finds hidden subdomains attackers might use
- DNS lookups with IP tracking
- Detects Cloudflare proxying
- Security score for each subdomain found

### Security Features
- JWT auth (tokens expire so stolen tokens are useless eventually)
- Rate limiting (100 requests/min, configurable)
- DDoS protection (learned this the hard way)
- IP whitelisting for localhost testing
- XSS and SQL injection filtering
- CORS configured properly

---

## Tech Stack

**Backend:**
- Python 3.11 (latest stable when I started)
- Flask 3.0 (lightweight, easy to work with)
- Scikit-learn for the ML stuff
- JWT for authentication
- Gunicorn for production (way better than Flask dev server)

**Frontend:**
- Vanilla JS (no framework bloat)
- CSS3 with glassmorphism (looks sick)
- Press Start 2P font (pixel art vibes)

**Infrastructure:**
- Nginx reverse proxy
- Systemd service (keeps it running 24/7)
- Let's Encrypt SSL (free certs ftw)
- Ubuntu 22.04 LTS

**Security:**
- bcrypt password hashing
- Rate limiting per IP
- Security headers (XSS, clickjacking, all that)
- Input validation and sanitization

---

## How It Works

```
1. User enters URL → Frontend
2. Frontend sends JWT token + URL → Backend API
3. Backend checks:
   ├─ Is it in PhishTank database? → Known threat
   ├─ Does it match suspicious rules? → Likely phishing
   └─ What does ML model think? → Confidence score
4. Response sent back with verdict + detailed analysis
5. User sees: Safe / Suspicious / Dangerous + reasons why
```

The ML model looks at things like:
- URL length and structure
- Number of dots, dashes, special chars
- Domain age and registration info
- TLD reputation (.com is safer than .tk)
- Use of IP addresses instead of domains
- Presence of @ symbols or punycode
- Subdomain patterns
- SSL certificate validity

---

## Setup

### Quick Start (Local Development)

```bash
# Clone it
git clone https://github.com/yourusername/phishing-detector.git
cd phishing-detector

# Setup Python env
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r backend/requirements.txt

# Configure credentials
cp .env.example .env
# Edit .env with your settings

# Run backend
cd backend
python secure_api.py

# Open frontend
# Just open frontend/index.html in browser or use live server
```

### Requirements
- Python 3.11+
- 2GB RAM minimum (ML model is chunky)
- Internet connection (for PhishTank updates)

---

## Deployment

Check out `HOSTING_GUIDE.md` for complete instructions. Here's the quick version:

```bash
# On your VPS (Ubuntu):
cd /var/www
git clone your-repo
cd phishing-detector
chmod +x deployment/deploy.sh
./deployment/deploy.sh
```

The script handles everything:
- System dependencies
- Python environment
- Nginx configuration
- SSL certificates (Let's Encrypt)
- Systemd service
- Firewall rules

Your backend runs 24/7 automatically via Systemd. If it crashes, it restarts. If the server reboots, it auto-starts.

---

## API Docs

### Authentication

```bash
POST /api/login
{
  "username": "your_username",
  "password": "your_password"
}

Response: { "token": "jwt_token_here" }
```

### Check URL

```bash
POST /api/scan
Headers: { "Authorization": "Bearer your_jwt_token" }
{
  "url": "https://suspicious-site.com"
}

Response: {
  "prediction": "phishing",
  "confidence": 0.89,
  "phishtank_match": true,
  "reasons": [...],
  "security_score": 75
}
```

### Subdomain Scan

```bash
POST /api/subdomain-scan
Headers: { "Authorization": "Bearer your_jwt_token" }
{
  "domain": "example.com"
}

Response: {
  "subdomains": [...],
  "total_found": 15,
  "security_assessment": {...}
}
```

### Health Check

```bash
GET /api/health

Response: { "status": "healthy" }
```

More details in `API_DOCUMENTATION.md` (if I get around to writing it...)

---

## Security

### What's Protected
- Directory listing is OFF (no browsing backend files)
- Sensitive files return 404 (.env, .py, .json)
- Custom error pages (no server info leakage)
- Security headers on everything
- Rate limiting per IP
- JWT tokens expire after 24h
- Passwords hashed with bcrypt
- SQL injection prevention
- XSS filtering on all inputs

### Testing Security
```bash
# All of these should return 403 or 404:
curl https://yourdomain.com/.env
curl https://yourdomain.com/backend/
curl https://yourdomain.com/credentials.json
```

### Reporting Issues
Found a security vulnerability? Please email me instead of opening a public issue. Check `SECURITY.md` for details.

---

## Screenshots

*Coming soon - need to take some good ones*

---

## Contributing

PRs are welcome! Here's what I need help with:
- [ ] More ML training data
- [ ] Browser extension version
- [ ] Mobile app
- [ ] Better subdomain wordlist
- [ ] Performance optimizations
- [ ] More tests (I know, I know...)

### Development Setup
```bash
# Fork the repo, clone your fork
git checkout -b feature-name
# Make changes
# Test it thoroughly
git commit -m "Add feature-name"
git push origin feature-name
# Open PR
```

---

## License

MIT License - do whatever you want with it, just don't sue me if something breaks.

---

## Acknowledgments

- PhishTank for the threat database
- Scikit-learn team for making ML accessible
- Stack Overflow for saving my life multiple times
- Coffee for existing

---

## Contact

- GitHub: [@yourusername](https://github.com/yourusername)
- Email: your.email@example.com
- LinkedIn: [Your Profile](https://linkedin.com/in/yourprofile)

---

**Built with code and way too much caffeine**

*Last updated: October 2025*
