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
git clone https://github.com/yourusername/phishing-detector.git
cd phishing-detector
python -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
cp .env.example .env
python backend/secure_api.py


Then open frontend/index.html in ur browser.

Need internet coz phishtank update.
2gb ram enough.

Deploy

If u using vps do this

cd /var/www
git clone repo
cd phishing-detector
chmod +x deployment/deploy.sh
./deployment/deploy.sh


It auto install nginx, ssl, firewall, and all thing.

API

Login:
POST /api/login
give username, password → get token

Scan URL:
POST /api/scan
give url → get result with confidence, reason, score

Subdomain Scan:
POST /api/subdomain-scan
give domain → get all subdomains list

Health:
GET /api/health → status ok

Security

no backend file visible

env file hidden

bcrypt password

rate limit per ip

jwt expire 24hr

input sanitized

if u find any issue pls mail me dont put public issue ok.

Screenshot

coming soon (i need to take nice one 😅)

Contribute

u can help me add more data or make browser extension or mobile app version. i also need help for speed and test code.

License

MIT license (do anything u want but dont blame me if it break ur pc 😂)

Thanks to

PhishTank api

Scikit learn

Stackoverflow help always

Coffee 😪