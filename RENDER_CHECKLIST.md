# Render Deployment - Quick Checklist

Use this checklist while deploying to Render.com

## ✅ Pre-Deployment

- [x] Code pushed to GitHub
- [x] `render.yaml` exists
- [x] `build.sh` exists
- [x] `start.sh` exists
- [x] `gunicorn` in requirements.txt
- [x] Frontend API URLs use placeholder

---

## 🚀 Backend Deployment

### Create Web Service

- [ ] Go to https://dashboard.render.com/
- [ ] Click "New +" → "Web Service"
- [ ] Connect GitHub repo: `SakravarthiR/phishing-detection-system`

### Configure Service

- [ ] **Name:** `phishing-detector-api`
- [ ] **Region:** Oregon (US West)
- [ ] **Branch:** `main`
- [ ] **Runtime:** Python 3
- [ ] **Build Command:** `pip install -r backend/requirements.txt`
- [ ] **Start Command:** `sh start.sh`

### Environment Variables

Add these in "Advanced" section:

- [ ] `PORT` = `10000`
- [ ] `PYTHON_VERSION` = `3.11.0`
- [ ] `SECRET_KEY` = [Generate]
- [ ] `JWT_SECRET_KEY` = [Generate]
- [ ] `APP_ENV` = `production`
- [ ] `DEBUG` = `False`
- [ ] `API_HOST` = `0.0.0.0`
- [ ] `SESSION_TIMEOUT_MINUTES` = `60`
- [ ] `MAX_REQUESTS_PER_MINUTE` = `100`
- [ ] `PHISHTANK_CACHE_HOURS` = `6`

### Create & Deploy

- [ ] Click "Create Web Service"
- [ ] Wait for build (5-10 minutes)
- [ ] Build succeeds ✅

### Add Credentials

- [ ] Go to Environment → Secret Files
- [ ] Add file: `credentials.json`
- [ ] Content:
```json
{
    "username": "admin",
    "password": "SaKravarthi@0809"
}
```
- [ ] Save (auto-redeploys)

### Verify Backend

- [ ] Service shows "Deploy live" (green)
- [ ] Copy backend URL: `https://phishing-detector-api-xxxx.onrender.com`
- [ ] Test health: `curl https://YOUR_BACKEND_URL/api/health`
- [ ] Returns: `{"status":"healthy"}`

---

## 🎨 Frontend Deployment

### Update API URLs

- [ ] Open `frontend/login.js`
- [ ] Update line 24: `const API_BASE_URL = 'YOUR_BACKEND_URL';`
- [ ] Open `frontend/scanner.js`
- [ ] Update line 23: `const API_BASE_URL = 'YOUR_BACKEND_URL';`
- [ ] Commit: `git commit -m "Update API URLs to Render backend"`
- [ ] Push: `git push origin main`

### Create Static Site

- [ ] Go to Render dashboard
- [ ] Click "New +" → "Static Site"
- [ ] Connect same GitHub repo
- [ ] **Name:** `phishing-detector`
- [ ] **Branch:** `main`
- [ ] **Publish Directory:** `frontend`
- [ ] **Build Command:** (leave empty)
- [ ] Click "Create Static Site"
- [ ] Wait 1-2 minutes

### Verify Frontend

- [ ] Site shows "Deploy live" (green)
- [ ] Copy frontend URL: `https://phishing-detector-xxxx.onrender.com`
- [ ] Open URL in browser
- [ ] Homepage loads with pixel theme
- [ ] Click "Launch Scanner"
- [ ] Login page loads
- [ ] Login works: `admin` / `SaKravarthi@0809`
- [ ] Scanner page loads
- [ ] Can scan a test URL

---

## 🌐 Custom Domain (Optional)

### Connect Domain

- [ ] Frontend → Settings → Custom Domain
- [ ] Add: `phishingdetector.me`
- [ ] Add: `www.phishingdetector.me`

### Update DNS (Namecheap)

- [ ] Login to Namecheap
- [ ] Domain List → Manage → Advanced DNS
- [ ] Add CNAME for `www` → `your-site.onrender.com`
- [ ] Add A/ALIAS for `@` → (Render provides)
- [ ] Wait 10-30 minutes

### Update CORS

- [ ] Backend → Environment
- [ ] Update `ALLOWED_ORIGINS`:
```
https://phishingdetector.me,https://www.phishingdetector.me
```
- [ ] Save (auto-redeploys)

### Verify Domain

- [ ] `https://phishingdetector.me` loads
- [ ] SSL shows green padlock
- [ ] Login and scanning work

---

## 📋 Final Verification

### Backend Tests

- [ ] `curl https://BACKEND_URL/api/health` returns `{"status":"healthy"}`
- [ ] Logs show: "Listening at: http://0.0.0.0:10000"
- [ ] No errors in logs

### Frontend Tests

- [ ] Homepage loads
- [ ] Images/styles load correctly
- [ ] No console errors
- [ ] Login redirects properly
- [ ] Token authentication works

### Full Flow Test

- [ ] Open site
- [ ] Click "Launch Scanner"
- [ ] Login with credentials
- [ ] Enter test URL: `paypal-secure-login.com`
- [ ] Click "Scan Domain"
- [ ] Results display correctly
- [ ] Risk score shows
- [ ] Indicators display

### Security Tests

- [ ] SSL certificate active (https://)
- [ ] No mixed content warnings
- [ ] Credentials.json not publicly accessible
- [ ] .env not publicly accessible

---

## 📊 Monitoring

### Check Status

- [ ] Backend: Dashboard → Service → Events (should be green)
- [ ] Frontend: Dashboard → Site → Events (should be green)

### View Logs

- [ ] Backend → Logs tab working
- [ ] Can enable "Live tail"
- [ ] No error messages

---

## 🎉 Launch Complete!

- [ ] Both services deployed successfully
- [ ] All tests passing
- [ ] URLs saved:
  - Backend: `_____________________________`
  - Frontend: `_____________________________`
- [ ] Screenshot taken for portfolio
- [ ] Added to resume
- [ ] Posted on LinkedIn

---

## 🆘 Troubleshooting

### Build Failed

- [ ] Check Logs tab for errors
- [ ] Clear build cache: Settings → Build & Deploy
- [ ] Verify PYTHON_VERSION = 3.11.0
- [ ] Check requirements.txt syntax

### Login Not Working

- [ ] Verify credentials.json in Secret Files
- [ ] Check JSON syntax
- [ ] Check backend logs for errors
- [ ] Verify API_BASE_URL in frontend

### Backend Sleeping

This is normal on free tier:
- First request after 15min = 30-60 seconds
- Subsequent requests = fast
- Upgrade to Starter ($7/mo) to prevent sleep

---

**Need help?** Check `RENDER_DEPLOYMENT.md` for detailed instructions!
