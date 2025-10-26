# Render.com Deployment Guide

Complete guide for deploying the Phishing Detection System on Render.com

## Prerequisites

- ✅ GitHub account
- ✅ Render.com account (free tier works)
- ✅ Domain name (optional, Render provides free subdomain)

---

## Step 1: Prepare Repository

Your code is already on GitHub at:
`https://github.com/SakravarthiR/phishing-detection-system`

All necessary files are included:
- `render.yaml` - Render configuration
- `build.sh` - Build script
- `start.sh` - Start script
- `backend/requirements.txt` - Python dependencies
- `backend/gunicorn_config.py` - WSGI server config

---

## Step 2: Deploy Backend API

### A) Create Web Service

1. Go to https://dashboard.render.com/
2. Click **"New +"** → **"Web Service"**
3. Connect your GitHub repository
4. Configure:

```
Name: phishing-detector-api
Region: Oregon (US West)
Branch: main
Root Directory: (leave empty)
Runtime: Python 3
Build Command: pip install -r backend/requirements.txt
Start Command: sh start.sh
Instance Type: Free
```

### B) Add Environment Variables

Click **"Advanced"** and add these:

```
PORT = 10000
PYTHON_VERSION = 3.11.0
SECRET_KEY = [Click "Generate" button]
JWT_SECRET_KEY = [Click "Generate" button]
APP_ENV = production
DEBUG = False
API_HOST = 0.0.0.0
SESSION_TIMEOUT_MINUTES = 60
MAX_REQUESTS_PER_MINUTE = 100
PHISHTANK_CACHE_HOURS = 6
```

### C) Create Web Service

Click **"Create Web Service"** - Build will start automatically (5-10 minutes)

### D) Add Credentials Secret

After service is created:

1. Go to service → **Environment** tab
2. Click **"Secret Files"** section
3. Click **"Add Secret File"**
4. Configure:
   - **Filename:** `credentials.json`
   - **Contents:**
   ```json
   {
       "username": "admin",
       "password": "SaKravarthi@0809"
   }
   ```
5. Click **"Save Changes"** (will auto-redeploy)

### E) Get Backend URL

After deployment succeeds, your backend URL will be:
```
https://phishing-detector-api-xxxx.onrender.com
```

Copy this URL - you'll need it for the frontend!

---

## Step 3: Update Frontend API URLs

### A) Update Local Files

Update these two files with your backend URL:

**frontend/login.js** - Line 24:
```javascript
const API_BASE_URL = 'https://phishing-detector-api-xxxx.onrender.com';
```

**frontend/scanner.js** - Line 23:
```javascript
const API_BASE_URL = 'https://phishing-detector-api-xxxx.onrender.com';
```

### B) Commit and Push

```bash
git add frontend/login.js frontend/scanner.js
git commit -m "Update API URLs to Render backend"
git push origin main
```

---

## Step 4: Deploy Frontend Static Site

### A) Create Static Site

1. Go to Render dashboard
2. Click **"New +"** → **"Static Site"**
3. Connect same GitHub repository
4. Configure:

```
Name: phishing-detector
Region: Oregon (US West)
Branch: main
Root Directory: (leave empty)
Publish Directory: frontend
Build Command: (leave empty or "echo 'No build needed'")
```

### B) Create Static Site

Click **"Create Static Site"** - Deploys in 1-2 minutes

Your frontend URL will be:
```
https://phishing-detector-xxxx.onrender.com
```

---

## Step 5: Connect Custom Domain (Optional)

### A) In Render Dashboard

1. Go to your static site → **Settings**
2. Scroll to **"Custom Domain"**
3. Click **"Add Custom Domain"**
4. Enter: `phishingdetector.me`
5. Click **"Verify"**

### B) Update DNS (Namecheap)

Render will show you DNS records to add:

1. Login to Namecheap
2. Go to **Domain List** → **Manage** → **Advanced DNS**
3. Add these records:

```
Type: CNAME
Host: www
Value: phishing-detector-xxxx.onrender.com
TTL: Automatic

Type: ALIAS or ANAME (if supported) or A Record
Host: @
Value: [Render provides IP or CNAME]
TTL: Automatic
```

4. Wait 10-30 minutes for DNS propagation

### C) Update CORS Origins

After domain is connected, update backend environment:

1. Go to backend service → **Environment**
2. Update `ALLOWED_ORIGINS`:
```
ALLOWED_ORIGINS = https://phishingdetector.me,https://www.phishingdetector.me
```
3. Save (will auto-redeploy)

---

## Step 6: Verify Deployment

### Test Backend

```bash
# Health check
curl https://phishing-detector-api-xxxx.onrender.com/api/health

# Should return:
{"status":"healthy"}
```

### Test Frontend

1. Open: `https://phishing-detector-xxxx.onrender.com` (or your custom domain)
2. Should see pixel art homepage
3. Click **"Launch Scanner"**
4. Login: `admin` / `SaKravarthi@0809`
5. Test scanning a URL

---

## Important Notes

### Free Tier Limitations

- ✅ **Free forever**
- ⏸️ **Sleeps after 15 minutes of inactivity**
- 🐌 **Cold start takes 30-60 seconds**
- ✅ **750 hours/month free** (enough for demos)

### To Prevent Sleep (Paid Tier Only)

Upgrade to **Starter Plan** ($7/month):
- No sleep
- Faster performance
- Custom domains included

### Cold Start Behavior

When backend sleeps:
- First request takes 30-60 seconds
- User sees loading spinner
- Subsequent requests are fast
- Perfect for portfolio/demos

---

## Troubleshooting

### Build Failed

**Check logs:**
1. Go to service → **Logs** tab
2. Look for error messages

**Common fixes:**
- Clear build cache: Settings → Build & Deploy → Clear build cache
- Check Python version: Environment → `PYTHON_VERSION = 3.11.0`
- Verify requirements.txt has no syntax errors

### Backend Not Responding

**Check service status:**
1. Go to service → **Events** tab
2. Should show "Deploy live" (green)

**Check logs:**
```
Go to service → Logs tab
Look for: "Listening at: http://0.0.0.0:10000"
```

### Login Not Working

**Check credentials.json:**
1. Go to backend → **Environment** → **Secret Files**
2. Verify `credentials.json` exists
3. Check JSON syntax is valid

### CORS Errors

**Update ALLOWED_ORIGINS:**
1. Go to backend → **Environment**
2. Add your frontend URL to `ALLOWED_ORIGINS`
3. Format: `https://your-frontend.onrender.com`

---

## Monitoring

### View Logs

**Backend logs:**
```
Dashboard → phishing-detector-api → Logs
```

**Watch live:**
Click **"Live tail"** button to stream logs in real-time

### Check Metrics

```
Dashboard → Service → Metrics tab
```

Shows:
- CPU usage
- Memory usage
- Request count
- Response times

---

## Updating Code

### Deploy Updates

```bash
# Make changes locally
git add .
git commit -m "Your changes"
git push origin main

# Render auto-deploys within 1-2 minutes
```

### Manual Deploy

If auto-deploy doesn't trigger:
1. Go to service
2. Click **"Manual Deploy"** (top right)
3. Select **"Deploy latest commit"**

---

## Cost Summary

| Service | Plan | Cost |
|---------|------|------|
| Backend API | Free | $0 |
| Frontend Static Site | Free | $0 |
| Custom Domain SSL | Included | $0 |
| **Total** | | **$0/month** |

---

## Production Checklist

- [ ] Backend deployed and running
- [ ] Credentials.json added as secret file
- [ ] Environment variables configured
- [ ] Health endpoint returns success
- [ ] Frontend deployed
- [ ] Frontend API URLs updated
- [ ] Login works
- [ ] Scanning works
- [ ] Custom domain connected (if applicable)
- [ ] SSL certificate active (green padlock)
- [ ] CORS configured for custom domain
- [ ] Repository README updated with live URL

---

## Support

**Render Documentation:**
https://render.com/docs

**Common Issues:**
https://render.com/docs/troubleshooting-deploys

**Community:**
https://community.render.com

---

🎉 **Your phishing detector is now live on Render!**

Share your portfolio project:
- Live URL: `https://your-site.onrender.com`
- GitHub: `https://github.com/SakravarthiR/phishing-detection-system`
- Add to resume and LinkedIn!
