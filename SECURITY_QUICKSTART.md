# Quick Start: IP-Based Session Security

## What's New? 🔒

Your application now has **strict IP-based session security**:
- ✅ Sessions locked to device IP address
- ✅ Privileged operations only from whitelisted devices
- ✅ Real-time device management
- ✅ Admin session control
- ✅ Enhanced audit logging

## First Time Setup (5 minutes)

### Step 1: Start the Backend
```bash
cd backend
python secure_api.py
```

Expected output:
```
🔒 SECURE PHISHING DETECTOR API
✅ IP Session Security initialized
✅ Default Login: admin / phishing123
```

### Step 2: Log In
1. Open `http://127.0.0.1:5000` in browser
2. Click "Login" or go to `/secure-auth-portal.html`
3. Enter credentials:
   - **Username**: `admin`
   - **Password**: `phishing123`
4. ✅ You're logged in!

### Step 3: Check Your Device Status
Open browser DevTools (F12) → Console, and run:
```javascript
// Check if logged in
console.log(getSession());

// Check if device is privileged
console.log('Privileged:', isPrivileged());

// Check device name
console.log('Device:', getDeviceName());
```

Expected output:
```
{
  "token": "...",
  "session_id": "...",
  "username": "admin",
  "privileged": true,
  "device_name": "Local Development"
}
Privileged: true
Device: Local Development
```

## Managing Authorized Devices

### Find Your Device IP
```javascript
// Run in console:
fetch('http://127.0.0.1:5000/api/my-ip')
  .then(r => r.json())
  .then(d => console.log('Your IP:', d.ip_address));
```

Or check at: https://whatismyipaddress.com

### Add a New Device to Whitelist

**Option 1: Using API (Recommended)**
```javascript
// Run in console from whitelisted device:
const headers = getAuthHeaders();
fetch('http://127.0.0.1:5000/admin/devices/add', {
  method: 'POST',
  headers: headers,
  body: JSON.stringify({
    ip: "192.168.1.100",
    name: "Laptop at Work",
    description: "Office workstation"
  })
})
.then(r => r.json())
.then(d => console.log(d));
```

**Option 2: Direct File Edit**
Edit `backend/device_whitelist.json`:
```json
{
  "devices": {
    "127.0.0.1": {
      "name": "Local Development",
      "description": "Your computer",
      "added_at": "2026-01-07T00:00:00",
      "last_access": null
    },
    "192.168.1.100": {
      "name": "Laptop at Work",
      "description": "Office workstation",
      "added_at": "2026-01-07T14:00:00",
      "last_access": null
    }
  }
}
```

Then **restart** the backend for changes to take effect.

### List All Whitelisted Devices
```javascript
// Run in console:
const headers = getAuthHeaders();
fetch('http://127.0.0.1:5000/admin/devices', {
  headers: headers
})
.then(r => r.json())
.then(d => console.log(d));
```

### Remove a Device
```javascript
// Run in console:
const headers = getAuthHeaders();
fetch('http://127.0.0.1:5000/admin/devices/remove', {
  method: 'POST',
  headers: headers,
  body: JSON.stringify({
    ip: "192.168.1.100"
  })
})
.then(r => r.json())
.then(d => console.log(d));
```

## Admin Session Management

### View All Active Sessions
```javascript
const headers = getAuthHeaders();
fetch('http://127.0.0.1:5000/admin/sessions', {
  headers: headers
})
.then(r => r.json())
.then(d => {
  console.log('Active Sessions:', d.sessions);
  d.sessions.forEach(s => {
    console.log(`- ${s.username} from ${s.ip_address} (${s.device_name})`);
  });
});
```

### Revoke a User Session
```javascript
const headers = getAuthHeaders();
fetch('http://127.0.0.1:5000/admin/sessions/revoke', {
  method: 'POST',
  headers: headers,
  body: JSON.stringify({
    session_id: "..." // Copy from session list
  })
})
.then(r => r.json())
.then(d => console.log(d));
```

## Protected Features

### Feature: Only Accessible from Whitelisted Devices

Example - Admin Panel (requires privilege):
```javascript
if (!isPrivileged()) {
  alert('This operation requires a whitelisted device!');
  return;
}

// Perform admin operation...
```

## Changing Admin Password

### Option 1: Environment Variable
```bash
# Windows
set ADMIN_PASSWORD_HASH=your_bcrypt_hash

# Linux/Mac
export ADMIN_PASSWORD_HASH=your_bcrypt_hash
```

### Option 2: Credentials File
Edit `backend/credentials.json`:
```json
{
  "admin_username": "admin",
  "admin_password_hash": "your_bcrypt_hash"
}
```

To generate bcrypt hash:
```python
import bcrypt
password = "your_new_password"
hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
print(hash.decode())
```

## Troubleshooting

### "Session IP mismatch - Access denied"
**Problem**: Device IP changed (WiFi → VPN, etc.)

**Solution**:
1. Log out from current session: `clearSession()`
2. Log in again
3. Your new IP will be bound

### "Insufficient privileges - Device not authorized"
**Problem**: Your device is not in the whitelist

**Solution**:
1. Get your IP: `fetch('/admin/my-ip').then(r => r.json())`
2. Ask admin to whitelist it: `/admin/devices/add`
3. Log out and log back in

### "Cannot connect to API"
**Problem**: Backend not running or CORS issue

**Solution**:
1. Start backend: `python secure_api.py`
2. Check it's running: `http://127.0.0.1:5000/status`
3. Check browser console (F12) for errors

### Sessions Lost After Browser Restart
**Problem**: localStorage cleared or disabled

**Solution**:
1. Enable localStorage (not in Private/Incognito mode)
2. Check browser settings → Privacy → Allow local storage
3. Log in again

## Default Whitelisted IPs

```
127.0.0.1 → Local Development (your computer)
```

Add more IPs based on where you'll be accessing from:
- Work office: `192.168.1.100`
- Home: `203.0.113.50`
- Laptop: `192.168.1.105`

## Security Best Practices

✅ **DO:**
- Change default password immediately
- Whitelist only trusted devices
- Review active sessions regularly
- Log out when done
- Use HTTPS in production

❌ **DON'T:**
- Whitelist shared/public WiFi IPs
- Leave default password unchanged
- Share session IDs
- Disable HTTPS in production
- Enable from untrusted networks

## Testing the Security

### Test 1: IP Binding Works
```javascript
// Should show your current IP
console.log(getSession().ip_from_login);
```

### Test 2: Sessions Are Revoked on IP Change
1. Log in from Device A
2. Try to access from Device B (different IP)
3. ✅ Should be denied: "Session IP mismatch"

### Test 3: Privilege Required for Admin Ops
1. Log in from non-whitelisted IP
2. Try to access `/admin/devices`
3. ✅ Should be denied: "Insufficient privileges"

## Next Steps

1. ✅ Change default admin password
2. ✅ Add your production IPs to whitelist
3. ✅ Deploy to Render.com (see main docs)
4. ✅ Enable HTTPS
5. ✅ Review security logs regularly

## Documentation

Full details: See [SECURITY.md](./SECURITY.md)

---

**Questions?** Check the logs:
```bash
tail -f backend/security.log
```

Happy secure coding! 🔒
