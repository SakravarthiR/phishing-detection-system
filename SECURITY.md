# IP-Based Session Security Implementation

## Overview
This enhanced security system enforces strict IP validation for all user sessions. Only devices with whitelisted IPs can access privileged operations.

## Key Security Features

### 1. **Session Binding to Device IP**
- Each session is cryptographically tied to the client's IP address
- Sessions from different IPs are automatically rejected
- Prevents session hijacking and unauthorized access

### 2. **Privileged Operations Require Whitelisting**
- Administrative operations only accessible from pre-approved device IPs
- Whitelisted devices stored in `device_whitelist.json`
- Real-time device management via admin endpoints

### 3. **Strict IP Validation**
```
Login Flow:
1. User authenticates with username/password
2. Backend verifies credentials (Rate-limited: 5 attempts per 15 min)
3. Session created with client IP + User Agent binding
4. Session ID returned to client
5. All subsequent requests validated against original IP
```

## Configuration

### Device Whitelist File
Location: `backend/device_whitelist.json`

```json
{
  "devices": {
    "127.0.0.1": {
      "name": "Local Development",
      "description": "Development machine",
      "added_at": "2026-01-07T00:00:00",
      "last_access": null
    },
    "192.168.1.100": {
      "name": "Work Computer",
      "description": "Office workstation",
      "added_at": "2026-01-07T10:30:00",
      "last_access": "2026-01-07T15:45:00"
    }
  }
}
```

## Admin API Endpoints

### 1. **List Whitelisted Devices** 
```bash
GET /admin/devices
Authorization: Bearer <session_id>
```

**Response:**
```json
{
  "success": true,
  "devices": {
    "127.0.0.1": {...},
    "192.168.1.100": {...}
  },
  "count": 2
}
```

### 2. **Add Device to Whitelist**
```bash
POST /admin/devices/add
Authorization: Bearer <session_id>
Content-Type: application/json

{
  "ip": "192.168.1.105",
  "name": "New Workstation",
  "description": "Additional secure device"
}
```

**Response (201 Created):**
```json
{
  "success": true,
  "message": "Device New Workstation added to whitelist",
  "ip": "192.168.1.105"
}
```

### 3. **Remove Device from Whitelist**
```bash
POST /admin/devices/remove
Authorization: Bearer <session_id>
Content-Type: application/json

{
  "ip": "192.168.1.105"
}
```

### 4. **List Active Sessions**
```bash
GET /admin/sessions
Authorization: Bearer <session_id>
```

**Response:**
```json
{
  "success": true,
  "sessions": [
    {
      "session_id": "...",
      "username": "admin",
      "ip_address": "127.0.0.1",
      "device_name": "Local Development",
      "is_privileged": true,
      "created_at": "2026-01-07T10:00:00",
      "expires_at": "2026-01-08T10:00:00",
      "last_activity": "2026-01-07T10:15:30",
      "request_count": 45
    }
  ],
  "count": 1
}
```

### 5. **Revoke Session**
```bash
POST /admin/sessions/revoke
Authorization: Bearer <session_id>
Content-Type: application/json

{
  "session_id": "..."
}
```

## Frontend Integration

### Session Manager Functions

#### Store Session
```javascript
storeSession({
  token: "...",
  session_id: "...",
  username: "admin",
  expires_in: 86400,
  privileged: true,
  device_name: "Local Development"
});
```

#### Check Authentication
```javascript
if (!isSessionValid()) {
  window.location.href = '/secure-auth-portal.html';
}
```

#### Make Authenticated Requests
```javascript
const response = await authenticatedFetch('/api/endpoint', {
  method: 'POST',
  body: JSON.stringify({...})
});
```

#### Require Privilege
```javascript
if (await requirePrivilege('Delete User')) {
  // Perform privileged operation
}
```

## Security Headers & Protections

### Built-in Protections
- **X-Frame-Options**: DENY (prevent clickjacking)
- **X-Content-Type-Options**: nosniff (prevent MIME sniffing)
- **Strict-Transport-Security**: HTTPS only
- **Content-Security-Policy**: Strict policies
- **X-XSS-Protection**: Enabled

### Rate Limiting
- **Login**: 5 attempts per 15 minutes per IP
- **General**: 60 requests per minute per IP
- **Hourly**: 500 requests per hour per IP
- **Lockout**: 15 minutes after max attempts exceeded

## Deployment Security Checklist

### Before Production Deployment

1. **Change Admin Password**
   - Edit credentials.json or environment variables
   - Default: `admin / phishing123`
   - ✅ Must change this!

2. **Update Device Whitelist**
   - Add production server IPs
   - Add trusted admin workstations
   - Remove test/development IPs

3. **Enable HTTPS**
   - Set `SESSION_COOKIE_SECURE = True`
   - Install SSL certificate
   - Force HTTPS redirect

4. **Configure CORS**
   ```python
   ALLOWED_ORIGINS = [
       'https://yourdomain.com',
       'https://www.yourdomain.com'
   ]
   ```

5. **Use Redis for Session Storage** (Production)
   ```python
   RATE_LIMIT_STORAGE_URL = 'redis://localhost:6379'
   ```

6. **Set Secure Cookies**
   ```python
   SESSION_COOKIE_SECURE = True
   SESSION_COOKIE_HTTPONLY = True
   SESSION_COOKIE_SAMESITE = 'Strict'
   ```

7. **Enable Advanced Security**
   - DDoS Protection: ON
   - IP Whitelisting: ON
   - Port Scanning Detection: ON
   - Fingerprinting: ON

## Troubleshooting

### "Session IP mismatch - Access denied"
- **Cause**: Device IP changed or accessing from VPN
- **Solution**: 
  1. Clear browser cache/storage
  2. Log in again from the same device
  3. Ask admin to whitelist new IP if using VPN

### "Insufficient privileges - Device not authorized"
- **Cause**: Device IP not in whitelist
- **Solution**: 
  1. Identify your device IP
  2. Ask admin to run `/admin/devices/add` endpoint
  3. Provide device name and description

### "Session expired"
- **Cause**: Session timeout (default 24 hours)
- **Solution**: Log in again

### Sessions not persisting across page reloads
- **Cause**: localStorage disabled or cleared
- **Solution**: 
  1. Enable localStorage in browser
  2. Check Privacy/Incognito mode
  3. Clear browser cache

## Logs & Monitoring

### Security Events Logged
- `SUCCESSFUL_LOGIN`: User authenticated
- `FAILED_LOGIN`: Authentication attempt failed
- `BLOCKED_IP_LOGIN_ATTEMPT`: Too many failed attempts
- `SESSION_IP_MISMATCH`: Session hijacking attempt detected
- `DEVICE_WHITELISTED`: New device added
- `DEVICE_REMOVED`: Device removed from whitelist
- `PRIVILEGE_ACCESS_GRANTED`: Admin operation performed
- `SESSION_REVOKED`: Admin revoked user session

### View Logs
```bash
# Linux/Mac
tail -f backend/security.log

# Windows
Get-Content backend/security.log -Tail 50 -Wait
```

## Advanced Configuration

### Custom Session Timeout
Edit `backend/security_config.py`:
```python
SESSION_TIMEOUT_MINUTES = 1440  # 24 hours
```

### Custom Rate Limits
```python
LOGIN_RATE_LIMIT = 5  # attempts
RATE_LIMIT_PER_MINUTE = 60  # requests
RATE_LIMIT_PER_HOUR = 500  # requests
```

### User Agent Validation (Strict Mode)
Edit `backend/ip_session_security.py`:
```python
# Uncomment for stricter security:
# return False, None, "Session user agent mismatch - Access denied"
```

## API Response Examples

### Success (200)
```json
{
  "success": true,
  "token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "session_id": "...",
  "privileged": true,
  "device_name": "Local Development"
}
```

### Unauthorized (401)
```json
{
  "error": "Session invalid",
  "message": "Session IP mismatch - Access denied"
}
```

### Forbidden (403)
```json
{
  "error": "Insufficient privileges",
  "message": "This device is not authorized for privileged operations",
  "ip": "192.168.1.100"
}
```

### Too Many Attempts (429)
```json
{
  "error": "Too many failed attempts",
  "message": "Account temporarily locked. Try again in 15 minutes.",
  "retry_after": 900
}
```

## Support & Questions

For security issues or questions:
1. Check this documentation
2. Review logs in `backend/security.log`
3. Ensure device IP is whitelisted
4. Verify browser localStorage is enabled
5. Test from a different device/IP

---

**Last Updated**: January 7, 2026
**Version**: 1.0.0 - Enhanced IP Session Security
