# QShield Database Configuration Guide

## Problem: "Scan not found" Error on PDF Download

If you're getting **"Scan not found"** when trying to download a PDF on your hosted Q-Shield instance, your database is not configured for persistence.

**Why this happens**: Without a persistent database, Q-Shield uses an in-memory SQLite database that gets wiped when your app restarts or receives a new request.

---

## Quick Fix (3 minutes on Render)

### Step 1: Create PostgreSQL Database

1. Open [Render Dashboard](https://dashboard.render.com)
2. Click **New +** → **PostgreSQL**
3. Set Name: `qshield-db`
4. Leave other fields as default
5. Click **Create Database**
6. ⏳ Wait ~1 minute for initialization

### Step 2: Get Database Connection String

1. In Render, open the PostgreSQL service you just created
2. Scroll down to **Connection** section
3. Copy the **Internal Database URL** (important: use Internal, not External)
   - Format: `postgresql://user:password:host:port/qshield_db`

### Step 3: Add to Your QShield Web Service

1. Go to Render Dashboard
2. Click your **qshield** Web Service
3. Click **Environment** on the left sidebar
4. Click **Add Environment Variable**
5. Key: `DATABASE_URL`
6. Value: *Paste the connection string from Step 2*
7. Click **Save**
8. ✅ Your service will automatically redeploy (2-3 min)

### Step 4: Verify

Once the service redeploys:

1. Check Render logs - look for:
   ```
   Database initialized successfully.
   ✅ NOT: "Using in-memory database"
   ```

2. Test scanning and PDF download:
   - Go to your Q-Shield instance
   - Run a test scan
   - Try to download the PDF
   - Should work now!

---

## Alternative Platforms

### Railway.app (Recommended - PostgreSQL included)

1. Open your Railway project
2. Click **+ Add** → **Database** → **PostgreSQL**
3. Click the database, go to **Connect** tab
4. Copy the **URI**
5. Go to your web service → **Variables**
6. Add: `DATABASE_URL=<paste-uri>`
7. Deploy

### AWS RDS

```bash
DATABASE_URL=postgresql://admin:password@qshield-db.xxxxx.us-east-1.rds.amazonaws.com:5432/qshield
```

### Other PostgreSQL Providers

- **Supabase**: https://supabase.com (PostgreSQL + free tier)
- **Heroku Postgres**: https://www.heroku.com/postgres
- **Clever Cloud**: https://www.clever-cloud.com

---

## Testing Your Database Connection

After setting `DATABASE_URL`, you can verify it works:

### View Logs on Render

1. Go to your QShield service
2. Click **Logs** tab
3. Look for one of these messages:

✅ **Success** (database is working):
```
Database initialized successfully.
```

❌ **Problem** (database not configured):
```
CRITICAL: Falling back to in-memory database. Data will NOT persist between requests!
Please configure a persistent database using DATABASE_URL environment variable.
Using in-memory database. Scans will be lost on app restart!
```

---

## How Scan Data is Stored

Once you have a persistent PostgreSQL database:

```
PostgreSQL Database (Persistent)
    ↓
scan_records table
    ├── scan_id: "scan_20260411_074021_51150b"
    ├── target: "example.com"
    ├── cbom_json: { ... CBOM data ... }
    ├── result_json: { ... TLS scan results ... }
    └── vulnerabilities_json: { ... quantum risks ... }
    
When you download PDF:
    ↓
API queries scan_records table
    ↓
Finds scan_id = "scan_20260411_074021_51150b"
    ↓
Renders PDF from cbom_json
    ↓
Returns to browser ✓
```

**Without persistent database** (in-memory):
```
In-Memory Database (Temporary - Lost on restart)
    ↓
Each request gets a NEW empty database
    ↓
Scan created in Request #1 ✓
PDF download in Request #2 - Database is empty ✗
Error: "Scan not found"
```

---

## Cost Estimates (Monthly)

| Service | Free Tier | Basic Tier | Setup Time |
|---------|-----------|-----------|-----------|
| **Railway** | $5 credit | Included | 2 min |
| **Render** | None | $15/mo (1GB) | 3 min |
| **Supabase** | 500MB free | $25/mo | 5 min |
| **AWS RDS** | 12mo free (t2.micro) | $30/mo | 10 min |

**Recommended**: Use Railway (included) or Render PostgreSQL ($15/month is very affordable)

---

## Troubleshooting

### "Still getting 'Scan not found' error after setup"

1. ✅ Verify `DATABASE_URL` is set correctly:
   - Check Render Environment variables (no typos)
   - Check the PostgreSQL service is running

2. ✅ Wait for service to fully redeploy:
   - New services take 2-3 minutes
   - Check status shows "Live" ✓

3. ✅ Clear browser cache and try again:
   - Hard refresh (Ctrl+Shift+R or Cmd+Shift+R)

4. ✅ Check logs for errors:
   - Go to Render Logs
   - Search for "Database" or "ERROR"
   - Report any error messages

### "PostgreSQL connection refused"

- Verify the connection string is correct
- Check the database is running (status = "Available")
- Try using the **Internal** URL (not External) if you have multiple options

### "Timeout connecting to database"

- If using External URL, Render may need you to use Internal URL instead
- Check Render's network settings
- Restart the web service

---

## Need Help?

If you're still stuck:

1. Run a test scan and capture the scan_id from the URL
2. Check Render logs for error messages
3. Verify `DATABASE_URL` environment variable is set
4. Check PostgreSQL service status is "Available"
5. Try redeploying the web service manually

Let me know which step fails and I can help debug further!
