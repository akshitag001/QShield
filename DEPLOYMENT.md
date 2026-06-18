# QShield Deployment Guide

## Docker-based Deployment (Recommended for PQC Support)

This guide explains how to deploy QShield with full PQC hybrid key exchange support using Docker.

### Why Docker?
- **Full Control**: Compile OpenSSL 3.6.1 from source (ensures PQC/oqs-provider support)
- **Consistent Environment**: Same dependencies across dev, staging, and production
- **Vercel Alternative**: Works with Railway.app, Render.com, AWS, DigitalOcean, etc.

---

## Option A: Deploy to Railway.app (Fastest - 5 minutes)

### Prerequisites
- GitHub account (already have)
- Railway.app account (free tier available at https://railway.app)

### Steps

1. **Sign up at Railway.app** with GitHub
   - Go to https://railway.app
   - Click "Start Project" → "Deploy from GitHub"
   - Select your `QShield` repository

2. **Railway auto-detects Dockerfile** and builds it

3. **Set environment variables** (if needed in future):
   - Go to "Variables" tab in Railway dashboard
   - No special vars needed for QShield currently

4. **Get deployment URL**
   - Railway gives you a public URL like `https://qshield-prod-xxxx.railway.app`
   - Test: `https://qshield-prod-xxxx.railway.app/login`

5. **View logs**
   - Click "Logs" tab to see real-time build and startup output
   - Verify OpenSSL 3.6.1 compiled successfully

---

## Option B: Deploy to Render.com (Also Good)

### Steps

1. **Sign up at Render.com** with GitHub
   - Go to https://render.com
   - Click "New +" → "Web Service"
   - Connect GitHub and select `QShield` repo

2. **Configure deployment**:
   - **Name**: `qshield`
   - **Environment**: Docker
   - **Instance Type**: Free (for testing) or Starter ($7/month for production)
   - **Plan** → Deploy

3. **Get deployment URL** from dashboard

---

## Option C: Deploy to AWS (Most Scalable)

### Using AWS App Runner (simplest)

1. Go to AWS Console → App Runner
2. Click "Create service"
3. Choose "Source code repository" → GitHub
4. Select QShield repo
5. Choose "Dockerfile" as build method
6. Deploy

---

## Testing Deployment

Once deployed, verify PQC support is working:

```bash
# Replace with your deployment URL
curl https://YOUR-DEPLOYMENT-URL.railway.app/api/scan/stream?domain=sc.com

# Check the response for:
# - "key_exchange_details": { "algorithm": "X25519+ML-KEM-768" }
# - "pqc_detection": { "detection_method": "openssl_groups_negotiation" }
```

---

## Troubleshooting

### "OpenSSL build fails during deployment"
- Check deployment logs for error messages
- The Dockerfile compiles OpenSSL 3.6.1 using parallel build jobs (`make -j$(nproc)`) to reduce build time
- Subsequent deployments use Docker cache (faster)

### "Hybrid key exchange not detected on deployed version"
- Ensure OpenSSL compilation succeeded in logs
- Run: `curl https://YOUR-URL/api/scan/stream?domain=google.com`
- Check `detection_method` field - should be `openssl_groups_negotiation`, not `openssl_unavailable`

### "Build timeout on Railway"
- If timeout still occurs, retry once (free-tier builders can be noisy/slow)
- Keep OpenSSL build parallelized in Docker (`make -j$(nproc)`) and avoid adding heavy compile steps before app copy
- Free tier may have resource limits

---

## Local Testing Before Deployment

Test locally with Docker:

```bash
cd QShield-main
docker build -t qshield:latest .
docker run -p 8000:8000 qshield:latest
# Visit http://localhost:8000/login
```

---

## Recommended Next Steps

1. **Test Railway deployment** (free tier, takes 5 min)
2. **Verify PQC detection** via diagnostics line in scan results
3. **Compare with localhost** - both should show `X25519+ML-KEM-768` now
4. **Upgrade to paid tier** only if load testing shows need

---

## Cost Comparison

| Platform | Free Tier | Paid Tier | Notes |
|----------|-----------|-----------|-------|
| Railway | $5 credit/month | $5+ | Sleep after 7 days inactivity |
| Render | Builds stop after 15 min | $7/month | Spinning up takes time |
| AWS App Runner | 125 vCPU-hours/month | $0.065/vCPU-hour | Pay-per-use, good for production |
| Vercel | Limited (no Docker) | $20+/month | Easier but less control |

---

## Database Configuration (CRITICAL FOR DATA PERSISTENCE)

### Default Behavior
- **Local (Windows)**: Uses SQLite file (`./qshield.db`)
- **Render/Serverless**: Falls back to **in-memory database** if persistent storage not configured
  - ⚠️ **WARNING**: All scan data is LOST when app restarts!

### Set Up Persistent PostgreSQL Database

#### On Render.com

1. **Create PostgreSQL Instance**:
   - Go to Render Dashboard
   - Click **New +** → **PostgreSQL**
   - Name: `qshield-db`
   - Leave other settings as default
   - Click **Create**

2. **Wait for database to initialize** (~1 minute)

3. **Copy the Internal Database URL**
   - In Render PostgreSQL dashboard, copy the **Internal Database URL** (not External)
   - Format: `postgresql://user:password@host/dbname`

4. **Add to Render Web Service**:
   - Go to your QShield **Web Service** settings
   - Click **Environment**
   - Add new variable:
     ```
     DATABASE_URL=<paste-internal-database-url>
     ```
   - Click **Save** (service will redeploy automatically)

#### On Railway.app

1. **Add PostgreSQL Plugin**:
   - Go to your Railway project
   - Click **+ Add** → **Database** → **PostgreSQL**

2. **Get Connection String**:
   - Click the PostgreSQL service
   - Go to **Connect** tab
   - Copy the **URI** to clipboard

3. **Add to Web Service**:
   - Click your web service (QShield)
   - Go to **Variables**
   - Add: `DATABASE_URL=<paste-uri>`
   - Deploy

#### Using External PostgreSQL (AWS RDS, Heroku Postgres, etc.)

```bash
# Set DATABASE_URL to your external PostgreSQL connection string
DATABASE_URL=postgresql://user:password@host.provider.com:5432/dbname
```

### Verify Database Connection

After setting `DATABASE_URL` and redeploying:

```bash
# Check logs for successful connection
# Should see: "Database initialized successfully."
# NOT: "Using in-memory database"
```

### Cost of PostgreSQL Hosting

| Provider | Free Tier | Paid Tier | Notes |
|----------|-----------|-----------|-------|
| **Render** | None (but quick $7 tier) | $15/month | Easiest with Render web service |
| **Railway** | Included with $5 credit | Included | Simplest option |
| **AWS RDS** | 12 months free (t2.micro) | $0.165/hour+ | Most complex, most control |
| **Heroku Postgres** | None (deprecated) | $9+/month | Previously popular |
| **Supabase** | 500MB free | $25+/month | PostgreSQL + auth |

✅ **Recommended**: Use Railway.app (PostgreSQL included with free tier) or Render PostgreSQL ($15/month)


