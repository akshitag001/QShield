# QShield Database Setup Guide

## 1. Provision PostgreSQL on Render
- Go to your Render dashboard.
- Create a new PostgreSQL database.
- Copy the `Internal Database URL` (it will look like: `postgres://USER:PASSWORD@HOST:PORT/DBNAME`).

## 2. Set the DATABASE_URL
- Locally: Create a `.env` file in your project root with:
  
  DATABASE_URL=postgresql://USER:PASSWORD@HOST:PORT/DBNAME

- On Render: In your Render service settings, add an environment variable:
  
  Key: DATABASE_URL
  Value: (your Render PostgreSQL URL)

## 3. Initialize the Database
- Run the following command locally to create tables:

  ```bash
  python db_init.py
  ```

- On Render, tables will be created automatically on first app start (if not present).

## 4. Verify
- Data will be stored in PostgreSQL both locally and when hosted on Render, as long as DATABASE_URL is set correctly.

---

## Troubleshooting
- If you see errors about missing tables, make sure you ran the initialization step.
- If you see connection errors, double-check your DATABASE_URL and network/firewall settings.
