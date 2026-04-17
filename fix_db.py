#!/usr/bin/env python3
"""
Fix database schema - delete old DB and reinitialize
"""
import os
import time
import sqlite3

db_path = "qshield.db"

# Try to delete the database multiple times with retries
max_retries = 5
for attempt in range(max_retries):
    try:
        if os.path.exists(db_path):
            # Try to open and close it first to see if it's truly locked
            try:
                conn = sqlite3.connect(db_path, timeout=1)
                conn.close()
            except:
                pass
            
            # Now try to delete
            os.remove(db_path)
            print(f"✅ Database deleted successfully")
            break
    except PermissionError:
        if attempt < max_retries - 1:
            print(f"⏳ Database locked (attempt {attempt+1}/{max_retries}), retrying in 2 seconds...")
            time.sleep(2)
        else:
            print(f"❌ Could not delete database after {max_retries} attempts")
            print(f"   Please close the FastAPI server and run this script again")
            exit(1)

# Now recreate the database with correct schema
print("\n🔄 Initializing database with new schema...")
from app import Base, engine

try:
    Base.metadata.create_all(bind=engine)
    print("✅ Database initialized successfully with is_active column")
except Exception as e:
    print(f"❌ Error initializing database: {e}")
    exit(1)

# Verify the schema
print("\n✅ Verifying schema...")
conn = sqlite3.connect(db_path)
cursor = conn.cursor()
cursor.execute("PRAGMA table_info(users)")
columns = {col[1]: col[2] for col in cursor.fetchall()}
conn.close()

required_columns = ['id', 'username', 'password_hash', 'role', 'is_active', 'session_token', 'last_login', 'created_at']
missing = [col for col in required_columns if col not in columns]

if missing:
    print(f"❌ Missing columns: {missing}")
    exit(1)
else:
    print(f"✅ All required columns present: {list(columns.keys())}")
    print(f"\n✅ Database fix complete! You can now start the server.")
