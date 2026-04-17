#!/usr/bin/env python
"""Direct test of login without browser."""

import sys
sys.path.insert(0, r"c:\Users\24bcscs005\Downloads\QShield-main (3)\QShield-main")

from app import SessionLocal, User, _verify_password

# TEST 1: Direct database check
print("TEST 1: Check database directly")
print("=" * 50)

db = SessionLocal()
admin = db.query(User).filter(User.username == "admin").first()

if not admin:
    print("ERROR: Admin not found in database!")
    sys.exit(1)

print(f"Username in DB: {admin.username}")
print(f"Role in DB: {admin.role}")
print(f"Active in DB: {admin.is_active}")
print(f"Hash in DB: {admin.password_hash[:40]}...")

# TEST 2: Direct password verification
print("\nTEST 2: Direct password verification")
print("=" * 50)

test_password = "admin123"
verify_result = _verify_password(test_password, admin.password_hash)

print(f"Input password: {test_password}")
print(f"Verification result: {verify_result}")

if verify_result:
    print("SUCCESS: Password verification works!")
else:
    print("ERROR: Password verification failed!")
    print(f"This means the login will fail in the browser too!")

# TEST 3: Simulate form submission (same as login endpoint would receive)
print("\nTEST 3: Simulate form submission")
print("=" * 50)

form_username = "admin"
form_password = "admin123"

print(f"Form data received:")
print(f"  username = '{form_username}'")
print(f"  password = '{form_password}'")

# Find user as endpoint would
user = db.query(User).filter(User.username == form_username).first()

if not user:
    print("ERROR: User not found (as endpoint sees it)")
else:
    print("OK: User found")
    
    # Verify password as endpoint would
    pw_verify = _verify_password(form_password, user.password_hash)
    print(f"OK: Password verification = {pw_verify}")
    
    if not user.is_active:
        print("ERROR: User is inactive")
    else:
        print("OK: User is active")
    
    if pw_verify and user.is_active:
        print("\nSUCCESS: Login should work in browser!")
    else:
        print("\nERROR: Login will fail in browser")

db.close()
