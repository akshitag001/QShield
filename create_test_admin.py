#!/usr/bin/env python
"""Initialize test admin user for authentication testing."""

import os
import sys
sys.path.insert(0, os.path.dirname(__file__))

from app import SessionLocal, User, _hash_password

def create_test_admin():
    """Create a test admin user for testing."""
    db = SessionLocal()
    try:
        # Check if admin already exists
        admin = db.query(User).filter(User.username == "admin").first()
        if admin:
            print("Admin user already exists!")
            print(f"  Username: admin")
            print(f"  Role: {admin.role}")
            print(f"  Active: {admin.is_active}")
            
            # Optional: Update password if needed
            # Uncomment this section if you want to reset the password
            new_password = "admin123"
            admin.password_hash = _hash_password(new_password)
            db.commit()
            print(f"\nPassword updated to: {new_password}")
            return
        
        # Create admin with test credentials
        password = "admin123"
        password_hash = _hash_password(password)
        
        admin_user = User(
            username="admin",
            password_hash=password_hash,
            role="admin",
            is_active=True
        )
        
        db.add(admin_user)
        db.commit()
        
        print("SUCCESS! Test admin user created:")
        print(f"  Username: admin")
        print(f"  Password: {password}")
        print(f"  Role: admin")
        print(f"  Active: True")
        
    except Exception as e:
        print(f"ERROR: {e}")
        db.rollback()
        raise
    finally:
        db.close()

if __name__ == "__main__":
    create_test_admin()
