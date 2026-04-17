"""
Quick test script to verify PostgreSQL connection and table access
"""
from app import SessionLocal, User

def test_db():
    session = SessionLocal()
    try:
        # Try to add and query a user
        user = User(username="testuser", password_hash="dummyhash", role="tester")
        session.add(user)
        session.commit()
        found = session.query(User).filter_by(username="testuser").first()
        print("User found in DB:", found.username, found.role)
        # Clean up
        session.delete(found)
        session.commit()
        print("Test successful.")
    except Exception as e:
        print("DB test failed:", e)
    finally:
        session.close()

if __name__ == "__main__":
    test_db()
