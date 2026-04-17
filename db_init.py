"""
Database initialization script for QShield
Creates all tables in the configured database (PostgreSQL or SQLite)
"""

from app import Base, engine

if __name__ == "__main__":
    print("Creating all tables...")
    Base.metadata.create_all(bind=engine)
    print("Done.")
