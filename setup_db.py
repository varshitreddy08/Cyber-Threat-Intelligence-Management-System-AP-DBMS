"""
CTIMS Database Setup Script
Connects to Neon PostgreSQL and runs all SQL schema files in order.
Run this ONCE to set up the database.
Usage: python setup_db.py
"""
import sys
import os

# Use the correct Python executable path
PYTHON_PATH = r"C:\Users\varsh\AppData\Local\Programs\Python\Python312\python.exe"

try:
    import psycopg2
except ImportError:
    print("psycopg2 not found. Install with: pip install psycopg2-binary")
    sys.exit(1)

# Neon PostgreSQL connection string
CONN_STR = (
    "host=ep-muddy-sea-b4anq2mq-pooler.c-6.us-east-2.aws.neon.tech "
    "dbname=neondb "
    "user=neondb_owner "
    "password=npg_8Tbm4ChDXQqf "
    "sslmode=require"
)

SQL_DIR = os.path.join(os.path.dirname(__file__), "sql")

SQL_FILES = [
    "01_schema.sql",
    "02_indexes.sql",
    "03_views.sql",
    "04_triggers.sql",
]

def run_sql_file(conn, filepath):
    print(f"\n>>> Running {os.path.basename(filepath)} ...")
    with open(filepath, "r", encoding="utf-8") as f:
        sql = f.read()
    try:
        with conn.cursor() as cur:
            cur.execute(sql)
        conn.commit()
        print(f"    OK")
    except Exception as e:
        conn.rollback()
        print(f"    ERROR: {e}")
        raise

def main():
    print("=" * 60)
    print("  CTIMS - Database Setup")
    print("  Connecting to Neon PostgreSQL...")
    print("=" * 60)

    try:
        conn = psycopg2.connect(CONN_STR)
        conn.autocommit = False
        print("[OK] Connected to Neon DB successfully!\n")
    except Exception as e:
        print(f"[FAIL] Connection error: {e}")
        sys.exit(1)

    for sql_file in SQL_FILES:
        filepath = os.path.join(SQL_DIR, sql_file)
        if os.path.exists(filepath):
            run_sql_file(conn, filepath)
        else:
            print(f"[WARN] File not found: {filepath}")

    conn.close()
    print("\n" + "=" * 60)
    print("  Database setup complete!")
    print("  Tables, indexes, views, and triggers are ready.")
    print("  Run the Java application to start using CTIMS.")
    print("=" * 60)

if __name__ == "__main__":
    main()
