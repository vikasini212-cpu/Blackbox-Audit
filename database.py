# src/database.py
import sqlite3
import os
from datetime import datetime

# Automatically points to data/cve_store.db from the src folder
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "data", "cve_store.db")

def get_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    return sqlite3.connect(DB_PATH)

def init_database():
    conn = get_connection()
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                cve_id TEXT PRIMARY KEY,
                package_name TEXT NOT NULL,
                ecosystem TEXT DEFAULT 'PyPI',
                affected_range TEXT NOT NULL,
                fixed_version TEXT NOT NULL,
                severity TEXT NOT NULL,
                base_cvss REAL NOT NULL,
                epss_score REAL NOT NULL,
                last_updated TEXT NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_pkg ON vulnerabilities(package_name)")
    conn.close()

def seed_offline_data():
    init_database()
    base_cves = [
        ("CVE-2021-44228", "log4j-core", "PyPI", ">=2.0.0,<2.17.1", "2.17.1", "CRITICAL", 10.0, 0.97),
        ("CVE-2020-14343", "pyyaml", "PyPI", "<5.4", "5.4", "CRITICAL", 9.8, 0.85),
        ("CVE-2018-18074", "requests", "PyPI", ">=2.0.0,<2.20.0", "2.20.0", "HIGH", 7.5, 0.45),
        ("CVE-2019-11324", "urllib3", "PyPI", "<1.24.2", "1.24.2", "HIGH", 7.5, 0.38),
        ("CVE-2023-30861", "flask", "PyPI", "<2.2.5", "2.2.5", "MEDIUM", 6.5, 0.12),
        ("CVE-2022-42969", "py", "PyPI", "<1.11.0", "1.11.0", "HIGH", 7.5, 0.28),
        ("CVE-2021-33503", "urllib3", "PyPI", ">=1.25.0,<1.26.5", "1.26.5", "MEDIUM", 5.3, 0.08)
    ]
    
    conn = get_connection()
    now = datetime.utcnow().isoformat()
    with conn:
        for item in base_cves:
            conn.execute("""
                INSERT OR REPLACE INTO vulnerabilities 
                (cve_id, package_name, ecosystem, affected_range, fixed_version, severity, base_cvss, epss_score, last_updated)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (*item, now))
    conn.close()

if __name__ == "__main__":
    seed_offline_data()
    print("Database ready at:", DB_PATH)