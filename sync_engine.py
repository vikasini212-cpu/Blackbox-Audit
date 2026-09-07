# src/sync_engine.py
import json
import os
from datetime import datetime

import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from database import get_connection
def apply_delta_patch(delta_json_path: str):
    if not os.path.exists(delta_json_path):
        raise FileNotFoundError(f"Delta file not found: {delta_json_path}")

    with open(delta_json_path, "r", encoding="utf-8") as f:
        updates = json.load(f)

    conn = get_connection()
    now = datetime.utcnow().isoformat()
    
    with conn:
        for row in updates:
            conn.execute("""
                INSERT INTO vulnerabilities 
                (cve_id, package_name, ecosystem, affected_range, fixed_version, severity, base_cvss, epss_score, last_updated)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(cve_id) DO UPDATE SET
                    affected_range=excluded.affected_range,
                    fixed_version=excluded.fixed_version,
                    severity=excluded.severity,
                    base_cvss=excluded.base_cvss,
                    epss_score=excluded.epss_score,
                    last_updated=excluded.last_updated
            """, (
                row["cve_id"],
                row["package_name"].lower(),
                row.get("ecosystem", "PyPI"),
                row["affected_range"],
                row["fixed_version"],
                row["severity"],
                float(row["base_score"]),
                float(row["epss_score"]),
                now
            ))
    conn.close()
    return len(updates)

if __name__ == "__main__":
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    delta_file = os.path.join(BASE_DIR, "data", "sample_delta.json")
    if os.path.exists(delta_file):
        count = apply_delta_patch(delta_file)
        print(f"Applied {count} delta updates.")