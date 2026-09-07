# src/matcher.py
import re
from packaging.version import parse as parse_version
from packaging.specifiers import SpecifierSet

import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from database import get_connection

def parse_requirements_txt(content: str) -> dict:
    dependencies = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        
        match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*(?:==|>=|<=|~=|>|<)?\s*([0-9a-zA-Z\.\-_+]+)?", line)
        if match:
            pkg = match.group(1).lower()
            ver = match.group(2) or "0.0.0"
            dependencies[pkg] = ver
    return dependencies

def scan_dependencies(dependencies: dict) -> list:
    if not dependencies:
        return []

    conn = get_connection()
    cursor = conn.cursor()

    pkg_names = list(dependencies.keys())
    placeholders = ",".join(["?"] * len(pkg_names))
    
    query = f"""
        SELECT cve_id, package_name, affected_range, fixed_version, severity, base_cvss, epss_score
        FROM vulnerabilities
        WHERE package_name IN ({placeholders})
    """
    cursor.execute(query, pkg_names)
    rows = cursor.fetchall()
    conn.close()

    findings = []
    for cve_id, pkg, affected_range, fixed_ver, severity, base_cvss, epss in rows:
        installed_ver_str = dependencies.get(pkg)
        if not installed_ver_str:
            continue
        
        try:
            installed_ver = parse_version(installed_ver_str)
            specifier = SpecifierSet(affected_range)
            
            if installed_ver in specifier:
                findings.append({
                    "cve_id": cve_id,
                    "package": pkg,
                    "installed_version": installed_ver_str,
                    "affected_range": affected_range,
                    "fixed_version": fixed_ver,
                    "severity": severity,
                    "base_cvss": float(base_cvss),
                    "epss_score": float(epss),
                    "is_direct": True
                })
        except Exception:
            continue

    return findings