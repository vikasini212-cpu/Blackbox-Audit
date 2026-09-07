# app.py - BlackBox-Audit (Pure Python, Zero-DLL, 100% Windows Compatible)
import streamlit as st
import sqlite3
import os
import re
from datetime import datetime

# ==========================================
# 1. DATABASE ENGINE (SQLITE)
# ==========================================
DB_DIR = "data"
DB_PATH = os.path.join(DB_DIR, "cve_store.db")

def init_and_seed_db():
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
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
        
        base_cves = [
            ("CVE-2021-44228", "log4j-core", "PyPI", ">=2.0.0,<2.17.1", "2.17.1", "CRITICAL", 10.0, 0.97),
            ("CVE-2020-14343", "pyyaml", "PyPI", "<5.4", "5.4", "CRITICAL", 9.8, 0.85),
            ("CVE-2018-18074", "requests", "PyPI", ">=2.0.0,<2.20.0", "2.20.0", "HIGH", 7.5, 0.45),
            ("CVE-2019-11324", "urllib3", "PyPI", "<1.24.2", "1.24.2", "HIGH", 7.5, 0.38),
            ("CVE-2023-30861", "flask", "PyPI", "<2.2.5", "2.2.5", "MEDIUM", 6.5, 0.12),
            ("CVE-2022-42969", "py", "PyPI", "<1.11.0", "1.11.0", "HIGH", 7.5, 0.28),
            ("CVE-2021-33503", "urllib3", "PyPI", ">=1.25.0,<1.26.5", "1.26.5", "MEDIUM", 5.3, 0.08)
        ]
        now = datetime.utcnow().isoformat()
        for item in base_cves:
            conn.execute("""
                INSERT OR REPLACE INTO vulnerabilities 
                (cve_id, package_name, ecosystem, affected_range, fixed_version, severity, base_cvss, epss_score, last_updated)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (*item, now))
    conn.close()

# ==========================================
# 2. DETERMINISTIC VERSION MATCHER
# ==========================================
def parse_version_tuple(v_str):
    clean = re.sub(r"[^\d.]", "", v_str)
    parts = [int(p) for p in clean.split(".") if p.isdigit()]
    return parts or [0]

def is_version_vulnerable(installed_str, spec_str):
    try:
        inst = parse_version_tuple(installed_str)
        specs = spec_str.split(",")
        for sp in specs:
            sp = sp.strip()
            if sp.startswith("<="):
                if not (inst <= parse_version_tuple(sp[2:])): return False
            elif sp.startswith("<"):
                if not (inst < parse_version_tuple(sp[1:])): return False
            elif sp.startswith(">="):
                if not (inst >= parse_version_tuple(sp[2:])): return False
            elif sp.startswith(">"):
                if not (inst > parse_version_tuple(sp[1:])): return False
            elif sp.startswith("=="):
                if not (inst == parse_version_tuple(sp[2:])): return False
        return True
    except:
        return False

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
    conn = sqlite3.connect(DB_PATH)
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
        if is_version_vulnerable(installed_ver_str, affected_range):
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
    return findings

# ==========================================
# 3. OFFLINE EXPLAINABLE AI (PURE PYTHON)
# ==========================================
class OfflineExplainableAI:
    @staticmethod
    def explain(finding: dict) -> dict:
        cvss = finding["base_cvss"]
        epss = finding["epss_score"]
        direct = 1 if finding.get("is_direct", True) else 0
        has_fix = 1 if finding.get("fixed_version") else 0
        
        cvss_impact = round(cvss * 5.0, 1)
        epss_impact = round(epss * 35.0, 1)
        direct_impact = 10.0 if direct else 2.0
        fix_impact = 5.0 if has_fix else 0.0

        total_score = min(100.0, cvss_impact + epss_impact + direct_impact + fix_impact)

        factors = []
        if cvss >= 8.5:
            factors.append(f"Critical base severity ({cvss}/10)")
        elif cvss >= 7.0:
            factors.append(f"High base severity ({cvss}/10)")
            
        if epss >= 0.5:
            factors.append(f"Active in-the-wild exploit detected ({epss*100:.1f}%)")
        elif epss >= 0.15:
            factors.append(f"Public exploit signal ({epss*100:.1f}%)")
            
        if direct:
            factors.append("Direct production dependency")
            
        if has_fix:
            action = f"Upgrade immediately to {finding['fixed_version']}"
        else:
            action = "No patch available; isolate dependency"

        explanation = f"Prioritized at {round(total_score, 1)}/100 based on: " + " + ".join(factors) + f". Action: {action}."

        return {
            "risk_score": round(total_score, 1),
            "attributions": {
                "CVSS Severity Impact": cvss_impact,
                "Exploit Signal (EPSS)": epss_impact,
                "Direct Asset Exposure": direct_impact,
                "Immediate Patch Fix": fix_impact
            },
            "explanation": explanation
        }

# ==========================================
# 4. AUTO-REMEDIATOR (PATCH ENGINE)
# ==========================================
class ManifestRemediator:
    @staticmethod
    def fix_requirements_content(original_content: str, fixes: dict) -> tuple[str, list]:
        lines = original_content.splitlines()
        remediated_lines = []
        applied_changes = []

        for line in lines:
            stripped = line.strip()
            matched = False
            for pkg, target_ver in fixes.items():
                pattern = rf"^({re.escape(pkg)})\s*([=><~!].*)?$"
                match = re.match(pattern, stripped, re.IGNORECASE)
                if match:
                    new_line = f"{match.group(1)}=={target_ver}"
                    remediated_lines.append(new_line)
                    applied_changes.append({
                        "Package": pkg,
                        "Original Version": stripped,
                        "Patched Version": new_line
                    })
                    matched = True
                    break
            if not matched:
                remediated_lines.append(line)

        return "\n".join(remediated_lines), applied_changes


# ==========================================
# 5. STREAMLIT UI (100% PURE PYTHON)
# ==========================================
st.set_page_config(
    page_title="BlackBox-Audit | Local-First Dependency Risk Analyzer",
    page_icon="🛡️",
    layout="wide"
)

init_and_seed_db()

# Sidebar
st.sidebar.title("🛡️ BlackBox-Audit")
st.sidebar.markdown("**Team CodeStorm**")
st.sidebar.markdown("---")
st.sidebar.caption("Status: 🟢 **100% Offline (Zero-DLL Mode)**")

demo_manifest = """log4j-core==2.14.1
pyyaml==5.3
flask==2.0.0
requests==2.18.4
urllib3==1.24.1
pandas==2.2.0
numpy==1.26.4
scikit-learn==1.4.0
"""

option = st.sidebar.radio("Input Source", ["Use Demo Manifest", "Upload requirements.txt"])

if option == "Upload requirements.txt":
    uploaded = st.sidebar.file_uploader("Choose a requirements.txt file", type=["txt"])
    manifest_content = uploaded.getvalue().decode("utf-8") if uploaded else ""
else:
    manifest_content = demo_manifest

st.title("BlackBox-Audit: Resource Intelligence Engine")
st.markdown("A local-first dependency risk analyzer providing **Explainable Prioritization (XAI)** and **Automated 1-Click Remediation**.")

if not manifest_content:
    st.info("Please upload or provide a dependency manifest to begin analysis.")
    st.stop()

# Scanning
parsed_deps = parse_requirements_txt(manifest_content)
raw_findings = scan_dependencies(parsed_deps)

findings = []
fixes_available = {}
for f in raw_findings:
    explanation_data = OfflineExplainableAI.explain(f)
    f.update(explanation_data)
    findings.append(f)
    if f.get("fixed_version"):
        fixes_available[f["package"]] = f["fixed_version"]

findings.sort(key=lambda x: x["risk_score"], reverse=True)

# KPI Metric Cards
crit_count = sum(1 for f in findings if f["severity"] == "CRITICAL")
high_count = sum(1 for f in findings if f["severity"] == "HIGH")
med_low_count = len(findings) - crit_count - high_count

c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Dependencies Parsed", len(parsed_deps))
c2.metric("Critical Exposure", crit_count, delta="Immediate Action" if crit_count > 0 else "Clean", delta_color="inverse")
c3.metric("High Exposure", high_count)
c4.metric("Med / Low", med_low_count)
c5.metric("Auto-Fixable", len(fixes_available))

st.markdown("---")

# 1-Click Auto-Fix Section
if fixes_available:
    st.subheader("⚡ 1-Click Auto-Remediation")
    st.write(f"The engine discovered **{len(fixes_available)}** vulnerabilities that can be automatically fixed.")
    
    col_btn, col_down = st.columns([2, 3])
    with col_btn:
        if st.button("🚀 Automatically Fix All Vulnerabilities", type="primary"):
            patched_text, changes = ManifestRemediator.fix_requirements_content(manifest_content, fixes_available)
            st.session_state["patched_text"] = patched_text
            st.session_state["changes"] = changes
            st.success(f"Successfully remediated {len(changes)} packages to safe versions!")

    if "patched_text" in st.session_state:
        with col_down:
            st.download_button(
                label="📥 Download Remediated requirements.txt",
                data=st.session_state["patched_text"],
                file_name="requirements_remediated.txt",
                mime="text/plain"
            )
        with st.expander("View Auto-Remediation Changes"):
            for item in st.session_state["changes"]:
                st.write(f"• **{item['Package']}**: `{item['Original Version']}` ➔ `{item['Patched Version']}`")

st.markdown("---")

# Priority Ranking Visualizer (Zero Pandas, Native HTML)
if findings:
    st.subheader("📊 Remediation Priority Ranking")
    for f in findings:
        pkg = f["package"]
        score = f["risk_score"]
        color = "#ff4b4b" if score >= 80 else "#ffa421" if score >= 60 else "#21c354"
        
        st.markdown(f"""
        <div style="margin-bottom: 12px; background-color: #1e212d; padding: 10px; border-radius: 8px;">
            <div style="display:flex; justify-content:space-between; font-weight:600; margin-bottom:6px;">
                <span>📦 <b>{pkg}</b> <span style="color:{color}; font-size:12px;">[{f['severity']}]</span></span>
                <span style="color:{color}; font-size:14px;">Risk Score: {score} / 100</span>
            </div>
            <div style="background-color:#31333f; border-radius:6px; overflow:hidden; height:10px;">
                <div style="background-color:{color}; width:{score}%; height:100%; border-radius:6px;"></div>
            </div>
        </div>
        """, unsafe_allow_html=True)
# Explainable Findings Drawer
st.subheader("🔍 Explainable Security Findings")
for item in findings:
    score = item["risk_score"]
    with st.expander(f"[{item['severity']}] {item['package']} {item['installed_version']} ➔ Target Fix: {item['fixed_version']} (XAI Score: {score}/100)"):
        st.markdown(f"**CVE ID:** `{item['cve_id']}`")
        st.markdown(f"**Affected Specifier:** `{item['affected_range']}`")
        st.markdown(f"**Base CVSS:** `{item['base_cvss']}` | **EPSS Exploit Signal:** `{item['epss_score']*100:.1f}%`")
        st.info(f"💡 **AI Explainability Rationale:**\n\n{item['explanation']}")
        
        st.markdown("**Feature Attribution Breakdown:**")
        cols = st.columns(4)
        attrs = list(item["attributions"].items())
        for i, (name, val) in enumerate(attrs):
            cols[i].metric(name, f"+{val} pts")

if not findings:
    st.success("🎉 Zero known vulnerabilities detected in your dependencies!")