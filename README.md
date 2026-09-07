# BlackBox-Audit: Resource Intelligence Engine

**A Local-First Dependency Risk Analyzer for Prioritized Remediation**  
*Team CodeStorm: Vikasini K • Varshini L • Vignesh S*

---

## 🚀 Key Innovations

1. **100% Offline-First Architecture**:
   - Zero runtime cloud API dependencies. Runs securely in air-gapped environments.
   - Periodic delta sync updates (< 200 KB) via USB or lightweight JSON patch files.

2. **Ultra-Low Storage (< 20 MB)**:
   - High-density indexed SQLite database (`cve_store.db`) instead of gigabytes of unstructured CVE dumps.

3. **Sub-Second PEP 440 Deterministic Matching**:
   - Evaluates hundreds of software dependencies in under 0.1 seconds with zero false positives.

4. **Offline Explainable AI (XAI)**:
   - Interpretable tree-based surrogate model ranking real-world risk using Base CVSS, EPSS exploit signals, direct reachability, and remediation friction.
   - Plain-English justifications for every security recommendation.

5. **1-Click Auto-Remediation**:
   - Automatically patches vulnerable manifests (`requirements.txt`) to the nearest safe versions with automated backup safety.

---

## 🛠️ How to Run

1. **Install Dependencies**:
   ```bash
   py -m pip install -r requirements.txt