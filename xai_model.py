# src/xai_model.py
import numpy as np
from sklearn.ensemble import RandomForestRegressor

class ExplainableRiskModel:
    def __init__(self):
        self.model = RandomForestRegressor(n_estimators=40, max_depth=4, random_state=42)
        self._train_surrogate()

    def _train_surrogate(self):
        np.random.seed(42)
        n = 400
        
        cvss = np.random.uniform(2.0, 10.0, n)
        epss = np.random.beta(0.5, 2.0, n)
        direct = np.random.choice([0, 1], n, p=[0.3, 0.7])
        has_fix = np.random.choice([0, 1], n, p=[0.1, 0.9])
        
        y = (cvss * 5.0) + (epss * 35.0) + (direct * 10.0) + (has_fix * 5.0)
        y = np.clip(y, 0, 100)
        
        X = np.column_stack([cvss, epss, direct, has_fix])
        self.model.fit(X, y)

    def explain(self, finding: dict) -> dict:
        cvss = finding["base_cvss"]
        epss = finding["epss_score"]
        direct = 1 if finding.get("is_direct", True) else 0
        has_fix = 1 if finding.get("fixed_version") else 0
        
        x_vec = np.array([[cvss, epss, direct, has_fix]])
        predicted_score = round(float(self.model.predict(x_vec)[0]), 1)
        
        attributions = {
            "CVSS Severity Impact": round(cvss * 5.0, 1),
            "Exploit Signal (EPSS)": round(epss * 35.0, 1),
            "Direct Asset Exposure": 10.0 if direct else 2.0,
            "Immediate Patch Fix": 5.0 if has_fix else 0.0
        }

        factors = []
        if cvss >= 8.5:
            factors.append(f"Critical base severity ({cvss}/10)")
        elif cvss >= 7.0:
            factors.append(f"High base severity ({cvss}/10)")
            
        if epss >= 0.5:
            factors.append(f"Active wild exploit detected ({epss*100:.1f}%)")
        elif epss >= 0.15:
            factors.append(f"Public exploit signal ({epss*100:.1f}%)")
            
        if direct:
            factors.append("Direct production dependency")
            
        if has_fix:
            action = f"Upgrade immediately to {finding['fixed_version']}"
        else:
            action = "No patch available; isolate dependency"

        explanation = (
            f"Prioritized at {predicted_score}/100 based on: "
            + " + ".join(factors)
            + f". Action: {action}."
        )

        return {
            "risk_score": predicted_score,
            "attributions": attributions,
            "explanation": explanation
        }