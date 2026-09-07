# src/remediator.py
import re
import os
import shutil
from datetime import datetime

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

    @staticmethod
    def backup_and_patch_file(filepath: str, fixes: dict) -> dict:
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = f"{filepath}.bak_{timestamp}"
        shutil.copyfile(filepath, backup_path)

        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()

        new_content, changes = ManifestRemediator.fix_requirements_content(content, fixes)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(new_content)

        return {
            "backup_file": backup_path,
            "changes_applied": changes
        }