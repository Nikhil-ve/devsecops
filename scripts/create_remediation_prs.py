import os
import json
import subprocess

def run_cmd(cmd: str):
    res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"[Warning] Command failed: {cmd}\nOutput: {res.stderr}")
    return res.stdout.strip()

def main():
    triage_file = "triage_output.json"
    if not os.path.exists(triage_file):
        print(f"[!] {triage_file} not found. Aborting PR creation.")
        return

    with open(triage_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    top_findings = data.get("top_findings", [])
    print(f"[*] Generating {len(top_findings)} Remediation Pull Requests...")

    # Configure Git identity for the CI runner
    run_cmd('git config user.name "DevSecOps-AI-Bot"')
    run_cmd('git config user.email "bot@devsecops-pipeline.local"')

    for item in top_findings:
        f_id = item["id"]
        title = item["vulnerability"]
        target_file = item["target_file"]
        explanation = item["root_cause_explanation"]
        fix = item["suggested_fix"]
        branch_name = f"ai-fix/finding-{f_id}"

        print(f"[*] Creating branch: {branch_name}")
        run_cmd(f"git checkout master")
        run_cmd(f"git checkout -B {branch_name}")

        # Write documentation/patch into remediation notes
        patch_file = f"REMEDIATION_FIX_{f_id}.md"
        with open(patch_file, "w", encoding="utf-8") as pf:
            pf.write(f"# AI Remediation Suggestion for {title}\n\n")
            pf.write(f"**Target File:** `{target_file}`\n")
            pf.write(f"**Scanner Source:** `{item.get('scanner')}`\n\n")
            pf.write(f"### Root Cause Analysis:\n{explanation}\n\n")
            pf.write(f"### Proposed Code Fix:\n```yaml\n{fix}\n```\n")

        run_cmd(f"git add {patch_file}")
        run_cmd(f'git commit -m "fix(security): automated remediation proposal for finding {f_id}"')
        run_cmd(f"git push origin {branch_name} --force")

        # Create Pull Request using GitHub CLI
        pr_body = f"""### 🛡️ Automated DevSecOps Triage Remediation
**Vulnerability**: {title}
**Target File**: `{target_file}`

#### Root Cause Analysis
{explanation}

#### Proposed Patch
