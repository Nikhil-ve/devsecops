import os
import json
import argparse
from pathlib import Path

def parse_gitleaks(file_path):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    if not os.path.exists(file_path):
        return counts
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            # Gitleaks findings represent secrets (categorized as HIGH/CRITICAL)
            counts["HIGH"] = len(data) if isinstance(data, list) else 0
    except Exception:
        pass
    return counts

def parse_semgrep(file_path):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    if not os.path.exists(file_path):
        return counts
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            for res in data.get("results", []):
                sev = res.get("extra", {}).get("severity", "MEDIUM").upper()
                if sev in ["ERROR", "CRITICAL"]:
                    counts["CRITICAL"] += 1
                elif sev == "WARNING":
                    counts["HIGH"] += 1
                else:
                    counts["MEDIUM"] += 1
    except Exception:
        pass
    return counts

def parse_checkov(file_path):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    if not os.path.exists(file_path):
        return counts
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            reports = data if isinstance(data, list) else [data]
            for rep in reports:
                for failed in rep.get("results", {}).get("failed_checks", []):
                    sev = failed.get("severity")
                    if sev:
                        counts[sev.upper()] = counts.get(sev.upper(), 0) + 1
                    else:
                        counts["MEDIUM"] += 1
    except Exception:
        pass
    return counts

def parse_trivy(file_path):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    if not os.path.exists(file_path):
        return counts
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            for res in data.get("Results", []):
                for vuln in res.get("Vulnerabilities", []):
                    sev = vuln.get("Severity", "LOW").upper()
                    if sev in counts:
                        counts[sev] += 1
    except Exception:
        pass
    return counts

def parse_zap(file_path):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    if not os.path.exists(file_path):
        return counts
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            # ZAP alert riskcode: 3=High, 2=Medium, 1=Low, 0=Info
            for site in data.get("site", []):
                for alert in site.get("alerts", []):
                    risk = str(alert.get("riskcode", "1"))
                    if risk == "3":
                        counts["HIGH"] += 1
                    elif risk == "2":
                        counts["MEDIUM"] += 1
                    else:
                        counts["LOW"] += 1
    except Exception:
        pass
    return counts

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", default="scan-data")
    parser.add_argument("--output-file", default="METRICS_DASHBOARD.md")
    args = parser.parse_args()

    in_dir = Path(args.input_dir)
    gitleaks_stats = parse_gitleaks(in_dir / "gitleaks.json")
    semgrep_stats = parse_semgrep(in_dir / "semgrep.json")
    checkov_stats = parse_checkov(in_dir / "checkov.json")
    trivy_fs_stats = parse_trivy(in_dir / "trivy-fs.json")
    trivy_img_stats = parse_trivy(in_dir / "trivy-image.json")
    zap_stats = parse_zap(in_dir / "zap-report.json")

    stages = [
        {"Stage": "Secrets (Gitleaks)", "Counts": gitleaks_stats},
        {"Stage": "SAST (Semgrep)", "Counts": semgrep_stats},
        {"Stage": "IaC (Checkov)", "Counts": checkov_stats},
        {"Stage": "SCA Dependencies (Trivy)", "Counts": trivy_fs_stats},
        {"Stage": "Container OS (Trivy)", "Counts": trivy_img_stats},
        {"Stage": "DAST Runtime (OWASP ZAP)", "Counts": zap_stats},
    ]

    total_critical = sum(s["Counts"]["CRITICAL"] for s in stages)
    total_high = sum(s["Counts"]["HIGH"] for s in stages)
    total_med = sum(s["Counts"]["MEDIUM"] for s in stages)
    total_low = sum(s["Counts"]["LOW"] for s in stages)
    grand_total = total_critical + total_high + total_med + total_low

    # Markdown generation
    md = []
    md.append("# DevSecOps Shift-Left Security Metrics Dashboard\n")
    md.append("### Pipeline Run Summary\n")
    md.append(f"- **Total Security Findings Caught:** `{grand_total}`")
    md.append(f"- **Critical Vulnerabilities:** `{total_critical}`")
    md.append(f"- **High Risk Vulnerabilities:** `{total_high}`")
    md.append(f"- **Medium / Low Warnings:** `{total_med + total_low}`\n")
    md.append("| Pipeline Stage | Scanner | Critical | High | Medium | Low | Total Caught |")
    md.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |")

    for s in stages:
        c = s["Counts"]
        st_total = sum(c.values())
        scanner = s["Stage"].split("(")[1].replace(")", "")
        stage_name = s["Stage"].split("(")[0].strip()
        md.append(f"| {stage_name} | {scanner} | {c['CRITICAL']} | {c['HIGH']} | {c['MEDIUM']} | {c['LOW']} | **{st_total}** |")

    md.append(f"| **Totals** | — | **{total_critical}** | **{total_high}** | **{total_med}** | **{total_low}** | **{grand_total}** |\n")

    md.append("### Shift-Left Efficiency & Coverage Analysis\n")
    static_caught = sum(s["Counts"]["CRITICAL"] + s["Counts"]["HIGH"] for s in stages[:4])
    dynamic_caught = zap_stats["CRITICAL"] + zap_stats["HIGH"]
    total_severe = max(static_caught + dynamic_caught, 1)
    shift_left_pct = round((static_caught / total_severe) * 100, 2)

    md.append(f"- **Pre-Deployment Detection Rate (Shift-Left Ratio):** `{shift_left_pct}%`")
    md.append("- **Vulnerabilities Caught in Commit/Build Phase:** Secrets, AST code flaws, and vulnerable third-party packages.")
    md.append("- **Vulnerabilities Caught in Staging (DAST):** Missing HTTP response headers, CORS misconfigurations, anti-CSRF flags.")

    with open(args.output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(md))

    # Export machine-readable JSON for Week 3 GenAI ingestion
    with open("metrics_summary.json", "w", encoding="utf-8") as f:
        json.dump({"summary": stages, "total": grand_total, "shift_left_pct": shift_left_pct}, f, indent=2)

if __name__ == "__main__":
    main()
