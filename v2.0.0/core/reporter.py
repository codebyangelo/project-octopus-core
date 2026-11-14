# -*- coding: utf-8 -*-
"""
🐙 Project Octopus v2.0.0 - Universal Reporter
Generates machine-readable SARIF 2.1.0, flat JSON, and Markdown reports.
"""

import os
import json
from datetime import datetime, timezone
from typing import Dict, List, Any
from .models import TargetProfile, TestCase, ScanVerdict, VerdictStatus

STATUS_EMOJIS = {
    VerdictStatus.SAFE_BLOCK: "🟢 SAFE_BLOCK",
    VerdictStatus.SAFE_ALLOW: "🟢 SAFE_ALLOW",
    VerdictStatus.CRASH_FAIL: "🔴 CRASH_FAIL",
    VerdictStatus.BYPASS_FAIL: "🔴 BYPASS_FAIL",
    VerdictStatus.NOT_APPLICABLE: "⚪ N/A",
    VerdictStatus.SKIPPED: "⚪ SKIPPED"
}

class UniversalReporter:
    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def write_reports(
        self,
        profile: TargetProfile,
        results: List[Dict[str, Any]],
        stats: Dict[str, int],
        adapter_name: str
    ) -> Dict[str, str]:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        
        md_path = os.path.join(self.output_dir, f"octopus_report_{timestamp}.md")
        json_path = os.path.join(self.output_dir, f"octopus_summary_{timestamp}.json")
        sarif_path = os.path.join(self.output_dir, f"octopus_report_{timestamp}.sarif")

        self._write_markdown(md_path, profile, results, stats, adapter_name)
        self._write_json(json_path, profile, results, stats, adapter_name)
        self._write_sarif(sarif_path, profile, results)

        return {
            "markdown": md_path,
            "json": json_path,
            "sarif": sarif_path
        }

    def _write_markdown(
        self,
        filepath: str,
        profile: TargetProfile,
        results: List[Dict[str, Any]],
        stats: Dict[str, int],
        adapter_name: str
    ) -> None:
        evaluated_count = stats.get("evaluated", 0)
        passed_count = stats.get("passed", 0)
        score_pct = (passed_count / evaluated_count * 100.0) if evaluated_count > 0 else 100.0

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("# 🐙 Project Octopus v2.0.0: Upstream Verification Report\n\n")
            f.write(f"**Target Repository:** `{profile.target_path}`  \n")
            f.write(f"**Primary Language:** {profile.primary_language}  \n")
            f.write(f"**Architecture:** {profile.architecture_style}  \n")
            f.write(f"**Active Adapter:** {adapter_name}  \n")
            f.write(f"**Compliance Score:** **{score_pct:.1f}%** ({passed_count}/{evaluated_count} applicable tests passed)  \n\n")

            f.write("## 🏛️ Target Component Topology\n\n")
            f.write("```mermaid\n")
            f.write(profile.dependency_graph + "\n")
            f.write("```\n\n")

            f.write("## 🎯 Verification Results Matrix\n\n")
            f.write("| Suite | Test ID | Severity | Status | Latency | Details |\n")
            f.write("| :--- | :--- | :--- | :--- | :--- | :--- |\n")
            for r in results:
                status_str = STATUS_EMOJIS.get(r["status"], r["status"].value)
                lat = f"{r['latency_ms']:.1f}ms" if r.get("latency_ms") else "0.0ms"
                detail = r["analysis"].replace("|", "\\|")
                f.write(f"| {r['suite']} | `{r['id']}` | {r['severity']} | {status_str} | {lat} | {detail} |\n")
            f.write("\n")

            f.write("## 📊 Outcome Summary\n\n")
            f.write(f"- **Evaluated:** {evaluated_count}\n")
            f.write(f"- **Passed (Safe Block / Allow):** {passed_count}\n")
            f.write(f"- **Crashed (SIGSEGV / Fault):** {stats.get('crashed', 0)}\n")
            f.write(f"- **Bypassed (Missing Clamp):** {stats.get('bypassed', 0)}\n")
            f.write(f"- **Not Applicable (Excluded):** {stats.get('not_applicable', 0)}\n")
            f.write(f"- **Skipped (Missing Tools):** {stats.get('skipped', 0)}\n")

    def _write_json(
        self,
        filepath: str,
        profile: TargetProfile,
        results: List[Dict[str, Any]],
        stats: Dict[str, int],
        adapter_name: str
    ) -> None:
        data = {
            "version": "2.0.0",
            "target": profile.target_path,
            "primary_language": profile.primary_language,
            "architecture": profile.architecture_style,
            "adapter": adapter_name,
            "stats": stats,
            "results": [
                {
                    "id": r["id"],
                    "suite": r["suite"],
                    "severity": r["severity"],
                    "status": r["status"].value,
                    "analysis": r["analysis"],
                    "latency_ms": r.get("latency_ms", 0.0)
                }
                for r in results
            ]
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def _write_sarif(
        self,
        filepath: str,
        profile: TargetProfile,
        results: List[Dict[str, Any]]
    ) -> None:
        rules = []
        sarif_results = []
        rule_ids = set()

        for r in results:
            rid = r["id"]
            if rid not in rule_ids:
                rule_ids.add(rid)
                rules.append({
                    "id": rid,
                    "shortDescription": {"text": f"{r['suite']}: {r.get('description', '')}"},
                    "properties": {
                        "severity": r["severity"],
                        "svap_tier": r.get("svap_tier", "")
                    }
                })

            # Emit SARIF errors strictly for genuine boundary failures
            if r["status"] in (VerdictStatus.CRASH_FAIL, VerdictStatus.BYPASS_FAIL):
                level = "error" if r["severity"] in ("Critical", "High") else "warning"
                sarif_results.append({
                    "ruleId": rid,
                    "level": level,
                    "message": {"text": f"Boundary failure: {r['analysis']}"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": os.path.basename(profile.target_path)}
                        }
                    }]
                })

        sarif_data = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Project Octopus",
                        "version": "2.0.0",
                        "informationUri": "https://github.com/codebyangelo/project-octopus",
                        "rules": rules
                    }
                },
                "results": sarif_results
            }]
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(sarif_data, f, indent=2)
