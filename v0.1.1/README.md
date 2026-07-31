# 🐙 Project Octopus (v0.1.1)

Project Octopus (v0.1.1) is the eleventh release of the security regression and compliance validation suite. It focuses on the **State Persistence Engine**, verifying how conversation state, session caches, and threat signatures are stored, validated, and loaded across system boundaries.

---

## 🆕 New in v0.1.1

### 1. 💾 State Persistence Validation
The verifier runs compliance test scenarios verifying the integrity of Lobster's storage interfaces:
*   **Threat DB Integrity:** Validates that the static signature database [threat_db.json](file:///root/home/projects/project-lobster/v0.6.5/data/threat_db.json) is formatted correctly and readable under standard JSON parsing guidelines.
*   **Forensic Log Export:** Intercepts `export_report` within Project Lobster's TUI dashboard, verifies that the generated HTML and JSON report logs are properly written to disk, checks their serialized content logic, and safely cleans up temporary exports.
*   **Cache Serialization Check:** Simulates runtime cache conversions to verify that in-memory cache states serialize/deserialize to JSON format without data structure loss or key-type mismatches.

### 2. 📊 Persistence Status Tables
*   Reports in `./reports/` feature a **Conversation State Persistence Validation** table detailing test scenarios, expected outputs, and actual outcomes.
*   CLI standard output displays the full state persistence breakdown.

---

## 🚀 Execution & Usage

### Verify Target Codebase
To run the state and persistence-scored regression validation suite:
```bash
python3 octopus_verifier.py --target /path/to/project-lobster/v0.6.5
```

---

## 📈 Version Changelog
*   **v0.0.1 - v0.0.7:** Regression baselines, taxonomy refactors, URL/Unicode/Homoglyph encoding checks, and context boundary tests (Markdown, HTML, YAML, CDATA XML, CSV, Source scopes).
*   **v0.0.8:** Severity Engine. Grouped findings by risk levels (`Critical`, `High`, `Medium`, `Low`).
*   **v0.0.9:** Confidence Scoring. Implemented outcomes (`Complete Block`, `Partial Block`, `Partial Leak`, `Full Bypass`).
*   **v0.1.0:** Conversation State Compliance. Verified multi-turn context propagation, cache isolation, and rate-limiting limits.
*   **v0.1.1:** Conversation State Persistence. Verified threat database parsing, forensic report generation, and cache serialization format rules.
