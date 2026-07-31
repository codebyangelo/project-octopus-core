# INSTALL.md
## Phase 6 - Installation & Environment Setup Guide

This document provides instructions for setting up, configuring, and verifying **Project Octopus** (`v1.0.6`) on Linux and mobile Unix environments (such as Termux/PRoot).

---

### 1. Prerequisites

Before installing Project Octopus, ensure your environment meets the following requirements:

* **Operating System**: Linux / Unix (Debian/Ubuntu, RHEL/Fedora, Arch Linux, or Android Termux/PRoot verified).
* **Python Runtime**: Python 3.10 or higher (Python 3.13 verified).
* **Built-in Python Modules**: `os`, `sys`, `re`, `json`, `argparse`, `datetime`
* **Optional Dependencies** *(For enriched formatting & network tests)*:
  * `python3-psutil` / `psutil` (for system resource telemetry)
  * `rich` (for terminal TUI formatting)
  * `requests` (for network boundary verification)

---

### 2. Installation & Setup

1. **Clone or Extract the Repository**:
   ```bash
   git clone https://github.com/your-org/project-octopus.git
   cd project-octopus-git/v1.0.6
   ```

2. **Set Up a Virtual Environment** *(Recommended)*:
   ```bash
   python3 -m venv --system-site-packages venv
   source venv/bin/activate
   ```

3. **Install Optional Package Dependencies**:
   ```bash
   pip install rich requests
   ```

---

### 3. Verification & Execution Commands

Verify that Project Octopus is properly installed by running profile queries and test executions:

1. **List All Available Validation Profiles**:
   ```bash
   python3 octopus_verifier.py --list-profiles
   ```

2. **Run Automatic Repository Profiling & Verification**:
   ```bash
   python3 octopus_verifier.py --target /root/home/projects/project-octopus-git/v1.0.6
   ```

3. **Run Specific Validation Profiles** (e.g. Generic & Optimizer):
   ```bash
   python3 octopus_verifier.py --target /root/home/projects/project-hermit-git/v0.1.9 --profile generic,optimizer
   ```

4. **Inspect Generated Report Outputs**:
   Report deliverables will be saved to `./reports/`:
   * `project_profile.md` (Repository discovery topology)
   * `octopus_report_<timestamp>.md` (Security regression report)
   * `octopus_report_<timestamp>.sarif` (SARIF 2.1.0 report)
   * `octopus_summary.json` (Flat JSON summary)
   * `compliance_badge.svg` (SVG status badge)
