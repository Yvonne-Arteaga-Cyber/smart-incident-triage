# 🛠️ Smart Incident Triage Tool

This project was created to simulate a basic incident response toolkit. It helps me understand how analysts run hash checks, apply rules to detect suspicious patterns, and log findings. I wanted it to look and feel real.

## 🧠 Why I Built It

As part of my cybersecurity learning journey, I wanted to create something I could use to show I understand how basic forensic tools work. I made this project from scratch to practice scripting, detection logic, and building clean outputs that could be used in real-world triage.

---

## 🔍 What It Does

- Calculates SHA256 hashes for file verification
- Scans text files using custom YARA rules
- Logs suspicious results in text and CSV format

---

## 📁 What’s Inside

- `/scripts` – Python scripts that handle scanning and logging
- `/yara_rules` – Sample YARA rules
- `/sample_logs` – Example logs you can scan
- `simulated_malware.txt` – Fake malware text to test detection
- `scan_report_simulated_malware.txt` – Example output
- `suspicious_activity_output.csv` – CSV format of detection logs

---

## ▶️ How To Run It

Make sure Python is installed, then:

```bash
pip install -r requirements.txt
python scripts/forensic_checks.py
