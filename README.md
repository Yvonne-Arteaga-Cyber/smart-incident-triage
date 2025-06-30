# Smart Incident Triage Tool

This project was created to simulate a basic forensic triage process using Python and YARA. It helped me understand how analysts run hash checks, apply rules to detect threats, and log everything they find. I learned a lot doing this and wanted it to look and feel real.

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
