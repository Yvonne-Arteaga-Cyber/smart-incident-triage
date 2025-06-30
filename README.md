# 🛠️ Smart Incident Triage Tool

This project was created to simulate a basic incident response toolkit. It helps me understand how analysts run hash checks, apply rules to detect suspicious patterns, and log findings. I wanted it to look and feel real.

## 🧠 Why I Built It

As part of my cybersecurity learning journey, I wanted to create something I could use to show I understand how basic forensic tools work. I made this project from scratch to practice scripting, detection logic, and building clean outputs that could be used in real-world triage.

---

## 🔍 What It Does

- Calculates SHA256 hashes for uploaded text files.
- Scans files using custom YARA rules to detect specific strings or behaviors.
- Logs suspicious results into clear, readable reports (`.txt` or `.csv`).
- Simulates how a real analyst would process suspicious artifacts during triage.

---

## 📁 What’s Inside

- `scripts/` – Python files for hashing, scanning, and report generation.
- `sample_logs/` – Sample logs for practicing detection logic.
- `yara_rules/` – Custom rules to simulate real-world threat patterns.
- `simulated_malware.txt` – A sample text file with a detectable string.
- `scan_report_simulated_malware.txt` – The output report from a YARA scan.

---

## ▶️ How to Run It

1. Clone the repo:  
   `git clone https://github.com/Yvonne-Arteaga-Cyber/smart-incident-triage.git`

2. Navigate into the folder:  
   `cd smart-incident-triage`

3. Run the tool:  
   `python scripts/incident_triage_tool.py`

Make sure you have Python installed. It works best in a local dev environment for now.
