import os
import time
import hashlib
import yara
from report_logger import generate_report

# 🔍 Known bad hashes (can expand this list)
known_bad_hashes = {
    "3a7bd3e2360a3432cd4f8a3a0d1b0d2c7a6dd56776cb7aa2f479ea5d3e0f9a3b",
}

def hash_check():
    file_to_check = input("🔎 Enter the path to the file you want to hash check: ").strip()

    if not os.path.isfile(file_to_check):
        print("❌ File not found.")
        return

    file_stats = os.stat(file_to_check)
    created = time.ctime(file_stats.st_ctime)
    modified = time.ctime(file_stats.st_mtime)
    accessed = time.ctime(file_stats.st_atime)

    with open(file_to_check, "rb") as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()
        print(f"📦 File SHA256 Hash: {file_hash}")

    print(f"📅 Created: {created}")
    print(f"🛠️ Modified: {modified}")
    print(f"👁️ Last Accessed: {accessed}")

    if file_hash in known_bad_hashes:
        print("🚨 Match found! This file matches a known bad hash.")
        generate_report(file_to_check, "Hash", "🚨 File matches known bad hash.")
    else:
        print("✅ No match found. File appears safe.")
        generate_report(file_to_check, "Hash", "✅ File appears safe.")

def yara_scan():
    if yara is None:
        print("⚠️ YARA module not installed. Please run: pip install yara-python")
        return

    file_path = input("🧪 Enter the path to the file you want to scan with YARA: ").strip()
    if not os.path.isfile(file_path):
        print("❌ File not found.")
        return

    rules = yara.compile(filepath="yara_rules/basic_malware.yar")

    try:
        matches = rules.match(file_path)
        if matches:
            print("🚨 YARA alert! Suspicious patterns found:")
            for match in matches:
                print(f"- {match.rule}")
            generate_report(file_path, "YARA", f"🚨 Suspicious pattern(s) found: {[match.rule for match in matches]}")
        else:
            print("✅ No suspicious patterns found.")
            generate_report(file_path, "YARA", "✅ File appears clean.")
    except Exception as e:
        print(f"⚠️ Error running YARA scan: {e}")

def view_last_report():
    import glob
    report_files = glob.glob("scan_report_*.txt")
    if not report_files:
        print("📭 No reports found.")
        return

    latest = max(report_files, key=os.path.getctime)
    print(f"\n📄 Opening latest report: {latest}\n")

    with open(latest, "r", encoding="utf-8") as f:
        print(f.read())

# 🧰 Main menu
def main():
    while True:
        print("\n🔧 Forensic Tool")
        print("1. Hash Check")
        print("2. YARA Scan")
        print("3. View Last Report")
        print("4. Exit")
        choice = input("Choose an option (1–4): ").strip()

        if choice == "1":
            hash_check()
        elif choice == "2":
            yara_scan()
        elif choice == "3":
            view_last_report()
        elif choice == "4":
            print("👋 Exiting Forensic Tool.")
            break
        else:
            print("❌ Invalid choice.")

if __name__ == "__main__":
    main()


