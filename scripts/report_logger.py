import hashlib
import datetime

def generate_report(file_path, scan_type, result, matched_rules=None):
    try:
        file_name = file_path.split("\\")[-1]
        with open(file_path, "rb") as f:
            sha256_hash = hashlib.sha256(f.read()).hexdigest()

        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report_name = f"scan_report_{file_name}".replace(".txt", "") + ".txt"

        with open(report_name, "w", encoding="utf-8") as report:
            report.write("=== Forensics Report ===\n")
            report.write(f"Date: {timestamp}\n")
            report.write(f"File Scanned: {file_name}\n")
            report.write(f"SHA256: {sha256_hash}\n\n")
            report.write(f"Scan Type: {scan_type}\n")
            report.write(f"Result: {result}\n")

            if scan_type == "YARA" and matched_rules:
                report.write("\nMatched Rules:\n")
                for rule in matched_rules:
                    report.write(f"- {rule}\n")

        print(f"\n📄 Report saved as: {report_name}\n")

    except Exception as e:
        print(f"❌ Error creating report: {str(e)}")
