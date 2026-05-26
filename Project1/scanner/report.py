from datetime import datetime
import os

def generate_report(results, output_file="logs/scan_report.txt"):
    dir_name = os.path.dirname(output_file)
    if dir_name and not os.path.exists(dir_name):
        os.makedirs(dir_name)

    with open(output_file, "a") as f:

        f.write("=== Sentinel Scan Report ===\n")
        f.write(
            f"Scan Time: {datetime.now()}\n\n"
        )

        if not results:
            f.write("No threats found.\n")
            return

        for r in results:
            f.write(
                f"""
Path: {r['path']}
Threat: {r['threat']}
Severity: {r['severity']}
Method: {r['method']}
-----------------------------------
"""
            )

    print(f"\nReport saved to: {output_file}")