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
            f.write(f"Path: {r['path']}\n")
            f.write(f"Threat: {r['threat']}\n")
            f.write(f"Severity: {r['severity']}\n")
            f.write(f"Method: {r['method']}\n")

            if "score" in r:
                f.write(f"Score: {r['score']}\n")

            if "reasons" in r:
                f.write("Reasons:\n")
                for reason in r["reasons"]:
                    f.write(f"  - {reason}\n")

            f.write("-----------------------------------\n")


    print(f"\nReport saved to: {output_file}")