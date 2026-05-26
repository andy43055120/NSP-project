from datetime import datetime


def generate_report(results, output_file="logs/scan_report.txt"):
    with open(output_file, "w") as f:

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