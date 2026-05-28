import json
import os

from scanner.pattern_scanner import scan_hex_pattern, scan_sha256_pattern
from scanner.heuristic import heuristic_scan
from scanner.report import generate_report


def load_signatures(path):
    with open(path, "r") as f:
        return json.load(f)


def scan_directory(target_dir, signatures):
    results = []

    for root, dirs, files in os.walk(target_dir):
        for filename in files:

            filepath = os.path.join(root, filename)

            all_results = []

            all_results.extend(
                scan_sha256_pattern(filepath, signatures)
            )

            all_results.extend(
                scan_hex_pattern(filepath, signatures)
            )

            all_results.extend(
                heuristic_scan(filepath)
            )

            for result in all_results:
                result["path"] = filepath
                results.append(result)

    return results


def main():
    signatures = load_signatures("signatures/signatures.json")
    results = scan_directory("test_files", signatures)

    if not results:
        print("No threats found.")
    else:
        print("Threats found:")
        for r in results:
            print(r)

    generate_report(results)


if __name__ == "__main__":
    main()