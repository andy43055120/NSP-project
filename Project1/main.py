import json
import os

from scanner.hash_scanner import calculate_sha256
from scanner.pattern_scanner import scan_hex_pattern
from scanner.heuristic import heuristic_scan
from scanner.report import generate_report


def load_signatures(path):
    with open(path, "r") as f:
        return json.load(f)


def scan_directory(target_dir, signatures):
    sha256_signatures = {
        sig["signature"]: sig
        for sig in signatures
        if sig["type"] == "SHA256"
    }

    results = []

    for root, dirs, files in os.walk(target_dir):
        for filename in files:
            filepath = os.path.join(root, filename)
            file_hash = calculate_sha256(filepath)

            if file_hash in sha256_signatures:
                matched = sha256_signatures[file_hash]
                results.append({
                    "path": filepath,
                    "threat": matched["name"],
                    "severity": matched["severity"],
                    "method": "SHA256"
                })

            hex_results = scan_hex_pattern(filepath, signatures)

            for h in hex_results:
                results.append({
                    "path": filepath,
                    "threat": h["threat"],
                    "severity": h["severity"],
                    "method": h["method"]
                })

            heuristic_results = heuristic_scan(filepath)

            for h in heuristic_results:
                results.append({
                    "path": filepath,
                    "threat": h["threat"],
                    "severity": h["severity"],
                    "method": h["method"]
                })

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