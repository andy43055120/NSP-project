import hashlib

def scan_hex_pattern(filepath, signatures):
    matches = []

    with open(filepath, "rb") as f:
        file_content = f.read().hex().upper()

    for sig in signatures:
        if sig["type"] == "HEX":
            pattern = sig["signature"].upper()

            if pattern in file_content:
                matches.append({
                    "threat": sig["name"],
                    "severity": sig["severity"],
                    "method": "HEX"
                })

    return matches

def scan_sha256_pattern(filepath, signatures):
    sha256_signatures = {
        sig["signature"]: sig
        for sig in signatures
        if sig["type"] == "SHA256"
    }
    results = []
    file_hash = ""
    with open(filepath, "rb") as f:
        file_hash = hashlib.file_digest(f, "sha256")
    if file_hash in sha256_signatures:
        matched = sha256_signatures[file_hash]
        results.append({
            "path": filepath,
            "threat": matched["name"],
            "severity": matched["severity"],
            "method": "SHA256"
        })
    return results