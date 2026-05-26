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