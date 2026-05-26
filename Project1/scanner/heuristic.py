SUSPICIOUS_KEYWORDS = {
    "os.system": "High",
    "subprocess": "High",
    "eval(": "Medium",
    "exec(": "Medium",
    "powershell": "High",
    "cmd.exe": "High",
    "curl": "Medium",
    "wget": "Medium",
    "base64": "Medium"
}


def heuristic_scan(filepath):
    matches = []

    try:
        with open(filepath, "r", errors="ignore") as f:
            content = f.read().lower()
    except Exception:
        return matches

    for keyword, severity in SUSPICIOUS_KEYWORDS.items():
        if keyword.lower() in content:
            matches.append({
                "threat": f"Suspicious keyword: {keyword}",
                "severity": severity,
                "method": "HEURISTIC"
            })

    return matches