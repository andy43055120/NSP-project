import os
import pefile


KEYWORD_SCORES = {
    "os.system": 3,
    "subprocess": 3,
    "eval(": 2,
    "exec(": 2,
    "powershell": 3,
    "cmd.exe": 2,
    "curl": 2,
    "wget": 2,
    "base64": 1,
}

IMPORT_SCORES = {
    "VirtualAlloc": 3,
    "WriteProcessMemory": 4,
    "CreateRemoteThread": 4,
    "LoadLibrary": 2,
    "GetProcAddress": 2,
    "WinExec": 3,
}

NETWORK_SCORES = {
    "socket": 2,
    "requests": 2,
    "urllib": 2,
    "connect": 2,
    "send(": 1,
    "recv(": 1,
    "ftp": 2,
    "http://": 2,
    "https://": 2,
}

OBFUSCATION_SCORES = {
    "b64decode": 3,
    "base64": 1,
    "marshal": 2,
    "zlib": 2,
}

PRIVILEGE_SCORES = {
    "runas": 3,
    "sedebugprivilege": 4,
    "sudo": 2,
    "setuid": 2,
}

COMBINATION_RULES = [
    (["powershell", "base64"], 4, "Encoded PowerShell payload"),
    (["os.system", "wget"], 4, "Command execution with payload download"),
    (["subprocess", "curl"], 4, "Subprocess download behavior"),
    (["socket", "exec("], 5, "Network activity with dynamic execution"),
    (["virtualalloc", "writeprocessmemory"], 5, "Possible memory injection behavior"),
    (["writeprocessmemory", "createremotethread"], 6, "Possible process injection behavior"),
]


def severity_from_score(score):
    if score >= 8:
        return "High"
    if score >= 4:
        return "Medium"
    return "Low"


def scan_score_group(content, score_dict, category):
    score = 0
    reasons = []

    for keyword, points in score_dict.items():
        if keyword.lower() in content:
            score += points
            reasons.append(f"{category}: {keyword} (+{points})")

    return score, reasons


def scan_combination_rules(content):
    score = 0
    reasons = []

    for keywords, points, description in COMBINATION_RULES:
        if all(keyword.lower() in content for keyword in keywords):
            score += points
            reasons.append(f"combination: {description} (+{points})")

    return score, reasons


def import_analysis(filepath):
    score = 0
    reasons = []

    try:
        pe = pefile.PE(filepath)
    except Exception:
        return score, reasons

    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return score, reasons

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            if imp.name is None:
                continue

            api_name = imp.name.decode(errors="ignore")

            for suspicious_api, points in IMPORT_SCORES.items():
                if api_name.lower() == suspicious_api.lower():
                    score += points
                    reasons.append(f"import: {api_name} (+{points})")

    return score, reasons


def pe_structure_scan(filepath, data):
    score = 0
    reasons = []

    ext = os.path.splitext(filepath)[1].lower()
    is_mz = data.startswith(b"MZ")

    if is_mz and ext not in [".exe", ".dll", ".sys"]:
        score += 6
        reasons.append(
            f"PE structure: disguised executable with {ext} extension (+6)"
        )

    embedded_offset = data.find(b"MZ", 1)

    if embedded_offset != -1 and ext not in [".exe", ".dll", ".sys"]:
        score += 5
        reasons.append(
            f"PE structure: possible embedded PE payload at offset {embedded_offset} (+5)"
        )

    return score, reasons


def heuristic_scan(filepath):
    matches = []

    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except Exception:
        return matches

    content = data.decode(errors="ignore").lower()

    total_score = 0
    reasons = []

    score, found = scan_score_group(content, KEYWORD_SCORES, "keyword")
    total_score += score
    reasons.extend(found)

    score, found = scan_score_group(content, NETWORK_SCORES, "network")
    total_score += score
    reasons.extend(found)

    score, found = scan_score_group(content, OBFUSCATION_SCORES, "obfuscation")
    total_score += score
    reasons.extend(found)

    score, found = scan_score_group(content, PRIVILEGE_SCORES, "privilege")
    total_score += score
    reasons.extend(found)

    score, found = scan_combination_rules(content)
    total_score += score
    reasons.extend(found)

    score, found = import_analysis(filepath)
    total_score += score
    reasons.extend(found)

    score, found = pe_structure_scan(filepath, data)
    total_score += score
    reasons.extend(found)

    if total_score >= 4:
        matches.append({
            "threat": "Heuristic suspicious behavior",
            "severity": severity_from_score(total_score),
            "method": "HEURISTIC-SCORE",
            "score": total_score,
            "reasons": reasons
        })

    return matches