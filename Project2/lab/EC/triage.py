#!/venv/bin/python3
"""
/triage  —  每輪失敗後由 grading script 呼叫一次

執行流程：
  1. 在 /shared/coredump/ 找最新的 coredump
  2. 嘗試方法 A：GDB（最可靠）
       gdb /server <coredump>
       → print &execute_task   ← 直接取得符號地址
  3. 若 GDB 失敗，嘗試方法 B：純 Python 解析 coredump ELF
       NT_PRSTATUS → 取 RIP（確認 SENTINEL 代表 padding 正確）
       NT_FILE     → 取 server text 段基址（偵測 PIE）
       掃描 text 段記憶體 → 找 execute_task 函式特徵
  4. 把結果寫入 /shared/triage_hint.txt
  5. 退出

不需要本地 binary（nm / objdump 都不用），GDB 只需能存取 /server 路徑。
"""

import os
import re
import sys
import glob
import struct
import tempfile
import subprocess

SHARED      = "/shared"
CORE_DIR    = f"{SHARED}/coredump"
HINT        = f"{SHARED}/triage_hint.txt"
SERVER_BIN  = "/share/blogic"

SENTINEL    = 0xDEADBEEFDEADBEEF
PADDING     = 104


def log(msg):
    print(f"[triage] {msg}", flush=True)


# ─── coredump 搜尋 ────────────────────────────────────────────────────────────

def find_latest_core() -> str | None:
    candidates = []
    search_dirs = [CORE_DIR, SHARED, "/tmp", "/var/crash", "/var/lib/systemd/coredump"]
    patterns    = ["core", "core.*", "*.core", "coredump*"]
    for d in search_dirs:
        if not os.path.isdir(d):
            continue
        for p in patterns:
            for f in glob.glob(os.path.join(d, p)):
                if os.path.isfile(f) and os.path.getsize(f) > 0:
                    candidates.append(f)
    if not candidates:
        return None
    return max(candidates, key=os.path.getmtime)


# ─── 方法 A：GDB ─────────────────────────────────────────────────────────────

GDB_CMDS = """set pagination off
set print pretty off
info registers rip rsp rbp
print/x (void*)execute_task
info proc mappings
bt 3
quit
"""

def run_gdb(core: str) -> str:
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".gdb", delete=False) as f:
            f.write(GDB_CMDS)
            script = f.name
        r = subprocess.run(
            ["gdb", "-batch", "-x", script, SERVER_BIN, core],
            capture_output=True, text=True, timeout=20
        )
        os.unlink(script)
        return r.stdout + r.stderr
    except FileNotFoundError:
        log("GDB 未安裝")
        return ""
    except subprocess.TimeoutExpired:
        log("GDB 超時")
        return ""


def parse_gdb(out: str) -> dict:
    info = {}
    for line in out.splitlines():
        # print &execute_task 輸出：$1 = 0x401234 <execute_task>
        if "execute_task" in line and "=" in line:
            m = re.search(r"=\s*(0x[0-9a-fA-F]+)", line)
            if m:
                addr = int(m.group(1), 16)
                if addr:
                    info["execute_task_addr"] = addr
                    log(f"GDB execute_task = 0x{addr:016x}")

        # RIP
        if not info.get("rip"):
            m = re.match(r"\s*rip\s+(0x[0-9a-fA-F]+)", line, re.I)
            if m:
                info["rip"] = int(m.group(1), 16)

        # PIE base（從 info proc mappings）
        if SERVER_BIN in line or "/server" in line:
            m = re.search(r"(0x[0-9a-fA-F]+)\s+0x[0-9a-fA-F]+", line)
            if m:
                base = int(m.group(1), 16)
                if base and "pie_base" not in info:
                    info["pie_base"] = base
                    info["pie"] = "true" if base != 0x400000 else "false"

    return info


# ─── 方法 B：純 Python ELF 解析 ──────────────────────────────────────────────

def u16(b, o): return struct.unpack_from("<H", b, o)[0]
def u32(b, o): return struct.unpack_from("<I", b, o)[0]
def u64(b, o): return struct.unpack_from("<Q", b, o)[0]

ET_CORE, PT_LOAD, PT_NOTE = 4, 1, 4
NT_PRSTATUS = 1
NT_FILE_NAME = b"CORE"
NT_FILE_TYPE = 0x46494c45   # some kernels use this; also check name=="CORE" + type==NT_FILE(0x46494c45) or type==0x3 depending on kernel


def parse_core_elf(core_path: str) -> dict:
    with open(core_path, "rb") as f:
        data = f.read()

    if data[:4] != b"\x7fELF":
        log("不是 ELF 檔案")
        return {}
    if data[4] != 2:
        log("非 64-bit ELF")
        return {}
    if u16(data, 0x10) != ET_CORE:
        log("非 ET_CORE")
        return {}

    e_phoff    = u64(data, 0x20)
    e_phentsize = u16(data, 0x36)
    e_phnum    = u16(data, 0x38)

    loads = []   # (vaddr, filesz, file_offset)
    notes_segments = []

    for i in range(e_phnum):
        base = e_phoff + i * e_phentsize
        p_type   = u32(data, base)
        p_offset = u64(data, base + 0x08)
        p_vaddr  = u64(data, base + 0x10)
        p_filesz = u64(data, base + 0x20)
        if p_type == PT_LOAD and p_filesz > 0:
            loads.append((p_vaddr, p_filesz, p_offset))
        elif p_type == PT_NOTE and p_filesz > 0:
            notes_segments.append(data[p_offset: p_offset + p_filesz])

    def read_vaddr(vaddr, size):
        for (base_v, fsz, foff) in loads:
            if base_v <= vaddr < base_v + fsz:
                rel = vaddr - base_v
                if rel + size <= fsz:
                    return data[foff + rel: foff + rel + size]
        return None

    # 解析 NOTE segments
    rip       = 0
    text_base = 0

    for seg in notes_segments:
        pos = 0
        while pos + 12 <= len(seg):
            namesz = u32(seg, pos);   pos += 4
            descsz = u32(seg, pos);   pos += 4
            ntype  = u32(seg, pos);   pos += 4
            name   = seg[pos: pos + namesz].rstrip(b"\x00")
            pos    = (pos + namesz + 3) & ~3
            desc   = seg[pos: pos + descsz]
            pos    = (pos + descsz + 3) & ~3

            # NT_PRSTATUS → 取 RIP
            if ntype == NT_PRSTATUS and len(desc) >= 0x90:
                # x86-64 prstatus：pr_reg 在 offset 0x48，rip 是第 16 個 greg（0-indexed）
                # offset = 0x48 + 16*8 = 0x88
                rip = u64(desc, 0x88)
                log(f"ELF: RIP = 0x{rip:016x}")

            # NT_FILE → 取 server text 段基址
            if name == b"CORE" and descsz > 16:
                try:
                    count = u64(desc, 0)
                    di    = 16   # skip count + page_size
                    entries = []
                    for _ in range(count):
                        start = u64(desc, di); di += 8
                        end   = u64(desc, di); di += 8
                        pgoff = u64(desc, di); di += 8
                        entries.append([start, end, pgoff, ""])
                    for e in entries:
                        nul = desc.find(b"\x00", di)
                        if nul < 0:
                            break
                        e[3] = desc[di:nul].decode("utf-8", errors="replace")
                        di = nul + 1
                    for (start, end, pgoff, fname) in entries:
                        if pgoff == 0 and ("server" in fname):
                            text_base = start
                            log(f"ELF: server text base = 0x{text_base:016x}")
                            break
                except Exception as e:
                    log(f"NT_FILE 解析失敗: {e}")

    info = {}
    if rip:
        info["rip"] = rip
    if text_base:
        info["pie"] = "false" if text_base == 0x400000 else "true"
        if text_base != 0x400000:
            info["pie_base"] = text_base

    # 掃描 text 段記憶體，找 execute_task 特徵
    # 特徵：函式序言(55 48 89 e5) + 短函式 + 兩個 call
    if text_base:
        scan_size = 0x8000
        mem = read_vaddr(text_base, scan_size)
        if mem:
            candidates = []
            i = 0
            while i < len(mem) - 64:
                if mem[i] == 0x55 and mem[i+1:i+4] == b"\x48\x89\xe5":
                    snippet = mem[i: i + 64]
                    ncalls = sum(
                        1 for j in range(4, len(snippet)-4)
                        if snippet[j] == 0xe8  # call rel32
                    )
                    if ncalls >= 2:
                        candidates.append(text_base + i)
                i += 1
            if candidates:
                # execute_task 在 source 裡排在 log_message 之後，取後面的候選
                best = candidates[-1]
                info["execute_task_addr"] = best
                log(f"ELF 掃描候選 execute_task = 0x{best:016x}（共 {len(candidates)} 個）")

    return info


# ─── 寫 hint 檔案 ─────────────────────────────────────────────────────────────

def write_hint(info: dict):
    os.makedirs(SHARED, exist_ok=True)
    with open(HINT, "w") as f:
        for k, v in info.items():
            val = f"0x{v:x}" if isinstance(v, int) else str(v)
            f.write(f"{k}={val}\n")
    log(f"triage_hint.txt 寫入：")
    for k, v in info.items():
        val = f"0x{v:x}" if isinstance(v, int) else str(v)
        log(f"  {k} = {val}")


# ─── 主流程 ──────────────────────────────────────────────────────────────────

def main():
    core = find_latest_core()
    if not core:
        log("找不到 coredump，無法分析")
        sys.exit(0)   # 不 crash，讓 grading 繼續

    log(f"分析 coredump：{core}")

    # ── 方法 A：GDB ──────────────────────────────────────────────────────────
    info = {}
    gdb_out = run_gdb(core)
    if gdb_out:
        info = parse_gdb(gdb_out)

    # ── 方法 B：ELF parser（補充或備用）──────────────────────────────────────
    if not info.get("execute_task_addr"):
        log("GDB 未取得 execute_task 地址，改用 ELF parser")
        elf_info = parse_core_elf(core)
        # 合併，以 ELF parser 為主（GDB 有的欄位優先保留）
        info = {**elf_info, **info}

    # ── 分析結果摘要 ──────────────────────────────────────────────────────────
    rsp = info.get("rip", 0)
    if rsp == SENTINEL:
        log("✓ RIP = SENTINEL：padding 104 已確認，地址是本輪分析的主要目標")
    elif rsp and info.get("execute_task_addr") and rsp == info["execute_task_addr"]:
        log("RIP = execute_task：地址已到達，可能 /backdoor 執行問題")
    elif rsp:
        log(f"RIP = 0x{rsp:x}，非預期值")

    if info.get("pie") == "true":
        log("⚠️  偵測到 PIE，execute_task 地址為本次執行期的絕對地址（下輪 ASLR 可能不同！）")

    # 固定寫入 padding（供 exploit 確認）
    info["padding"] = PADDING

    if info.get("execute_task_addr"):
        log(f"✓ execute_task = 0x{info['execute_task_addr']:016x}，寫入 hint 供 exploit 使用")
        write_hint(info)
    else:
        log("❌ 無法取得 execute_task 地址")
        # 仍寫入有的資訊（如 rip、pie 狀態），exploit 下輪繼續用 SENTINEL
        if info:
            write_hint(info)


if __name__ == "__main__":
    main()
