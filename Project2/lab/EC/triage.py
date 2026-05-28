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
HINT        = f"/tmp/triage_hint.txt"
SERVER_BIN  = f"{SHARED}/blogic"

def find_latest_core() -> str | None:
    candidates = []
    search_dir = CORE_DIR
    pattern    = "blogic-*.core"
    for f in glob.glob(os.path.join(search_dir, pattern)):
        if os.path.isfile(f) and os.path.getsize(f) > 0:
            candidates.append(f)
    if not candidates:
        return None
    return max(candidates)

GDB_CMDS = """
x $rsp
disas log_message
p execute_task
"""

def run_gdb(core: str) -> str:
    with tempfile.NamedTemporaryFile("w", suffix=".gdb", delete=False) as f:
        f.write(GDB_CMDS)
        script = f.name
    r = subprocess.run(
        ["gdb", "-batch", "-x", script, SERVER_BIN, core],
        capture_output=True, text=True, timeout=20
    )
    os.unlink(script)
    return r.stdout


def parse_gdb(out: str) -> dict:
    info = {}
    # print("GDB output:")
    for line in out.splitlines():
        # print(line)
        if "do_system" in line:
            info["movaps_not_aligned"] = "TRUE"
        if "0xdeadbeef" in line:
            m = re.search(r"(0x[0-9a-fA-F]+):\s*0xdeadbeef", line)
            if m:
                info["rsp_addr"] = int(m.group(1), 16)
        if "execute_task" in line and "=" in line:
            m = re.search(r"=.*(0x[0-9a-fA-F]+)", line)
            # print(f"Found execute_task: {m}")
            if m:
                addr = int(m.group(1), 16)
                if addr:
                    info["execute_task_addr"] = addr
        if "ret" in line:
            m = re.match(r"=?>?\s*(0x[0-9a-fA-F]+) <\+[0-9]+>:\tret", line)
            if m:
                info["ret_inst_addr"] = int(m.group(1), 16)
        # print(info)
    # print("===============================================")
    return info

def write_hint(info: dict):
    os.makedirs(SHARED, exist_ok=True)
    with open(HINT, "w") as f:
        for k, v in info.items():
            val = f"0x{v:x}" if isinstance(v, int) else str(v)
            f.write(f"{k}={val}\n")

def main():
    core = find_latest_core()
    if not core:
        sys.exit(0)   # 不 crash，讓 grading 繼續

    info = {}
    gdb_out = run_gdb(core)
    if gdb_out:
        info = parse_gdb(gdb_out)
    write_hint(info)


if __name__ == "__main__":
    main()
