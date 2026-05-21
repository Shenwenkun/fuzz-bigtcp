import re
from typing import List, Dict

FILE_HEADER = re.compile(r"^\s*(.+\.rs):\s*$")

LINE_ENTRY = re.compile(r"^\s*(\d+)\|\s*([^\|]*)\|\s*(.*)$")

FN_HEADER = re.compile(r"\bfn\s+([a-zA-Z0-9_]+)")

TARGET_FILES = ["tcp_conn.rs", "tcp_listen.rs", "common.rs"]

def extract_uncovered(path="coverage/coverage.txt", context=3):
    results = []
    current_file = None
    current_fn = None

    with open(path) as f:
        lines = f.readlines()

    for i, raw in enumerate(lines):
        line = raw.rstrip("\n")

        m = FILE_HEADER.match(line)
        if m:
            fullpath = m.group(1)

            if any(t in fullpath for t in TARGET_FILES):
                current_file = fullpath.split("aster-bigtcp/src/")[-1]
            else:
                current_file = None

            current_fn = None
            continue

        if current_file is None:
            continue

        m = FN_HEADER.search(line)
        if m:
            current_fn = m.group(1)

        m = LINE_ENTRY.match(line)
        if not m:
            continue

        lineno = int(m.group(1))
        count_field = m.group(2).strip()
        code = m.group(3)

        uncovered = False

        if count_field == "" or count_field == "0":
            uncovered = True

        if re.search(r"\^\d+", code):
            uncovered = True

        if not uncovered:
            continue

        start = max(0, i - context)
        end = min(len(lines), i + context + 1)
        snippet = [l.rstrip("\n") for l in lines[start:end]]

        results.append({
            "file": current_file,
            "line": lineno,
            "function": current_fn,
            "context": snippet,
        })

    return results
