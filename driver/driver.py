import os
import sys
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(ROOT)

from api import generate_llm_json_and_bin
from extract_coverage import extract_uncovered

HARNESS_PATH = os.path.join(ROOT, "fuzz", "fuzz_targets", "llm_fuzz_target_4.rs")
TCP_CONN_PATH = os.path.join(ROOT, "aster-bigtcp", "src", "socket", "bound", "tcp_conn.rs")


def run_fuzz_once():
    print("\n[+] Running fuzz for one round...")
    subprocess.run([
        "cargo", "fuzz", "run", "llm_fuzz_target_4", "--", "-runs=50000"
    ])


def run_coverage():
    print("[+] Running coverage analysis...")
    subprocess.run(["./cov_all.sh"])


def read_file_or_empty(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        print(f"[!] Failed to read {path}: {e}")
        return ""


def build_prompt(uncovered_items, max_items=5):
    harness_code = read_file_or_empty(HARNESS_PATH)
    tcp_conn_code = read_file_or_empty(TCP_CONN_PATH)

    parts = []

    
    parts.append(
        "You are a professional fuzzing engineer.\n\n"
        "I am using a fuzz harness (llm_fuzz_target_4.rs) to fuzz bigTCP.\n"
        "I want you to use the following three pieces of information to design more effective TCP inputs\n"
        "that can increase code coverage:\n\n"
        "1) The fuzz harness code (fuzz_target_5.rs)\n"
        "2) The bigTCP TCP connection implementation (tcp_conn.rs)\n"
        "3) The current coverage report (uncovered code snippets)\n\n"
    )

    parts.append("=========================\n")
    parts.append("【File 1: fuzz_target_5.rs】\n")
    parts.append("=========================\n")
    parts.append(harness_code)
    parts.append("\n\n")

    parts.append("=========================\n")
    parts.append("【File 2: tcp_conn.rs】\n")
    parts.append("=========================\n")
    parts.append(tcp_conn_code)
    parts.append("\n\n")

    parts.append("=========================\n")
    parts.append("【File 3: Coverage report (uncovered code)】\n")
    parts.append("=========================\n")

    for item in uncovered_items[:max_items]:
        file = item["file"]
        line = item["line"]
        fn = item["function"]
        ctx = "\n".join(item["context"])

        parts.append(f"\nFile: {file}\n")
        parts.append(f"Function: {fn}\n")
        parts.append(f"Uncovered line: {line}\n")
        parts.append("Context:\n")
        parts.append(ctx)
        parts.append("\n")

    parts.append(
        "\nYour tasks:\n"
        "1. Read fuzz_target_5.rs and understand the input format (TLV → TCP packet → iface.poll).\n"
        "2. Read tcp_conn.rs and understand the bigTCP TCP connection state machine and logic.\n"
        "3. Read the uncovered code snippets and identify which paths / branches are not covered.\n\n"
        "Based on this, you should:\n"
        "A. Propose an optimal input structure template (how the TLV payload should be organized).\n"
        "B. Propose an optimal field generation strategy (how to choose seq/ack/MSS/timestamp/SACK, etc.).\n"
        "C. Propose an optimal multi-packet sequence (e.g., SYN → ACK → DATA → FIN) that can drive deeper states.\n"
        "D. Internally reason about these, and then use them to generate ONE concrete TCP packet instance.\n\n"
        "You do NOT need to output the template or strategy explicitly.\n"
        "Instead, you must directly output ONE concrete packet in the following field format.\n\n"
    )


    parts.append(
        "=== Simplified TCP Specification ===\n"
        "- SYN: seq = X\n"
        "- SYN+ACK: seq = Y, ack = X+1\n"
        "- ACK: ack = Y+1\n"
        "- FIN consumes 1 sequence number\n"
        "- RST aborts the connection\n"
        "- seq increases by payload length\n"
        "- ack acknowledges peer seq+1\n"
        "- Flags: SYN=2, ACK=16, FIN=1, RST=4, PSH=8\n"
        "- payload_hex must be valid hexadecimal\n\n"
    )

    parts.append(
        "Now generate ONE TCP packet that is likely to reach one of the uncovered branches above.\n"
        "Output ONLY the following fields, one per line:\n\n"
        "ptype=<int>\n"
        "seq=<int>\n"
        "ack=<int>\n"
        "win=<int>\n"
        "flags=<int>\n"
        "mss=<int>\n"
        "sack_perm=<true/false>\n"
        "tsval=<int>\n"
        "tsecr=<int>\n"
        "sack_ranges=<none or start1-end1,start2-end2,start3-end3>\n"
        "payload_hex=<hex string>\n\n"
        "IMPORTANT:\n"
        "- No JSON.\n"
        "- No brackets.\n"
        "- No quotes.\n"
        "- No comments.\n"
        "- Only the field lines above.\n"
    )

    return "".join(parts)


def feedback_loop(iterations=10, samples_per_round=8):
    for i in range(iterations):
        print("\n==============================")
        print(f"=== Feedback Iteration {i} ===")
        print("==============================")

        run_fuzz_once()

        run_coverage()

        uncovered = extract_uncovered("coverage/coverage.txt")
        print(f"[+] Uncovered paths: {len(uncovered)}")

        if len(uncovered) == 0:
            print("[!] No uncovered paths found. Stopping.")
            break


        prompt = build_prompt(uncovered)


        for k in range(samples_per_round):
            print(f"\n--- LLM sample {k+1}/{samples_per_round} ---")
            json_path, bin_path = generate_llm_json_and_bin(
                prompt,
                i * samples_per_round + k
            )
            print(f"[+] Saved: {bin_path}")

        print("[+] Next fuzzing round will use these inputs.")


if __name__ == "__main__":
    feedback_loop(iterations=20, samples_per_round=8)
