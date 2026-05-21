import os
import sys
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(ROOT)

from api2 import generate_llm_json_and_bin
from extract_coverage import extract_uncovered


HARNESS_PATH = os.path.join(ROOT, "fuzz", "fuzz_targets", "llm_fuzz_target_8.rs")
TCP_CONN_PATH = os.path.join(ROOT, "aster-bigtcp", "src", "socket", "bound", "tcp_conn.rs")


def run_fuzz_once():
    print("\n[+] Running fuzz for one round...")
    subprocess.run([
        "cargo", "fuzz", "run", "llm_fuzz_target_8", "--", "-runs=50000"
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
        "I am fuzzing bigTCP using an API-level fuzz harness (llm_fuzz_target_8.rs).\n"
        "The harness consumes a sequence of operations:\n\n"
        "    op=<int> arg=<int>\n\n"
        "Operation codes:\n"
        "    0 = Connect\n"
        "    1 = CheckState\n"
        "    2 = Send\n"
        "    3 = Recv\n"
        "    4 = ShutSend\n"
        "    5 = ShutRecv\n"
        "    6 = Close\n"
        "    7 = Reset\n"
        "    8 = ClearRst\n"
        "    9 = Tick\n\n"
        "Your goal is to generate a sequence of operations that can reach uncovered branches.\n\n"
    )

    parts.append("=========================\n")
    parts.append("【File 1: fuzz_target_8.rs】\n")
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
        "1. Analyze the uncovered code.\n"
        "2. Infer which API sequences can reach those branches.\n"
        "3. Internally reason about the optimal sequence.\n"
        "4. Output ONLY the final sequence in the format:\n\n"
        "    op=<int> arg=<int>\n"
        "    op=<int> arg=<int>\n"
        "    ...\n\n"
        "Requirements:\n"
        "- Generate 5~20 operations.\n"
        "- arg must be 0~255.\n"
        "- No explanations.\n"
        "- No comments.\n"
        "- Only the operation lines.\n"
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
