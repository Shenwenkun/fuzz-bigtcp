import subprocess
import json
import os
import binascii
import re
import struct

MODEL = "qwen2.5:7b-instruct"
OUT_JSON_DIR = "./json"
OUT_BIN_DIR = "./fuzz/corpus/llm_fuzz_target_4"
NUM_FILES = 50

os.makedirs(OUT_JSON_DIR, exist_ok=True)
os.makedirs(OUT_BIN_DIR, exist_ok=True)

PROMPT = """
You MUST output ONLY a JSON array. No explanations. No comments. No text outside JSON.

The JSON array MUST contain 8–20 packets.
Each packet MUST strictly follow this exact template:

{
  "ptype": 1,
  "seq": 123,
  "ack": 456,
  "win": 4096,
  "flags": 0,
  "mss": 1460,
  "sack_perm": true,
  "tsval": 111,
  "tsecr": 222,
  "sack_ranges": [
    [1000,2000],
    null,
    null
  ],
  "payload_hex": "abcd1234"
}

STRICT RULES:
- Output ONLY the JSON array.
- ptype MUST be one of: 1,2,3,4,5.
- seq and ack MUST be integers 0–4294967295.
- win MUST be 0–65535.
- flags MUST be 0–255.
- mss MUST be 0–1500.
- sack_perm MUST be true or false.
- tsval/tsecr MUST be integers 0–4294967295.
- sack_ranges MUST be EXACTLY 3 elements, each either [start,end] or null.
- payload_hex MUST be a valid hex string (0–200 bytes).
- NO trailing commas.
- NO missing fields.
- NO extra fields.
- NO text outside JSON.

Now output ONLY the JSON array.
"""

def fix_hex(s: str) -> str:
    s = s.strip().lower()
    s = ''.join(c for c in s if c in "0123456789abcdef")
    if len(s) % 2 == 1:
        s = "0" + s
    return s

def extract_json_array(text: str) -> str:
    match = re.search(r'\[.*\]', text, flags=re.S)
    if not match:
        raise ValueError("LLM 输出中未找到 JSON 数组")
    return match.group(0)

def encode_packet(item):
    """
    Encode one LLM packet into the TLV format required by fuzz_target:

    [ptype:1]
    [seq:4]
    [ack:4]
    [win:2]
    [flags:1]
    [mss:2]
    [sack_perm:1]
    [tsval:4]
    [tsecr:4]
    [sack_ranges: 3 * (start:4 + end:4)]
    [payload_len:2]
    [payload]
    """

    ptype = item["ptype"] & 0xFF
    seq = item["seq"] & 0xFFFFFFFF
    ack = item["ack"] & 0xFFFFFFFF
    win = item["win"] & 0xFFFF
    flags = item["flags"] & 0xFF
    mss = item["mss"] & 0xFFFF
    sack_perm = 1 if item["sack_perm"] else 0
    tsval = item["tsval"] & 0xFFFFFFFF
    tsecr = item["tsecr"] & 0xFFFFFFFF

    # SACK ranges
    sack_bytes = b""
    for r in item["sack_ranges"]:
        if r is None:
            sack_bytes += struct.pack("<II", 0, 0)
        else:
            start, end = r
            sack_bytes += struct.pack("<II", start & 0xFFFFFFFF, end & 0xFFFFFFFF)

    payload_hex = fix_hex(item.get("payload_hex", ""))
    payload = binascii.unhexlify(payload_hex) if payload_hex else b""
    payload_len = len(payload)

    header = struct.pack(
        "<B I I H B H B I I",
        ptype, seq, ack, win, flags, mss, sack_perm, tsval, tsecr
    )

    header += sack_bytes
    header += struct.pack("<H", payload_len)

    return header + payload


i = 1
success = 0

while success < NUM_FILES:
    print(f"\n=== Generating corpus {success+1}/{NUM_FILES} ===")

    result = subprocess.run(
        ["ollama", "run", MODEL],
        input=PROMPT.encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    raw_output = result.stdout.decode("utf-8").strip()

    try:
        json_text = extract_json_array(raw_output)
    except Exception:
        print("❌ 未找到 JSON 数组，重试")
        continue

    try:
        data = json.loads(json_text)
    except Exception:
        print("❌ JSON 格式错误，重试")
        continue

    json_path = os.path.join(OUT_JSON_DIR, f"llm_{i:04d}.json")
    with open(json_path, "w") as f:
        f.write(json_text)
    print(f"[OK] Saved JSON → {json_path}")

    bin_path = os.path.join(OUT_BIN_DIR, f"llm_{i:04d}.bin")
    try:
        with open(bin_path, "wb") as f:
            for item in data:
                pkt = encode_packet(item)
                f.write(pkt)
    except Exception as e:
        print("❌ 转换失败:", e)
        continue

    print(f"[OK] Converted → {bin_path}")

    i += 1
    success += 1

print("\nAll corpus generated and converted!")
