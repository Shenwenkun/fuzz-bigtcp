import subprocess
import json
import os
import binascii
import re
import struct
import os as _os

MODEL = "qwen2.5:7b-instruct"
OUT_JSON_DIR = "./json/llm_fuzz_target_5"
OUT_BIN_DIR = "./fuzz/corpus/llm_fuzz_target_5"
NUM_FILES = 50

os.makedirs(OUT_JSON_DIR, exist_ok=True)
os.makedirs(OUT_BIN_DIR, exist_ok=True)

PROMPT = """
You MUST output ONLY a JSON array. No explanations. No comments.

Each element MUST be one of:

{ "action": "syn" }

{ "action": "ack" }

{ "action": "fin" }

{ "action": "rst" }

{ "action": "data", "size": 120 }

STRICT RULES:
- Output ONLY the JSON array.
- The array MUST contain 5–30 elements.
- "action" MUST be one of: "syn","ack","fin","rst","data".
- For "data", the field "size" MUST exist and be an integer 0–200.
- For non-"data" actions, "size" MUST NOT appear.
- NO extra fields.
- NO trailing commas.
- NO text outside JSON.
"""

def extract_json_array(text: str) -> str:
    m = re.search(r'\[.*\]', text, flags=re.S)
    if not m:
        raise ValueError("LLM 输出中未找到 JSON 数组")
    return m.group(0)

def encode_packet(item, seq_counter):
    """
    映射到 fuzz_target_5 的 TLV:

    [ptype:1][len:1][payload]

    其中 payload 对于非 SYN 包：
    payload = [seq:4][padding:4][data...]

    对应 build_tcp_with_control 里的解析：
        if payload.len() < 8 { return vec![]; }
        let seq = u32::from_le_bytes(payload[0..4]);
        let data = &payload[8..];
    """
    action = item["action"]

    if action == "syn":
        ptype = 0x01
        # SYN 的 payload 在你当前 build_syn 里只是直接当 data 用，可以为空
        payload = b""
        return ptype, payload, seq_counter

    if action == "ack":
        ptype = 0x02
        size = 0
    elif action == "fin":
        ptype = 0x03
        size = 0
    elif action == "rst":
        ptype = 0x04
        size = 0
    elif action == "data":
        ptype = 0x05
        size = int(item.get("size", 0))
        size = max(0, min(size, 200))
    else:
        # 不认识的 action，直接丢弃
        return None, None, seq_counter

    # 至少要 8 字节给 seq + padding
    data_len = size
    seq = seq_counter & 0xFFFFFFFF
    seq_counter = (seq_counter + max(1, data_len + 1)) & 0xFFFFFFFF

    # 这里 data 用简单模式：重复 'A'
    data = b"A" * data_len
    payload = struct.pack("<I", seq) + b"\x00\x00\x00\x00" + data

    return ptype, payload, seq_counter

def tlv_encode(ptype, payload: bytes) -> bytes:
    # 你的 fuzz_target_5 里 TLV 是 [ptype:1][len:1][payload]
    length = len(payload)
    if length > 255:
        payload = payload[:255]
        length = 255
    return struct.pack("<BB", ptype & 0xFF, length & 0xFF) + payload

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
        actions = json.loads(json_text)
    except Exception:
        print("❌ JSON 解析失败，重试")
        continue

    if not isinstance(actions, list) or len(actions) == 0:
        print("❌ JSON 不是非空数组，重试")
        continue

    json_path = os.path.join(OUT_JSON_DIR, f"llm_{i:04d}.json")
    with open(json_path, "w") as f:
        f.write(json_text)
    print(f"[OK] Saved JSON → {json_path}")

    bin_path = os.path.join(OUT_BIN_DIR, f"llm_{i:04d}.bin")

    try:
        seq_counter = 1
        with open(bin_path, "wb") as f:
            for item in actions:
                if not isinstance(item, dict) or "action" not in item:
                    continue
                ptype, payload, seq_counter = encode_packet(item, seq_counter)
                if ptype is None:
                    continue
                pkt = tlv_encode(ptype, payload)
                f.write(pkt)
    except Exception as e:
        print("❌ 转换失败:", e)
        # 出错就不要计数
        continue

    print(f"[OK] Converted → {bin_path}")

    i += 1
    success += 1

print("\nAll corpus generated and converted!")
