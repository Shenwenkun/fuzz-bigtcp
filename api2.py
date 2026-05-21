import requests
import json
import os
import struct

OLLAMA_HOST = "http://192.168.137.1:11434"
MODEL = "qwen2.5:14b-instruct"

OUT_JSON_DIR = "./json_ops"
OUT_BIN_DIR = "./fuzz/corpus/llm_fuzz_target_8"

os.makedirs(OUT_JSON_DIR, exist_ok=True)
os.makedirs(OUT_BIN_DIR, exist_ok=True)


def parse_llm_ops(text: str):
    """
    从 LLM 输出中提取操作序列：
    格式示例：
        op=2 arg=32
        op=9 arg=200
        op=3 arg=0
    """
    ops = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue

        if "op" not in line:
            continue

        try:
            parts = line.replace(",", " ").split()
            op = None
            arg = 0

            for p in parts:
                if p.startswith("op="):
                    op = int(p[3:])
                elif p.startswith("arg="):
                    arg = int(p[4:])

            if op is not None:
                ops.append({"op": op & 0xFF, "arg": arg & 0xFF})

        except:
            continue

    return ops


def encode_ops_bin(ops):
    """
    每个操作写成两个字节：
        [op: u8][arg: u8]
    """
    data = bytearray()
    for item in ops:
        data.append(item["op"] & 0xFF)
        data.append(item["arg"] & 0xFF)
    return bytes(data)


def generate_llm_json_and_bin(prompt: str, index: int):
    print(f"\n=== LLM generation round {index} ===")

    # 调用 Ollama
    try:
        resp = requests.post(
            f"{OLLAMA_HOST}/api/generate",
            json={"model": MODEL, "prompt": prompt},
            timeout=120
        )
    except Exception as e:
        print("[!] Error calling Ollama:", e)
        return None, None

    if resp.status_code != 200:
        print("[!] Ollama returned error:", resp.text)
        return None, None

    raw_output = ""
    for line in resp.iter_lines():
        if not line:
            continue
        try:
            obj = json.loads(line.decode("utf-8"))
            raw_output += obj.get("response", "")
        except:
            continue

    raw_output = raw_output.strip()
    if not raw_output:
        print("[!] Empty LLM output")
        return None, None

    ops = parse_llm_ops(raw_output)
    if not ops:
        print("[!] No ops parsed from LLM output")
        return None, None

 
    json_path = os.path.join(OUT_JSON_DIR, f"llm_ops_{index:04d}.json")
    with open(json_path, "w") as f:
        json.dump(ops, f, indent=2)


    bin_path = os.path.join(OUT_BIN_DIR, f"llm_ops_{index:04d}.bin")
    with open(bin_path, "wb") as f:
        f.write(encode_ops_bin(ops))

    print(f"[OK] JSON saved → {json_path}")
    print(f"[OK] BIN saved  → {bin_path}")

    return json_path, bin_path
