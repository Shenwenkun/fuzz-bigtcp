import requests
import json
import os
import binascii
import re
import struct

OLLAMA_HOST = "http://192.168.137.1:11434"
MODEL = "qwen2.5:14b-instruct"

OUT_JSON_DIR = "./json"
OUT_BIN_DIR = "./fuzz/corpus/llm_fuzz_target_4"

os.makedirs(OUT_JSON_DIR, exist_ok=True)
os.makedirs(OUT_BIN_DIR, exist_ok=True)


def fix_hex(s: str) -> str:
    s = s.strip().lower()
    s = ''.join(c for c in s if c in "0123456789abcdef")
    if len(s) % 2 == 1:
        s = "0" + s
    return s


def parse_llm_fields(text: str):
    result = {}

    for line in text.splitlines():
        if "=" not in line:
            continue

        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip()

        if key in ["ptype", "seq", "ack", "win", "flags", "mss", "tsval", "tsecr"]:
            try:
                result[key] = int(val)
            except:
                result[key] = 0

        elif key == "sack_perm":
            result[key] = (val.lower() == "true")

        elif key == "sack_ranges":
            if val == "none":
                result[key] = [None, None, None]
            else:
                ranges = []
                for r in val.split(","):
                    if "-" in r:
                        start, end = r.split("-")
                        ranges.append((int(start), int(end)))
                while len(ranges) < 3:
                    ranges.append(None)
                result[key] = ranges

        elif key == "payload_hex":
            result[key] = fix_hex(val)

    return result


def encode_packet(item):
    ptype = item.get("ptype", 0) & 0xFF
    seq = item.get("seq", 0) & 0xFFFFFFFF
    ack = item.get("ack", 0) & 0xFFFFFFFF
    win = item.get("win", 0) & 0xFFFF
    flags = item.get("flags", 0) & 0xFF
    mss = item.get("mss", 0) & 0xFFFF
    sack_perm = 1 if item.get("sack_perm", False) else 0
    tsval = item.get("tsval", 0) & 0xFFFFFFFF
    tsecr = item.get("tsecr", 0) & 0xFFFFFFFF

    sack_bytes = b""
    for r in item.get("sack_ranges", [None, None, None]):
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

def generate_llm_json_and_bin(prompt: str, index: int):
    print(f"\n=== LLM generation round {index} ===")
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

    # Parse NDJSON streaming output from Ollama
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
        print("[!] Empty LLM output, skipping")
        return None, None

    fields = parse_llm_fields(raw_output)
    if not fields:
        print("[!] Failed to parse fields, skipping")
        return None, None

    json_data = [fields]
    json_path = os.path.join(OUT_JSON_DIR, f"llm_{index:04d}.json")
    with open(json_path, "w") as f:
        json.dump(json_data, f, indent=2)


    bin_path = os.path.join(OUT_BIN_DIR, f"llm_{index:04d}.bin")
    with open(bin_path, "wb") as f:
        pkt = encode_packet(fields)
        f.write(pkt)

    print(f"[OK] JSON saved → {json_path}")
    print(f"[OK] BIN saved  → {bin_path}")

    return json_path, bin_path
