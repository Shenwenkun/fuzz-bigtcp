# fuzz-bigtcp

A comprehensive fuzzing project targeting the Asterinas bigtcp network stack.  
This repository includes user‑space and kernel‑mock environments, multiple fuzz
targets (LLM‑driven and traditional), structured TLV input formats, and
reproducible crash artifacts.

The goal is to explore deep TCP state machine behavior, validate packet parsing
logic, and evaluate the effectiveness of LLM‑assisted fuzzing.

---

## ✨ Features

### ✔ Multiple fuzzing pipelines
- **Traditional byte‑level fuzzing**
- **Structured TLV fuzzing**
- **LLM‑assisted semantic fuzzing**  
  TLV → structured TCP fields → packet → bigtcp injection

### ✔ User‑space bigtcp execution
- Runs the Asterinas TCP stack without kernel dependencies
- Supports iface polling, listener simulation, and packet injection

### ✔ Kernel‑mock environment
- Simulates kernel scheduling and device behavior
- Useful for deterministic reproduction and debugging

### ✔ Up‑to‑date Asterinas network stack
- `aster-bigtcp/` is periodically synced with upstream Asterinas

### ✔ Reproducible crashes
- All minimized crash inputs are stored under `fuzz/artifacts/...`
- Each crash can be deterministically replayed

---

## 📁 Repository Structure

```
fuzz-bigtcp/
├── aster-bigtcp/            # Synced Asterinas network stack (bigtcp + smoltcp fork)
├── bigtcp_kernel_mock/      # Kernel-like mock environment
├── bigtcp_user/             # User-space bigtcp stack (fuzz target)
├── fuzz/
│   ├── fuzz_targets/        # Multiple fuzz targets (LLM + non-LLM)
│   │   ├── llm_fuzz_target_4.rs
│   │   └── ...
│   ├── artifacts/           # Minimized crash inputs
│   └── corpus/              # Seed corpora
├── json/                    # TLV/JSON schemas for structured fuzzing
├── api.py                   # Python helper for LLM/TLV generation
├── cov_all.sh               # Coverage automation script
├── Cargo.toml
└── README.md
```

---

## 🚀 Building & Running

### Install dependencies

```
rustup default nightly
cargo install cargo-fuzz
```

### Build user‑space bigtcp

```
cargo build -p bigtcp_user
```

### Run a fuzz target

```
cargo fuzz run llm_fuzz_target_4
```

### Run non‑LLM fuzz targets

```
cargo fuzz run fuzz_target_X
```

---

## 🧪 Reproducing Known Crashes

All minimized crash inputs are stored under:

```
fuzz/artifacts/<target>/
```

Replay a crash:

```
cargo fuzz run llm_fuzz_target_4 fuzz/artifacts/llm_fuzz_target_4/minimized-xxxx
```

Example panic:

```
slice index starts at 20 but ends at 0
at smoltcp/src/wire/tcp.rs:600
```

This originates from TCP option construction in smoltcp’s `Packet::options_mut`.

---

## 🧠 LLM Integration

This project uses a structured TLV format to encode:

- TCP flags  
- seq/ack numbers  
- window size  
- MSS  
- SACK ranges  
- timestamps  
- payload  

LLM is used to:

- Generate TLV sequences  
- Mutate structured fields  
- Explore deeper protocol states  
- Produce semantically valid but edge‑case packets  

Pipeline:

```
TLV → structured fields → TcpRepr → packet → iface.poll()
```

---

## 🎯 Purpose

This repository is designed for:

- Research on TCP fuzzing  
- Evaluating LLM‑assisted fuzzing  
- Discovering logic bugs in bigtcp/smoltcp  
- Providing reproducible cases for upstream maintainers  
- Building a reusable fuzzing framework for protocol stacks  

---
