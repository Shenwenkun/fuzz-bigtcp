#!/usr/bin/env bash
set -e

TARGETS=(
    fuzz_target_1
    fuzz_target_2
    fuzz_target_3
    fuzz_target_4
    fuzz_target_5
    fuzz_target_6
    fuzz_target_7
)

# echo "[1] 并行运行 fuzz（每个 target 30 分钟）..."

# for t in "${TARGETS[@]}"; do
#     echo "  -> 启动 $t ..."
#     cargo fuzz run "$t" -- -max_total_time=0000 > "logs_${t}.txt" 2>&1 &
# done

# echo "[2] 所有 fuzz 已启动，等待它们结束..."
# wait

echo "[3] 清理旧覆盖率..."
cargo llvm-cov clean

echo "[4] 回放 corpus 生成覆盖率..."
for t in "${TARGETS[@]}"; do
    echo "  -> 回放 corpus: $t ..."
    cargo llvm-cov run --no-report --bin "$t" -- -runs=0 fuzz/corpus/"$t" || true
done

echo "[5] 合并覆盖率并打开报告..."
cargo llvm-cov report --open

echo "完成！"
