#!/usr/bin/env bash
set -e

echo "[1] 清理旧覆盖率..."
cargo llvm-cov clean

# fuzz_target_1~5，如果以后增加可以继续加
TARGETS=(
    fuzz_target_1
    fuzz_target_2
    fuzz_target_3
    fuzz_target_4
    fuzz_target_5
    fuzz_target_6
)

echo "[2] 构建所有 fuzz target（带覆盖率）..."
for t in "${TARGETS[@]}"; do
    echo "  -> 构建 $t ..."
    cargo llvm-cov run --no-report --bin "$t" -- -runs=0 fuzz/corpus/"$t" || true
done



echo "[3] 合并覆盖率并打开报告..."
cargo llvm-cov report --open

echo "完成！"
