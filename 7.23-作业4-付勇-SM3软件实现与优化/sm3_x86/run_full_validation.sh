#!/usr/bin/env bash
set -euo pipefail

CPU_CORE="${CPU_CORE:-2}"
TOTAL_MIB="${TOTAL_MIB:-256}"
RESULT_DIR="${RESULT_DIR:-results}"

mkdir -p "$RESULT_DIR"

{
  date -Iseconds
  uname -a
  lscpu
  echo
  gcc --version
  echo
  openssl version -a
} > "$RESULT_DIR/environment.txt"

make clean
make -j"$(nproc)" all
make test | tee "$RESULT_DIR/correctness.txt"
make verify-openssl | tee "$RESULT_DIR/openssl-differential.txt"
make sanitize | tee "$RESULT_DIR/sanitizer.txt"
make clean
make -j"$(nproc)" all
make asm-check | tee "$RESULT_DIR/disassembly-summary.txt"

for size in 64 256 1024 4096 16384 1048576; do
  taskset -c "$CPU_CORE" ./sm3_x86_bench "$size" "$TOTAL_MIB" \
    | tee "$RESULT_DIR/bench-${size}.txt"

  if command -v perf >/dev/null 2>&1; then
    perf stat -r 5 \
      -e cycles,instructions,branches,branch-misses,cache-references,cache-misses \
      taskset -c "$CPU_CORE" ./sm3_x86_bench "$size" "$TOTAL_MIB" \
      > "$RESULT_DIR/perf-${size}.stdout.txt" \
      2> "$RESULT_DIR/perf-${size}.txt" || true
  fi
done

echo "Validation artifacts written to $RESULT_DIR/"
