#!/usr/bin/env bash
set -euo pipefail

LAB_DIR="${GARAK_LAB_DIR:-${HOME}/garak-lab}"
VENV="${LAB_DIR}/garak-env/bin/activate"
LOG_DIR="${LAB_DIR}/logs"

if [[ ! -f "${VENV}" ]]; then
  echo "Virtual environment not found: ${VENV}" >&2
  echo "Run scripts/setup.sh first." >&2
  exit 1
fi

source "${VENV}"
mkdir -p "${LOG_DIR}"

python -m garak \
  --target_type ollama.OllamaGenerator \
  --target_name qwen2.5:1.5b \
  --probes promptinject.HijackHateHumans \
  --generations 1 \
  --seed 42 \
  --report_prefix qwen_promptinject_hate_g1 \
  2>&1 | tee "${LOG_DIR}/qwen_promptinject_hate_g1.log"

