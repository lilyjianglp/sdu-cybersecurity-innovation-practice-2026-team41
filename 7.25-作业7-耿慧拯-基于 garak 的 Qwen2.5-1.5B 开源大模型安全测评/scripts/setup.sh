#!/usr/bin/env bash
set -euo pipefail

LAB_DIR="${GARAK_LAB_DIR:-${HOME}/garak-lab}"
TMP_WORK="${LAB_DIR}/tmp"

mkdir -p "${TMP_WORK}"
export TMPDIR="${TMP_WORK}"
export TEMP="${TMP_WORK}"
export TMP="${TMP_WORK}"

echo "[1/5] Installing Ubuntu packages"
sudo apt update
sudo apt install -y python3-venv python3-pip curl

echo "[2/5] Creating Python virtual environment"
mkdir -p "${LAB_DIR}/logs"
python3 -m venv "${LAB_DIR}/garak-env"
source "${LAB_DIR}/garak-env/bin/activate"

echo "[3/5] Installing Python dependencies"
python -m pip install -U pip setuptools wheel
python -m pip install --no-cache-dir \
  pyyaml colorama tqdm numpy requests ollama xdg-base-dirs jsonpath-ng \
  python-magic rapidfuzz markdown jinja2 aiohttp backoff nltk langdetect==1.0.9
python -m pip install --no-cache-dir --no-deps garak==0.15.1

echo "[4/5] Printing versions"
python --version
python -m garak --version

echo "[5/5] Environment ready"
echo "Virtual environment: ${LAB_DIR}/garak-env"
echo "Next:"
echo "  ollama pull qwen2.5:1.5b"
echo "  ollama serve"

