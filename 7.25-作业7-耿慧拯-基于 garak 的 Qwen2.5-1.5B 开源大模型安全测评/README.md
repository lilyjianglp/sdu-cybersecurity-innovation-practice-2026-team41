# garak Homework 7 Core

本目录包含作业7的核心运行脚本，用于在本地 Ollama 上调用
`qwen2.5:1.5b`，并使用 garak 0.15.1 完成以下五类安全测评：

1. 提示注入：`promptinject.HijackHateHumans`
2. DAN越狱：`dan.Ablation_Dan_11_0`
3. 编码绕过：`encoding.InjectBase64`、`encoding.InjectROT13`
4. 软件包幻觉：`packagehallucination.Python`
5. 数据泄露与文本复现：`leakreplay.LiteratureCloze`

## 统一实验参数

| 项目 | 取值 |
|---|---|
| Generator | `ollama.OllamaGenerator` |
| 模型 | `qwen2.5:1.5b` |
| generations | `1` |
| seed | `42` |
| garak | `0.15.1` |
| Ollama API | `http://127.0.0.1:11434` |

## 目录结构

```text
7.25-作业7-耿慧拯-基于 garak 的 Qwen2.5-1.5B 开源大模型安全测评/
├── README.md
├── requirements.txt
├── scripts/
│   ├── setup.sh
│   ├── run_promptinject.sh
│   ├── run_dan.sh
│   ├── run_encoding_base64.sh
│   ├── run_encoding_rot13.sh
│   ├── run_packagehallucination_local.py
│   ├── offline_packagehallucination.py
│   ├── run_leakreplay.sh
│   └── extract_leakreplay_cases.py
├──基于 garak 的 Qwen2.5-1.5B 开源大模型安全测评实验报告.pdf
```

## 环境部署

在 WSL2 Ubuntu 中执行：

```bash
chmod +x scripts/*.sh
bash scripts/setup.sh
```

安装并启动 Ollama：

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5:1.5b
ollama serve
```

运行测评前，可在另一个终端确认服务和模型：

```bash
curl http://127.0.0.1:11434/api/tags
```

默认虚拟环境位于 `~/garak-lab/garak-env`。如需使用其他目录，可设置：

```bash
export GARAK_LAB_DIR=/path/to/garak-lab
```

## 运行正式测评

```bash
bash scripts/run_promptinject.sh
bash scripts/run_dan.sh
bash scripts/run_encoding_base64.sh
bash scripts/run_encoding_rot13.sh
bash scripts/run_leakreplay.sh
```

上述脚本会自动激活虚拟环境，并将终端日志保存到
`${GARAK_LAB_DIR:-$HOME/garak-lab}/logs/`。garak 的 JSONL 和 HTML
报告默认保存在：

```text
~/.local/share/garak/garak_runs/
```

## 软件包幻觉测评

该测评需要本地 PyPI 快照。先按照 `data/README.md` 放置
`data/pypi-20241031.tsv`，再执行：

```bash
source "${GARAK_LAB_DIR:-$HOME/garak-lab}/garak-env/bin/activate"
python scripts/run_packagehallucination_local.py
```

`run_packagehallucination_local.py` 仅将 Detector 的远程包名数据源替换
为本地快照，Probe、Generator、Detector 和 Evaluator 仍由 garak 完整运行。

`offline_packagehallucination.py` 用于第一次远程检测中断后的离线恢复分析，
不是正式重跑结果。使用示例：

```bash
python scripts/offline_packagehallucination.py \
  --report ~/.local/share/garak/garak_runs/qwen_packagehallucination_python_g1_full.report.jsonl
```

离线恢复结果与正式重跑结果不能相加或取平均。

## 数据泄露案例提取

正式测试完成后，可提取全部Detector自动命中案例，并根据模型首行答案
是否包含目标名称进行初步分类：

```bash
python scripts/extract_leakreplay_cases.py \
  ~/.local/share/garak/garak_runs/qwen_leakreplay_literaturecloze_g1.report.jsonl
```

该脚本只负责辅助筛选。最终的“有效复现”或“疑似误报”结论仍应结合
完整输出进行人工确认。


