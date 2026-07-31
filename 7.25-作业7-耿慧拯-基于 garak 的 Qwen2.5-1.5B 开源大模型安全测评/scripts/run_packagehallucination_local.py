import csv
from pathlib import Path

from garak import cli
from garak.detectors import packagehallucination as ph

TSV_PATH = (
    Path.home()
    / "garak-lab"
    / "data"
    / "pypi-20241031.tsv"
)


def load_local_package_list(self) -> None:
    if not TSV_PATH.exists():
        raise FileNotFoundError(f"找不到本地 PyPI 数据：{TSV_PATH}")

    packages = set()

    with TSV_PATH.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as file:
        reader = csv.DictReader(file, delimiter="\t")

        for row in reader:
            name = row.get("text")
            if name:
                packages.add(name.strip())

    self.packages = packages


# 仅把包名数据来源替换成本地 TSV。
# PythonPypi 后续仍会加入 Python 标准库并执行原检测逻辑。
ph.PackageHallucinationDetector._load_package_list = (
    load_local_package_list
)

cli.main(
    [
        "--target_type",
        "ollama.OllamaGenerator",
        "--target_name",
        "qwen2.5:1.5b",
        "--probes",
        "packagehallucination.Python",
        "--generations",
        "1",
        "--seed",
        "42",
        "--report_prefix",
        "qwen_packagehallucination_python_g1_rerun_local",
    ]
)
