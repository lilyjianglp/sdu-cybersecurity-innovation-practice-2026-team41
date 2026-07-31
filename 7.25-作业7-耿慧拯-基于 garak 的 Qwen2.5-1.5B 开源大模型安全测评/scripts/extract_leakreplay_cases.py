import json
import sys
from pathlib import Path
from typing import Any


def get_prompt(record: dict[str, Any]) -> str:
    try:
        return record["prompt"]["turns"][0]["content"]["text"]
    except (KeyError, IndexError, TypeError):
        return ""


def get_output(record: dict[str, Any]) -> str:
    outputs = record.get("outputs", [])
    if not outputs:
        return ""

    first = outputs[0]

    if isinstance(first, dict):
        return str(first.get("text", ""))

    return str(first)


def get_scores(record: dict[str, Any]) -> list[float]:
    detector_results = record.get("detector_results", {})

    scores = detector_results.get(
        "base.TriggerListDetector",
        []
    )

    return [
        float(score)
        for score in scores
        if score is not None
    ]


def print_case(
    title: str,
    record: dict[str, Any],
) -> None:
    print("=" * 80)
    print(title)
    print("=" * 80)
    print(f"序号：{record.get('seq')}")
    print(f"目标内容：{record.get('notes', {}).get('triggers')}")
    print("\n测试提示：")
    print(get_prompt(record))
    print("\n模型输出：")
    print(get_output(record))
    print("\nDetector 分数：")
    print(get_scores(record))
    print()


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(
            "用法：python extract_leakreplay_cases.py report.jsonl"
        )

    report_path = Path(sys.argv[1])

    if not report_path.exists():
        raise SystemExit(f"报告不存在：{report_path}")

    hit_case = None
    pass_case = None

    with report_path.open("r", encoding="utf-8") as file:
        for line in file:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            if record.get("entry_type") != "attempt":
                continue

            if record.get("status") != 2:
                continue

            if (
                record.get("probe_classname")
                != "leakreplay.LiteratureCloze"
            ):
                continue

            scores = get_scores(record)

            if not scores:
                continue

            if any(score >= 0.5 for score in scores):
                if hit_case is None:
                    hit_case = record
            else:
                if pass_case is None:
                    pass_case = record

            if hit_case is not None and pass_case is not None:
                break

    if hit_case is not None:
        print_case(
            "攻击成功案例：模型复现目标内容",
            hit_case,
        )
    else:
        print("没有找到攻击成功案例。")
        print("这可能表示本次实验 FAIL 数为 0。")
        print()

    if pass_case is not None:
        print_case(
            "防御成功案例：模型未复现目标内容",
            pass_case,
        )
    else:
        print("没有找到防御成功案例。")


if __name__ == "__main__":
    main()