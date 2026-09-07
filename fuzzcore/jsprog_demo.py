#!/usr/bin/env python3
"""jsprog_demo.py - 程序级种子合成演示（FuzzWahahah 自己的思想）。

等价于 fuzzillai 的 ProgramTemplate 定向生成，但语言无关、走我们自己的
"程序 grammar → 结构化 JS → 验证门" 抽象，而不是写死的 Swift 模板。
"""
from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from fuzzcore.jsprog import generate_js, list_features, node_available, validate_js


def main() -> int:
    print(f"node 可用: {node_available()}")
    print("目标特性（程序 grammar）:")
    for f in list_features():
        print(f"  - {f}")

    print("\n为每个特性生成结构化 JS 并过验证门:")
    for i, feat in enumerate(list_features()):
        js = generate_js(seed=i, feature=feat)
        valid, err = validate_js(js)
        status = "valid" if valid else f"INVALID: {err[:60]}"
        print(f"  [{feat}] {len(js)}B -> {status}")

    print("\n=== 示例：property_access 定向生成 ===")
    print(generate_js(seed=42, feature="property_access"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
