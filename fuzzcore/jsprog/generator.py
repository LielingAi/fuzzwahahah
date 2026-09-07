"""js_generator.py - 程序级种子合成（FuzzWahahah 自己的"程序 grammar"）。

对应 fuzzillai 的 ProgramTemplate，但：
  - 语言无关：产出 JS 文本，喂给任意 JS 引擎（V8/SpiderMonkey/JSC），
    而不像 fuzzillai 那样写死成 Swift 的 Fuzzilli 模板。
  - 走我们自己的抽象：一个"程序 grammar"= 目标特性列表，生成器据此
    组合出结构化程序（warmup 循环触发 JIT + 目标特性在热函数体内）。

这是 Phase 2 的 Grammar IR / SeedSynthesis 从字节级扩展到程序级。
"""
from __future__ import annotations

import random

# 目标特性（对应 fuzzillai ProgramTemplate 里要"定向"的 JIT/语言特性）
FEATURES = {
    "jit_function": "warmup 循环调用热函数，触发 JIT",
    "property_access": "热函数内 get/set 属性，定向 IC 优化",
    "class_hierarchy": "class + 继承 + super，定向构造/原型链",
    "generator": "generator + yield，定向 generator 状态机",
    "async_await": "async/await，定向 promise/微任务",
    "typed_array": "TypedArray + 越界/填充，定向元素种类转换",
}

IDENT = "abcdefghijklmnopqrstuvwxyz"


def _rand_ident(rnd: random.Random, n: int = 4) -> str:
    return "".join(rnd.choice(IDENT) for _ in range(n))


def _warmup_body(rnd: random.Random, feature: str) -> str:
    """按目标特性生成热函数体内的定向代码。"""
    v = _rand_ident(rnd)
    if feature == "property_access":
        return (f"var o = {{ {v}: 42 }}; "
                f"for (var i=0;i<100;i++) o.{v} = i; return o.{v};")
    if feature == "class_hierarchy":
        return (f"class B {{ m(){{return 1}} }}; class D extends B {{ m(){{return 2}} }}; "
                f"var x = new D(); return x.m();")
    if feature == "generator":
        return (f"function* g(){{ yield 1; yield 2; }}; "
                f"var it = g(); return it.next().value + it.next().value;")
    if feature == "async_await":
        return ("async function inner(){ return 42; } "
                "return inner().then(function(x){ return x; });")
    if feature == "typed_array":
        return (f"var a = new Int32Array(100); a.fill(7); "
                f"a[0] = {rnd.randint(-2**31, 2**31-1)}; return a[0];")
    # 默认：随机代码块（触发 JIT 编译）
    return f"var x = {rnd.randint(0, 1000)}; var y = {rnd.randint(0, 1000)}; return x + y;"


def generate_js(seed: int = 0, feature: str = "jit_function") -> str:
    """生成一个结构化 JS 程序：warmup 循环 + 热函数体内含定向特性。"""
    rnd = random.Random(seed)
    fn = _rand_ident(rnd)
    body = _warmup_body(rnd, feature)
    n_iter = rnd.randint(100, 10000)
    return (
        f"function {fn}(a) {{\n"
        f"  {body}\n"
        f"}}\n"
        f"for (var i = 0; i < {n_iter}; i++) {{\n"
        f"  {fn}(i);\n"
        f"}}\n"
    )


def list_features() -> list[str]:
    return list(FEATURES.keys())
