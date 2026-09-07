"""fuzz CLI - FuzzWahahah 统一入口（替代散落的独立脚本/命令）。

一条命令跑完整 fuzzing 任务：

  # 文件格式（完整闭环：新目标接入 → fuzz → 平台期反射弧自救 → 无效升级 LLM → 覆盖回升）
  fuzz run --type binary --harness harness.exe --grammar crc32_lzma --llm deepseek

  # 网络协议（ProtocolEngine + 协议 profile, 代理指标观察）
  fuzz run --type protocol --protocol http --host 192.168.1.10 --port 80

  # 浏览器/JS 引擎（Fuzzilli + QuickJS, REPRL Windows 移植）
  fuzz run --type browser

  # 任务报告
  fuzz report --out out/

设计说明：
- binary 走完整闭环（FuzzJobRunner + 字节 Grammar + 验证门 + LLM 编排）。
- protocol/browser 的语法层（协议状态机 / 程序语法）与字节 Grammar 不同构，
  当前跑引擎+观察+报告；这两类的 LLM 闭环在语法层统一后接入（见 ARCHITECTURE.md §10.6）。
- LLM 后端：deepseek（OpenAI-compatible, OPENAI_API_KEY 环境变量）或 kimi（Kimi Code ACP）。
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from fuzzcore.corpus import SqliteCorpus


def _build_llm(backend: str, corpus_db: str, workdir: str):
    """按后端名构造 LLM 编排器。"""
    if backend == "none":
        return None
    if backend == "deepseek":
        from llm_agent import DeepSeekOrchestrator
        return DeepSeekOrchestrator(corpus_db)
    if backend == "kimi":
        from llm_agent import LLMOrchestrator
        return LLMOrchestrator(workdir=workdir, corpus_db=corpus_db)
    raise ValueError(f"unknown llm backend: {backend}")


def _run_binary(args) -> int:
    """文件格式目标：完整闭环。"""
    from fuzzcore.agent import FuzzJobRunner
    from fuzzcore.engine.file_engine import LibFuzzerFileEngine, WinAFLFileEngine
    from fuzzcore.engine.base import Target, TargetKind

    corpus_db = str(Path(args.out) / "corpus.db")
    corpus = SqliteCorpus(corpus_db)

    # grammar：Corpus 已注册按名取；否则需 --grammar-file 或 LLM 综合
    grammar = corpus.get_grammar(args.grammar) if args.grammar else None
    if grammar is None and args.grammar_file:
        from fuzzcore.grammar import Grammar
        import json
        grammar = Grammar.from_dict(json.loads(Path(args.grammar_file).read_text(encoding="utf-8")))
    if grammar is None and args.llm == "none":
        print("错误: binary 目标需要 --grammar <名>（Corpus 已注册）或 --grammar-file <json>，"
              "或 --llm deepseek/kimi 让 LLM 综合 grammar", file=sys.stderr)
        return 2

    # 引擎
    if args.winafl:
        engine = WinAFLFileEngine(afl_fuzz=args.afl_fuzz,
                                  coverage_modules=[args.coverage_module or Path(args.target).name],
                                  target_module=Path(args.target).name)
        target = Target(TargetKind.BINARY, f"{args.target} @@")
    else:
        if not args.harness:
            print("错误: --type binary 需要 --harness <libFuzzer harness.exe>"
                  "（或 --winafl 走黑盒）", file=sys.stderr)
            return 2
        engine = LibFuzzerFileEngine(args.harness)
        target = Target(TargetKind.BINARY, f"{args.harness} @@")

    llm = _build_llm(args.llm, corpus_db, str(PROJECT_ROOT))

    # 无 grammar 且有 LLM：先 on_new_target 综合 grammar
    if grammar is None and llm is not None:
        print(f"[cli] 新目标接入: LLM 分析 {args.target} 综合 grammar...", flush=True)
        llm.on_new_target(args.harness or args.target,
                          magic_hex=args.magic or "",
                          extra_context=args.context or "")
        grammars = corpus.list_grammars()
        if grammars:
            grammar = corpus.get_grammar(grammars[-1])
            print(f"[cli] LLM 综合 grammar: {grammar.name}", flush=True)
        else:
            # LLM 不确定性的确定性回退: recovery 的信封 grammar
            # (LLM 综合失败时平台不能停 — 用结构恢复的确定性信封兜底)
            print("[cli] LLM 未综合出 grammar, 回退 recovery 信封...", flush=True)
            if args.magic:
                from fuzzcore.recovery import StructureRecovery
                from fuzzcore.grammar import Field
                recovery = StructureRecovery()
                grammar = recovery.build_grammar(
                    name=f"{Path(args.target).stem}_envelope",
                    magic_hex=args.magic)
                corpus.register_grammar(grammar)
                print(f"[cli] recovery 信封 grammar: {grammar.name}", flush=True)
    if grammar is None:
        print("错误: 无 grammar（LLM 未综合且无 --magic 回退）", file=sys.stderr)
        return 2

    runner = FuzzJobRunner(engine, grammar, corpus, orchestrator=llm,
                           digest_delay=args.digest_delay)
    print(f"[cli] 启动 loop agent: target={args.target} grammar={grammar.name} "
          f"llm={args.llm} budget={args.budget}s", flush=True)
    report = runner.run(target, args.seed_dir, args.out,
                        budget_s=args.budget, observe_interval=args.interval,
                        init_seed_count=args.init_seeds,
                        on_event=lambda ev, d: print(f"  [{ev}] {d}", flush=True))
    _print_report(report)
    return 0


def _run_protocol(args) -> int:
    """协议目标：ProtocolEngine + 观察 + 报告（代理指标）。"""
    from fuzzcore.engine.protocol_engine import ProtocolEngine
    from fuzzcore.engine.base import Target, TargetKind

    profile = str(PROJECT_ROOT / "fuzzcore" / "profiles" / "generic_profile.py")
    engine = ProtocolEngine(profile)
    target = Target(TargetKind.SERVICE, f"{args.protocol} {args.host} {args.port}")
    print(f"[cli] 协议 fuzz: {args.protocol} {args.host}:{args.port} "
          f"max_cases={args.max_cases}", flush=True)
    handle = engine.start(target, args.seed_dir, args.out,
                          timeout=args.timeout, max_cases=args.max_cases)
    try:
        import time
        start = time.time()
        while time.time() - start < args.budget:
            time.sleep(args.interval)
            status = engine.status(handle)
            print(f"  [obs] cases={status.coverage.total_paths} "
                  f"crashes={status.crash_count}", flush=True)
    except KeyboardInterrupt:
        print("[cli] 中断", flush=True)
    finally:
        engine.stop(handle)
    cov = engine.export_coverage(handle)
    print(f"[done] protocol {args.protocol}: cases={cov.total_paths} crashes={cov.unique_crashes}")
    return 0


def _run_browser(args) -> int:
    """浏览器/JS 引擎目标：FuzzilliEngine + 观察。"""
    from fuzzcore.engine.fuzzilli_engine import FuzzilliEngine
    from fuzzcore.engine.base import Target, TargetKind

    fuzzilli_cli = str(PROJECT_ROOT / "vendor" / "fuzzillai" / ".build" / "debug" / "FuzzilliCli.exe")
    qjs = str(PROJECT_ROOT / "vendor" / "quickjs" / "qjs_fuzzilli.exe")
    if not Path(fuzzilli_cli).exists() or not Path(qjs).exists():
        print("错误: FuzzilliCli/qjs_fuzzilli 未构建, 先跑 scripts/setup_windows.ps1",
              file=sys.stderr)
        return 2

    engine = FuzzilliEngine(fuzzilli_cli=fuzzilli_cli, js_engine=qjs,
                            profile=args.profile or "qjs")
    target = Target(TargetKind.BROWSER, "qjs")
    print(f"[cli] 浏览器 fuzz: Fuzzilli(profile={args.profile or 'qjs'}) → QuickJS",
          flush=True)
    handle = engine.start(target, args.seed_dir, args.out)
    try:
        import time
        start = time.time()
        while time.time() - start < args.budget:
            time.sleep(args.interval)
            cov = engine.export_coverage(handle)
            print(f"  [obs] crashes={cov.unique_crashes}", flush=True)
    except KeyboardInterrupt:
        print("[cli] 中断", flush=True)
    finally:
        engine.stop(handle)
    cov = engine.export_coverage(handle)
    print(f"[done] browser: crashes={cov.unique_crashes}")
    return 0


def _print_report(report) -> None:
    print("=== TaskReport ===")
    print(f"  target={report.target_id}  rounds={report.rounds}")
    print(f"  coverage_curve={report.coverage_curve}")
    print(f"  final_coverage={report.final_coverage}  crashes={report.crashes}")
    print(f"  反射弧: {report.reflex_rescues} 次 (回升 {report.reflex_recovered})  "
          f"LLM: {report.llm_escalations} 次 (回升 {report.llm_recovered}, "
          f"调用 {report.llm_calls_used})")
    print(f"  终止: {report.stop_reason}  耗时: {report.elapsed_s:.1f}s")


def main() -> int:
    parser = argparse.ArgumentParser(prog="fuzz",
                                     description="FuzzWahahah 统一 fuzzing 入口")
    sub = parser.add_subparsers(dest="cmd", required=True)

    run = sub.add_parser("run", help="跑一个 fuzzing 任务")
    run.add_argument("--type", choices=["binary", "protocol", "browser"], required=True)
    run.add_argument("--target", default="", help="目标路径/说明（binary 用）")
    # binary
    run.add_argument("--harness", default="", help="libFuzzer harness.exe")
    run.add_argument("--winafl", action="store_true", help="用 WinAFL 黑盒路径（默认 libFuzzer）")
    run.add_argument("--afl-fuzz", default="", help="afl-fuzz.exe 路径（winafl 模式）")
    run.add_argument("--coverage-module", default="", help="winafl 插桩模块")
    run.add_argument("--grammar", default="", help="Corpus 里已注册的 grammar 名")
    run.add_argument("--grammar-file", default="", help="grammar JSON 文件路径")
    run.add_argument("--magic", default="", help="新目标接入的已知 magic(hex)")
    run.add_argument("--context", default="", help="新目标接入的补充上下文")
    # protocol
    run.add_argument("--protocol", default="", help="协议名（protocol_templates/）")
    run.add_argument("--host", default="127.0.0.1")
    run.add_argument("--port", type=int, default=0)
    run.add_argument("--max-cases", type=int, default=0, help="协议最大用例数（0=不限）")
    run.add_argument("--timeout", type=int, default=5)
    # browser
    run.add_argument("--profile", default="", help="Fuzzilli profile（默认 qjs）")
    # 通用
    run.add_argument("--llm", choices=["deepseek", "kimi", "none"], default="deepseek")
    run.add_argument("--budget", type=float, default=60.0,
                     help="任务时间预算秒（loop agent 自主控制循环到此为止）")
    run.add_argument("--interval", type=float, default=2.0, help="观察间隔秒")
    run.add_argument("--digest-delay", type=float, default=2.0, help="注入消化等待秒")
    run.add_argument("--init-seeds", type=int, default=10, help="新目标初始种子数")
    run.add_argument("--out", default="out")
    run.add_argument("--seed-dir", default="in")

    rep = sub.add_parser("report", help="任务报告")
    rep.add_argument("--out", default="out")

    args = parser.parse_args()
    if args.cmd == "run":
        Path(args.out).mkdir(parents=True, exist_ok=True)
        Path(args.seed_dir).mkdir(parents=True, exist_ok=True)
        if args.type == "binary":
            return _run_binary(args)
        if args.type == "protocol":
            return _run_protocol(args)
        if args.type == "browser":
            return _run_browser(args)
    if args.cmd == "report":
        return _report(args)
    return 0


def _report(args) -> int:
    """任务报告：从 out/ 读覆盖统计与崩溃。"""
    out = Path(args.out)
    if not out.exists():
        print(f"错误: {args.out} 不存在", file=sys.stderr)
        return 2
    crashes = list(out.rglob("crashes/id_*")) + list(out.rglob("crash-*"))
    print(f"out: {args.out}")
    print(f"崩溃样本: {len(crashes)}")
    for c in crashes[:10]:
        print(f"  {c.name}")
    stats = out / "fuzzer_stats"
    if stats.exists():
        from fuzzcore.feedback import coverage_from_fuzzer_stats
        cov = coverage_from_fuzzer_stats(str(stats))
        print(f"覆盖: paths={cov.total_paths} bitmap={cov.bitmap_cvg}% "
              f"execs={cov.execs_done} crashes={cov.unique_crashes}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
