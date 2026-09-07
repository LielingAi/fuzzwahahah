# FuzzWahahah

FuzzWahahah 是一个面向 Windows 平台的覆盖引导（coverage-guided）模糊测试平台，支持三类目标：**文件格式**、**网络协议**、**浏览器 JavaScript 引擎**。平台在外层用 LLM agent 做调度与种子/语法综合，内层复用成熟的 fuzzing 引擎，不重写它们的变异与调度循环。

## 核心能力

- **三类目标的统一引擎抽象**：AFL++/WinAFL（TinyInst）、libFuzzer、boofuzz、Fuzzilli 各自作为可插拔的内层引擎，平台统一启动、观察、注入种子、收集覆盖与崩溃。
- **结构感知的种子合成**：从二进制恢复输入格式结构（magic / length / checksum），合成不破坏校验和的合法种子，并通过验证门（VerificationGate）拦截坏种子。
- **LLM 编排**：LLM agent 在外层循环（秒级）做平台期自救、定向种子生成、崩溃分诊与 harness 合成，所有产出强制过验证门，幻觉无法进入语料库。
- **协议会话状态机**：Grammar IR 支持会话级状态机（login → command → logout），合成与验证合法会话序列。

## 当前状态

| 目标 | 引擎 | 状态 |
|------|------|------|
| 文件格式 | WinAFL（TinyInst 后端）/ libFuzzer | 端到端可用，结构化种子覆盖 11× 于裸变异 |
| 网络协议 | boofuzz（15 协议 profile + 通用生成器） | 端到端可用 |
| 浏览器 | Fuzzilli + QuickJS（REPRL Windows 移植） | 端到端可用，已抓到真实崩溃 |

详细的架构决策、分阶段交付记录与已知限制见 [ARCHITECTURE.md](ARCHITECTURE.md)。

## 快速开始（Windows）

环境要求：Windows 10/11、Visual Studio 2022（含 C++ 工作负载）、Python 3.10+。

```powershell
powershell -ExecutionPolicy Bypass -File scripts\setup_windows.ps1
```

初始化脚本完成外部工具检查、Swift 工具链安装、fuzzillai 与 QuickJS 构建、（可选）WinAFL/TinyInst 构建与端到端验证。加 `-SkipWinAFL` 可跳过 WinAFL 构建。

构建产物：

- `vendor/fuzzillai/.build/debug/FuzzilliCli.exe` — Fuzzilli 命令行前端
- `vendor/quickjs/qjs_fuzzilli.exe` — 带覆盖插桩与 REPRL 支持的 QuickJS

运行示例：

```powershell
# 浏览器：Fuzzilli 驱动 QuickJS
.\vendor\fuzzillai\.build\debug\FuzzilliCli.exe --profile=qjs --storagePath=out .\vendor\quickjs\qjs_fuzzilli.exe

# 协议：以 Echo 为例（其余 14 个协议脚本同构）
python boofuzz_echo_fuzzer.py <host> <port>

# 平台演示（引擎/语法/调度/结构恢复/LLM 编排）
python fuzzcore\phase1_demo.py
python fuzzcore\mcp_demo.py
```

## 目录结构

```
fuzzcore/            平台核心（引擎抽象、语法 IR、验证门、语料库、调度 agent、MCP 工具、结构恢复）
  vendor/boofuzz/    vendored boofuzz（协议 fuzzing）
vendor/              vendored 第三方依赖
  quickjs/           QuickJS（含 REPRL Windows 移植与覆盖插桩）
  fuzzillai/         Fuzzilli fork（JS 引擎 fuzzer）
  winafl/            WinAFL + TinyInst（Windows 覆盖引导 fuzzer）
llm_agent/           LLM 编排包（Kimi Code ACP 客户端 + 事件→prompt 编排）
protocol_templates/  16 种协议数据模板
protocol_configs/    协议 fuzzer 生成器配置
scripts/             环境初始化脚本
patches/             对 fuzzillai/winafl 的定制补丁（新环境初始化用）
```

## 致谢

FuzzWahahah 建立在以下开源项目与框架之上：

- **[boofuzz](https://github.com/jtpereyda/boofuzz)**（GPL-2.0）— 网络协议模糊测试框架，vendored 于 `fuzzcore/vendor/boofuzz`，作为协议引擎与协议语法模型。
- **[Fuzzilli](https://github.com/googleprojectzero/fuzzilli)**（Apache-2.0）— Google Project Zero 的覆盖引导 JavaScript 引擎 fuzzer，作为浏览器目标的内层引擎。
- **[fuzzillai](https://github.com/VRIG-RITSEC/fuzzillai)**（Apache-2.0）— Fuzzilli 的分叉，本项目在其 Windows 移植基础上修复了 REPRL 的若干问题。
- **[WinAFL](https://github.com/googleprojectzero/winafl)**（Apache-2.0）— Windows 平台的覆盖引导 fuzzer（AFL 移植）。
- **[TinyInst](https://github.com/googleprojectzero/TinyInst)**（Apache-2.0）— 轻量动态插桩库，作为 WinAFL 在 Windows 25H2 上替代 DynamoRIO 的插桩后端。
- **[DynamoRIO](https://dynamorio.org/)**（BSD）— 动态二进制插桩框架（WinAFL 的可选后端）。
- **[AFL++](https://github.com/AFLplusplus/AFLplusplus)**（Apache-2.0）— 覆盖引导 fuzzing 的范式与反馈信号（fuzzer_stats / showmap）来源。
- **[libFuzzer / LLVM SanitizerCoverage](https://llvm.org/docs/LibFuzzer.html)**（Apache-2.0 with LLVM Exceptions）— 进程内覆盖引导 fuzzing 与 `trace-pc-guard` 覆盖插桩。
- **[QuickJS](https://bellard.org/quickjs/)**（MIT，Fabrice Bellard）— JavaScript 引擎，本项目为其补充了 REPRL 的 Windows 实现。
- **[Intel XED](https://github.com/intelxed/xed)**（Apache-2.0）— x86 指令编码/解码库（TinyInst 依赖）。
- **[SQLite](https://www.sqlite.org/)**（公有领域）— 语料库、种子队列与学习数据的持久化。
- **[Kimi Code](https://www.kimi.com/code/)**（Moonshot AI）— LLM agent，经 Agent Client Protocol（ACP）承担外层编排。

架构上参考了 OSS-Fuzz 与 ClusterFuzz 的"监督式黑盒引擎"范式，以及 Fuzzillai 的 generated-program-queue 种子队列模式。

## 许可证

本项目代码以 [MIT](LICENSE) 许可证发布。各 vendored 第三方组件保留其原始许可证（见上述致谢及对应目录）。

许可证分层说明：vendored 的 **boofuzz**（`fuzzcore/vendor/boofuzz`）为 GPL-2.0，直接 `import boofuzz` 的协议 fuzzer 脚本（`boofuzz_*_fuzzer.py` 及生成器产物）与其构成单一程序，同样以 GPL-2.0 发布；平台其余部分（`fuzzcore/` 的引擎、调度、语法、`llm_agent/` 等）通过子进程方式调用 boofuzz，属于聚合（aggregate）而非衍生作品，以 MIT 发布。
