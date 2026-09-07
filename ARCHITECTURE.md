# FuzzWahahah 架构决策文档

> 状态：**架构 v2（WREN 已审定，§10 为最新权威）**
> 目标：把当前"boofuzz + 脚本 + AI 门面"重构为一个可支撑 **原生 AI fuzz（agent 调度）+ 覆盖引导 + 结构恢复（读汇编/读代码 → grammar）+ 三目标（浏览器/协议/文件格式）+ Windows** 的平台。
>
> v2 相对 v1 的变化：boofuzz 收进 `fuzzcore/vendor/`；LLM agent 独立成 `llm_agent/` 包（驱动 Kimi Code ACP）；三个目标全部落地为可用引擎；LLM 通过 fuzzcore MCP 工具编排 seed/harness/代码分析/变异分析/执行操作。

---

## 0. 决策摘要

1. **这是架构改造，不是项目改造。** 核心循环从 boofuzz 的 `Session` 上解耦出来，boofuzz 从"平台本身"降级为"一个 engine"。
2. **Engine 采用"监督式黑盒"模型**：AFL++ / libFuzzer / WinAFL / boofuzz / Domato 各自跑自己的内层循环，平台只负责 `启动 / 观察 / 注入 / 停止`，**不**重写它们的变异与调度。
3. **Agent 只在外层循环**，永不进入每轮变异（内层微秒级，LLM 秒级，混在一起吞吐量崩两个数量级）。
4. **三个硬工程决策**：信封优先（envelope-first）；验证门强制（generated seed 必须实测"比随机字节深入更多"才准入 corpus）；LLM 定位为"综合器"而非"反汇编器"。
5. **分阶段交付**：先 FileEngine 最小闭环验证，再 ProtocolEngine，再 Agent，再结构恢复，最后 BrowserEngine。

---

## 1. 现状与问题

当前架构（见各源文件）存在的四个硬约束，决定了它只能重构、不能叠加：

| # | 约束 | 证据 |
|---|------|------|
| 1 | 核心循环封闭 | 所有 fuzzer 及 `protocol_fuzzer_generator.py` 生成的模板最终都是 `Session(...)` → `session.fuzz()`；`Session.fuzz()` 内没有 coverage / corpus / agent 接口位 |
| 2 | 输入抽象错误 | boofuzz 的输入是"发到 socket 的请求"，无法表达"喂给 harness 的字节缓冲"（文件格式）或"喂给引擎的程序"（浏览器 JS） |
| 3 | "AI" 是门面 | `enhanced_symbolic_execution.py` 无求解器、`learn_from_feedback` 无覆盖，是启发式随机变异，不能作为地基 |
| 4 | 两套并列循环 | boofuzz 路径与 AFL 路径（`sudo_mutator.py`）各自独立，无共享 corpus、无统一调度 |

结论：目标终态（原生 AI fuzz + 三目标 + Windows + 结构恢复）跨过了"加功能"的边界，进入"换核心抽象"的领域。

---

## 2. 核心抽象

### 2.1 总览

```
FuzzPlatform
├── Engine 抽象（监督式黑盒）
│    ├── ProtocolEngine   ← 包一层 boofuzz
│    ├── FileEngine       ← WinAFL / libFuzzer / AFL++
│    └── BrowserEngine    ← Domato + headless / WinAFL 组件
├── Target / Harness      ← 引擎要 fuzz 的对象
├── Input                 ← 单个测试样本（bytes 或 program）+ 溯源
├── Feedback              ← 归一化的覆盖 + 事件（crash/timeout/new-edge）
├── Corpus（DB）          ← 共享语料 + 种子队列（generated_program_queue 模式）
├── Mutator               ← 语法感知变异（engine 内置 或 种子合成注入）
├── Grammar（IR）         ← 格式/状态机描述（升级 protocol_templates）
├── SeedSynthesis         ← grammar → 结构化种子 + 保结构变异 + 重算 CRC/长度
├── VerificationGate      ← 种子准入前的"解析深度"裁决
├── StructureRecovery     ← 反汇编(Ghidra/angr) + 源码(libclang/tree-sitter) + LLM → Grammar
├── Agent                 ← 外层调度（fuzz loop agent）
└── CrashTriage           ← cdb/gdb 最小化 + 根因 + 变体
```

### 2.2 接口草案（Python 风格，非最终实现）

```python
class Engine(ABC):
    """自包含 fuzz 引擎。平台只监督与观察，不接管其内层循环。"""
    id: str
    target: Target

    def start(self, **cfg) -> EngineHandle          # 起子进程/worker
    def stop(self, handle: EngineHandle) -> None
    def status(self, handle) -> EngineStatus        # 运行态 + coverage_rate + crash 计数
    def inject_seeds(self, handle, seeds: list[Input]) -> None   # 写入语料/种子队列
    def export_corpus(self, handle) -> list[Input]
    def export_coverage(self, handle) -> CoverageReport


class Target:
    kind: "binary" | "service" | "browser"
    command: str          # 二进制+args / endpoint / browser profile
    harness: "Harness | None"   # libFuzzer/AFL harness 描述（含 @@ 或 stdin 约定）


class Input:
    data: bytes                      # 或 program 文本（浏览器/协议）
    provenance: SeedProvenance       # 来自哪个 grammar/模板/变异器/父样本
    coverage_sig: str | None


class Feedback:
    coverage: CoverageReport         # 归一化后的边/分支集合 + 趋势
    events: list[Crash | Timeout | NewEdge]


class Corpus(ABC):
    """DB 持久化（替代 ai_learning_data/*.json 单文件）。"""
    def add(self, input: Input, meta: dict) -> None
    def query(self, **filters) -> list[Input]
    def enqueue_seed(self, target_id: str, seed: Input) -> None   # 种子队列
    def pull_seed(self, target_id: str) -> list[Input]


class Mutator:
    """语法感知变异。两种形态：
    (a) engine 内置（AFL_PYTHON_MODULE，如 FileEngine 的格式感知 mutator）
    (b) 种子合成器：从 Grammar 生成合法种子注入 corpus（不破坏 magic/CRC/长度）"""
    grammar: Grammar
    def synthesize(self, count: int) -> list[Input]
    def mutate(self, input: Input) -> list[Input]
```

**关键设计决定（需要 WREN 拍板）**：`Engine` 是**监督式黑盒**，不是"平台驱动执行"。
理由：AFL++ / libFuzzer / boofuzz 各自的调度与变异是多年打磨的，平台重写它们的循环既是大工程又会丢掉它们的启发式。平台的价值在于**跨引擎统一观察、统一语料、统一调度、注入结构感知种子**——这正是 OSS-Fuzz / ClusterFuzz / Fuzzillai（Fuzzilli=engine，Postgres=反馈，agent=观察+注入）的成熟范式。

---

## 3. 两层循环与数据流

```
                    ┌────────────────────────────────────────┐
                    │  Agent（外层，秒级，事件驱动）            │
                    │  observe → decide → act                  │
                    │  工具: generate_seeds / triage_crash /    │
                    │        write_harness / set_strategy       │
                    └──────┬─────────────────────────▲─────────┘
                    注入种子│  调整策略/写harness      │读状态
                    ┌──────▼─────────┐        ┌──────┴─────────┐
                    │  SeedSynthesis │        │  Feedback +    │
                    │  Grammar IR    │        │  Corpus(DB)    │
                    └──────┬─────────┘        └──────▲─────────┘
                    合法种子│                          │coverage/crash
                    ┌──────▼──────────────────────────┴─────────┐
                    │  Engine（内层，微秒级，确定性，各自循环）      │
                    │  Protocol / File / Browser engine           │
                    └─────────────────────────────────────────────┘
```

- **内层**：engine 跑高吞吐变异 + 执行，产出 coverage / crash / 有趣样本 → 归一化进 Corpus。
- **外层**：Agent 在"平台期 / 崩溃 / 新目标 / 定时"四个触发点被唤醒，做目标选择、种子生成、harness 生成、崩溃分诊、策略调整。
- **种子队列**：Agent/SeedSynthesis 的产出不直接进 engine 共享语料，而是按 `generated_program_queue`（Fuzzillai 模式）排队给目标 engine，由 engine 下个同步周期拉取后清除。解耦生产与消费。

**触发点**（事件驱动，非轮询）：
1. 覆盖率平台期（新边 N 分钟无增长）→ 换目标 / 生成定向种子 / 换策略。
2. 崩溃产生 → 唤醒 CrashTriage（最小化 + 根因 + 变体）。
3. 新目标接入 → StructureRecovery → Grammar → 初始 corpus + harness。
4. 定时健康检查 + 全局重调度。

---

## 4. Grammar IR（结构恢复的产出，种子合成的输入）

这是 B/C/D/E 各阶段的公共契约。草案 schema：

```json
{
  "name": "png",
  "kind": "binary_file",              // binary_file | protocol | dom
  "fields": [
    { "name": "magic", "offset": 0, "size": 8,
      "type": "magic", "value": "89504E470D0A1A0A" },
    { "name": "width",  "offset": 16, "size": 4,
      "type": "uint_be", "constraints": { "range": [1, 2147483647] } },
    { "name": "chunk_len", "offset": 8, "size": 4,
      "type": "length", "references": "chunk_data" },
    { "name": "chunk_data", "type": "container",
      "length_field": "chunk_len", "nested": "chunk" },
    { "name": "crc", "type": "checksum",
      "algorithm": "crc32", "over": ["chunk_type", "chunk_data"] }
  ],
  "containers": [
    { "name": "chunk",
      "tag_field": "chunk_type",
      "variants": { "IHDR": { "...": "..." }, "IDAT": { "...": "..." } } }
  ],
  "state_machine": []                 // 仅 protocol 使用（会话/状态转移）
}
```

设计要点：
- `type` 覆盖 `magic / uint_be / uint_le / length / checksum / container / tag / varint / blob / choice`。
- `length` 与 `checksum` 是**约束关系**而非普通字段：变异器据此重算，而非盲翻字节。
- `container` + `tag` 表达嵌套与分发，解决 TLV / 递归解析。
- `state_machine` 给协议用，浏览器侧用独立的 DOM 语法（`kind: dom`），不硬塞进字节格式模型。

---

## 5. Keep / Replace 迁移清单

### 5.1 保留（概念/资产，多数需改造）

| 现有资产 | 去向 |
|----------|------|
| boofuzz 的 block/primitive/`s_size`/`s_checksum` 语法模型 | ProtocolEngine 的 grammar 层（成熟，勿重造） |
| `protocol_templates/*.json` | 迁移为 Grammar IR |
| `protocol_configs/*.yaml` | 迁移为 Engine 配置 |
| `llm_seed_generator.py` / `eml_seed_generator.py` | 改造为 Agent 工具（`generate_seeds`） |
| `sudo_mutator.py` 的 AFL 自定义变异器模式 | FileEngine 的格式感知 mutator 骨架 |
| `ai_learning_data` 概念 | 升级为 DB Corpus |
| `fuzz_pop3_server.py` / `redis_mock.py` | 差分 oracle 参考实现 |
| POP3 CVE 定向思路 | 定向 fuzz 的范式参考 |

### 5.2 替换（核心）

| 现有资产 | 替换为 |
|----------|--------|
| `Session.fuzz()` 封闭循环 | Engine 抽象 |
| `enhanced_symbolic_execution.py` / `symbolic_execution.py` 假符号执行/假遗传算法 | 真实覆盖引导 + StructureRecovery |
| `protocol_fuzzer_generator.py`（Jinja 生成器） | Grammar IR + Engine 配置 |
| `process_monitor.py`（pedrpc） | `cdb_monitor.py`（WinDbg/cdb）+ WinAFL 崩溃收集 |
| `boofuzz_*_fuzzer.py`（14 个独立脚本） | ProtocolEngine 的 profile 配置（非独立脚本） |
| 硬编码 API key（`eml_seed_generator.py:13`、`llm_seed_generator.py:9`） | `keys.cfg` + env（参照 fuzzillai 的 `config_loader.py`） |

---

## 6. 分阶段落地计划

每个阶段有明确的交付物与退出标准。

### Phase 0 — 架构冻结（本阶段）
- 交付：本决策文档 + 仓库目录布局。
- 退出：核心抽象接口（§2.2）与 Grammar IR（§4）经 WREN 审定。

### Phase 1 — FileEngine 最小闭环（验证切片）✅ 已完成
- 目标：证明"覆盖引导 + 结构化种子 + DB 语料"能跑通并优于裸 AFL。
- 验证目标（最终落地）：**CRC32 校验和门 + LZMA 解码器**（真实 7-Zip 代码 `7zCrc.c` + `LzmaDec.c`）。
  原定 `7z.exe` 全量容器因需要整个编解码器树（~50 文件 + COM 接口）而暂缓；改用"CRC32 门 + 门后 LZMA 深代码"的等价切片，严格门 + 深代码两头兼备。
- 交付：`FileEngine` 多 driver（`WinAFLFileEngine` 黑盒 + `LibFuzzerFileEngine` 源码 harness，共用 `BaseProcessEngine`）+ `Corpus`（SQLite）+ `Feedback`（读 AFL map）+ `cdb_monitor`（`fuzzcore/monitor/cdb_monitor.py`）。
- 退出标准 ✅ 达成：**结构化种子 cov=223 vs 裸变异 cov=20（11x）**（`-use_cmp=0` 纯变异基线，等价于 WinAFL 的裸变异）。
- 关键结论：
  - WinAFL 路径工具链已建成；DynamoRIO 后端在 Windows 25H2（build 26200）下
    对 kernel32/kernelbase 系统调用路径的翻译存在 execute-fault（0xc0000005 type 8），
    所有 DR 版本（9.0.1/11.3/11.90/11.91）均受影响；根因与 winafl 的 ABSMEM 插桩
    在高位共享内存地址截断相关（winafl.c 已修 movabs 间接寻址防御）。
  - **WinAFL 的可用路径是 TinyInst 后端**（`-DTINYINST=1` 构建，`afl-fuzz -y`），
    纯调试器 API 不依赖 DR 代码缓存：afl-showmap 收集 1462 覆盖 tuple，
    afl-fuzz 真实循环 45 秒抓到 2 个 crash（build64_tinyinst）。
    fuzzcore 的 WinAFLFileEngine 已支持 `mode="tinyinst"`（默认）/ `"dynamorio"`。
  - libFuzzer 路径完整跑通；默认 `use_cmp=1` 会自动解简单 magic/CRC 门，纯变异（`use_cmp=0`）下结构化种子价值凸显。
  - 端到端 loop 已由项目自身代码驱动（`fuzzcore/phase1_demo.py`：`SqliteCorpus` → `LibFuzzerFileEngine` → coverage 解析）。

### Phase 2 — Grammar IR + 种子合成 + 验证门 ✅ 已完成
- 交付：`fuzzcore/grammar/ir.py`（Grammar/Field schema）+ `seed_synthesis.py`（SeedSynthesis）+ `verification_gate.py`（VerificationGate）。
- 退出标准 ✅ 达成：以 CRC32+LZMA 为手写 Grammar，`phase2_demo.py` 验证——合成合法种子（gate=True）、100 次保结构变异全部通过、破坏 CRC 被拦（gate=False）、100 次不保结构变异 0 通过。
- 集成验证：Grammar 合成的种子与 Phase 1 手工种子逐字节一致，可直接喂进 libFuzzer harness 达到深覆盖（cov 223）。

### Phase 3 — ProtocolEngine（包 boofuzz）✅ 已完成
- 交付：`fuzzcore/engine/protocol_engine.py`（boofuzz 包成 Engine）+ `fuzzcore/profiles/generic_profile.py`（通用 profile，读 `protocol_templates/*.json` 自动生成请求）+ `fuzzcore/phase3_demo.py`（端到端演示）。
- 退出标准 ✅ 达成：16 个协议模板全部可加载（dns/echo/ftp/http/http2/imap/mqtt/mssql/mysql/pop3/rdp/redis/smtp/ssh/sudo/telnet），端到端演示跑通 echo/http/ftp（各 30 用例），feedback（测试用例数/崩溃数）从 engine.log 解析进 CoverageReport。
- 说明：boofuzz 已从"平台本身"降级为"一个 Engine 实现"（子进程启动 profile + 观察输出）。
- 遗留：原 14 个 `boofuzz_*_fuzzer.py` 有 `timeout=` 参数 bug（vendored SocketConnection 用 `send_timeout`/`recv_timeout`）且依赖假 AI，属遗留脚本待清理；协议数据到 Grammar IR 的 protocol/state_machine 映射留待后续。

### Phase 4 — FuzzLoopAgent（调度）✅ 已完成
- 交付：`fuzzcore/agent/agent.py`（FuzzLoopAgent：observe→decide→act 状态机 + 工具注册 + 事件派发）+ `fuzzcore/agent/tools.py`（generate_seeds/set_strategy/triage_crash）+ `fuzzcore/phase4_demo.py`。
- 退出标准 ✅ 达成：MockEngine 模拟 CRC 门，平台期(20) → Agent 检测 → 生成定向种子（Grammar 合成合法 CRC）→ 注入 → 覆盖回升(223)。事件序列 plateau → seeds_injected → recovered 完整可复现。
- 说明：Agent 只在外层循环，不进入内层变异；generate_seeds 复用 Phase 2 的 SeedSynthesis。

### Phase 5 — StructureRecovery（读汇编/读代码 → Grammar）✅ 核心完成
- 交付：`fuzzcore/recovery/rizin_frontend.py`（RizinFrontend，rizin/Cutter 字符串+信息提取）+ `fuzzcore/recovery/recover.py`（StructureRecovery，字节搜索 magic + Grammar 构建）+ `fuzzcore/phase5_demo.py`。
- 验证：对 7z.dll（真实解析器二进制）定位 .7z 签名 `377abcaf271c`（偏移 0x19fef4）+ 提取 27399 个字符串（格式提示）→ 构建信封 Grammar（magic+CRC+payload）→ SeedSynthesis 合成种子 gate=True。
- 说明：本阶段落地"信封恢复"最小切片（magic 定位 + Grammar 构建）；完整 length/CRC/container 的自动数据流恢复 + LLM 综合器属后续增强（angr/LLM 未引入）。

### Phase 6 — BrowserEngine（JS 引擎：内层复用 Fuzzilli，外层用自己机制）✅ 优化完成
- 架构原则（非抄写）：只复用 Fuzzilli 的**内层覆盖引导变异**（成熟、不重造），外层智能用 FuzzWahahah 自己的通用机制，不抄 fuzzillai 的 FoG/EBG。
- 交付：
  - `fuzzcore/engine/fuzzilli_engine.py` — FuzzilliEngine（内层，包装 FuzzilliCli）。
  - `fuzzcore/jsprog/generator.py` — 程序级种子合成（"程序 grammar" → 结构化 JS），**语言无关**，等价于 fuzzillai 的 ProgramTemplate 但产出 JS 文本而非 Swift 模板。
  - `fuzzcore/jsprog/gate.py` — JS 验证门（node --check），复用 Phase 2 的验证门概念。
  - `fuzzcore/jsprog_demo.py` — 6 个目标特性（jit_function/property_access/class_hierarchy/generator/async_await/typed_array）全部生成并通过验证门。
- 优化点：fuzzillai 写死成 V8+Swift 的 ProgramTemplate，FuzzWahahah 用"程序 grammar → JS 种子 → 验证门 → FuzzLoopAgent 调度"这套**目标无关**机制覆盖任意 JS 引擎；同一套 Grammar/Seed/Verification/Agent 已用于文件格式（字节级）与协议，程序级是它的自然扩展。
- 依赖（未就绪）：fuzzillai 需 `swift build`（v8/v8 与 IkaCore 子模块当前为空）+ 目标 JS 引擎 d8 编译。

### Phase 6b — Fuzzilli + QuickJS Windows 端到端打通（2026-09-07）✅ 完成

**新环境初始化**：`scripts/setup_windows.ps1`（仅 Windows）一键复现完整工具链——前置检查（C: 盘空间/VS/LLVM/node/7zip/git）、winget 装 Swift、开发者模式 + SwiftPM 镜像、fuzzillai clone + patch 固化 + swift build + DLL 归位、QuickJS 编译、（可选）WinAFL TinyInst、验证。patch 固化在 `patches/`（fuzzillai 修改文件完整副本 + winafl git diff + postgres-nio PoolStateMachine 备用）。用法：`powershell -ExecutionPolicy Bypass -File scripts\setup_windows.ps1 [-SkipWinAFL] [-Mirror <前缀>]`。脚本需 UTF-8 with BOM（PowerShell 5.1 中文兼容）。

- **fuzzillai Windows 构建**：`swift build` 出 FuzzilliCli.exe（Swift 6.3.3 for Windows）。摘除 postgres-nio/postgres-kit（其传递依赖 swift-nio-ssl 显式 `#error("unsupported os")`，且 postgres 同步属 FoG/EBG，本架构用 fuzzcore MCP 替代）；3 个源文件 `#if !os(Windows)` 包裹保留上游兼容。
- **libreprl-windows.c（REPRL Windows 实现）修复 6 个核心 bug**：CreatePipe 逻辑反转、hChild calloc 初始化 0 vs INVALID_HANDLE_VALUE(-1) 致从不 spawn、CreateProcessA 的 lpEnvironment 需环境字符串块（非 POSIX char**）、commandline 拼接 strncpy_s 长度算负 abort、WaitForSingleObject 等子进程退出 vs REPRL 持久循环、JS stdout 与控制管道混淆致协议污染（signal='['=91）。
- **QuickJS REPRL Windows 移植**（`fuzzwahahah/vendor/quickjs/`）：POSIX patch 的 sys/mman.h/shm_open → CreateFileMapping/MapViewOfFile；`--reprl` argv 触发；shmem_data 布局严格匹配 libcoverage（offsetof(edges)）；sancov 段边界经 module ctor init 保存；posix_shim（unistd/dirent/sys/time/utime）+ 关 Atomics。
- **端到端验证**：FuzzilliCli 驱动 qjs_fuzzilli.exe，`[Coverage] Initialized 26893 edges`，outcome=Succeeded，corpus/crashes 产出；**fuzzcore FuzzilliEngine 端到端 25 秒抓到 1 个 crash**。
- fuzzcore `FuzzilliEngine` 已对齐：默认 `profile=qjs` / `engine=mutation`、`--key=value` 参数形式、`--overwrite`（storagePath 非空兼容）。
- 后续（大工程）：v8/d8（depot_tools + gclient sync 网络依赖，VRIG fork 已下载核心源码）；QuickJS Atomics（pthread shim）。

---

## 7. 关键工程决策（已定 / 待定）

**已定：**
1. 架构改造（非项目改造）。
2. Engine = 监督式黑盒，平台不重写内层循环。
3. Agent 只在外层循环。
4. 信封优先、验证门强制、LLM 作综合器。

**已定（架构冻结）：**
- 覆盖归一化：Phase 1 只接 AFL map（`fuzzer_stats` + `afl-showmap`），libFuzzer/boofuzz 的归一化后置到对应 Engine 落地时再补。
- Corpus 存储：SQLite 单机起步，接口对齐 DB 模式（语料表 + 种子队列），后续换 Postgres 不改接口。
- Phase 1 验证目标：7-Zip（`7z.exe`）解析 `.7z`，接口 `7z t @@`（见 §6 Phase 1）。

---

## 8. 风险

| 风险 | 缓解 |
|------|------|
| LLM 合成的 grammar 有幻觉 | 验证门强制裁决；结构恢复分"确定性事实提取"与"不确定性综合"两层，后者不污染前者 |
| 跨引擎覆盖不可比 | CoverageReport 先做"同引擎内趋势"，跨引擎归一化后置 |
| Windows 崩溃检测不稳定 | cdb `!analyze -v` 为主，WER/crashpad dump 兜底 |
| 工程量大、战线长 | 严格按 Phase 顺序，每阶段独立可验证，不在前序未稳时开新战线 |

---

## 9. 状态

- 架构已冻结（§7 三项待定项已由 WREN 拍板）。
- **Phase 1 已完成**：结构化 223 vs 裸 20，端到端 loop 由项目自身代码驱动。
- **Phase 2 已完成**：Grammar IR + SeedSynthesis + VerificationGate（`fuzzcore/grammar/`），`phase2_demo.py` 验证通过。
- **Phase 3 已完成**：ProtocolEngine + generic_profile（16 协议模板），`phase3_demo.py` 跑通 echo/http/ftp。
- **Phase 4 已完成**：FuzzLoopAgent 调度闭环（平台期 20 → 定向种子 → 223），`phase4_demo.py` 验证。
- **Phase 5 已完成**：StructureRecovery（读二进制恢复 magic → Grammar），`phase5_demo.py` 验证。
- **Phase 6 已纠正**：浏览器/JS 引擎复用 fuzzillai（FuzzilliEngine），移除 Domato 玩具；依赖 fuzzillai build + d8。

---

## 10. 架构 v2（2026-09-06，WREN 审定）

### 10.1 五项审定决策

1. **boofuzz 收进 fuzzcore/**：vendored boofuzz 位于 `fuzzcore/vendor/boofuzz/`；项目根脚本经 `fw_vendor` 一行引导注入路径（`sitecustomize` 机制不可靠，弃用）；fuzzcore 包内由 `fuzzcore/__init__.py` 自动注入。
2. **LLM agent 独立**：`llm_agent/` 是独立顶层包，只通过 ACP（会话）与 MCP（工具）两个协议面与平台通信，不依赖 fuzzcore 内部对象。
3. **三目标完整实现**：文件格式 / 协议 / 浏览器各自有完整引擎 + 语法层 + 验证门 + 反馈契约，不允许"有引擎无反馈"的半成品。
4. **LLM 编排**：Kimi Code（`kimi acp` ACP 会话）承担编排循环，编排 seed、harness、代码分析、变异分析、执行操作；工具通过 `fuzzcore/mcp/` 的 MCP server 暴露；所有 LLM 产出强制过 VerificationGate / schema 校验。
5. **所有问题修复**：历史遗留的 B/C 级问题并入对应组件一并修复。

### 10.2 v2 目录布局

```
fuzzwahahah/
├── fuzzcore/                    ★ 唯一平台
│   ├── vendor/boofuzz/          vendored boofuzz（含 Session AI 接线、Group utf-8）
│   ├── engine/                  Engine 抽象 + FeedbackKind 反馈契约 + restart 消化
│   ├── grammar/                 Grammar IR + SeedSynthesis + VerificationGate
│   ├── feedback/                AFL 覆盖解析（afl_map 已破 feedback↔engine 循环）
│   ├── corpus/                  SQLite: inputs + seed_queue + grammars + learning_events
│   ├── agent/                   FuzzLoopAgent + restart_on_inject 消化编排
│   ├── recovery/                结构恢复（信封切片）
│   ├── jsprog/                  程序语法 → JS 种子 + node 验证门
│   ├── monitor/                 cdb 崩溃监视
│   ├── mcp/                     ★ MCP server（stdio, 5 工具, 无状态）
│   └── profiles/                协议 profile
├── vendor/                      ★ vendored 第三方依赖（主目录自包含）
│   ├── quickjs/                 QuickJS + REPRL Windows 移植（qjs_fuzzilli.exe）
│   ├── fuzzillai/               Fuzzilli fork（FuzzilliCli.exe, postgres 已摘除）
│   └── winafl/                  WinAFL + TinyInst（文件格式黑盒路径）
├── llm_agent/                   ★ 独立包: ACP client + 事件→prompt 编排器
├── patches/                     fuzzillai/winafl 修改的固化（新环境初始化用）
├── scripts/setup_windows.ps1    Windows 环境初始化（仅 Windows）
├── fw_vendor.py                 裸脚本的 vendor 路径引导
├── attic/                       已隔离危险文件
└── 遗留脚本                      boofuzz_*_fuzzer.py ×15（逐步退役为 profile）
```

注：vendored 依赖的**源码**进 git（boofuzz/quickjs/fuzzillai/winafl 一致），**构建产物**由 `.gitignore` 排除（vendor/fuzzillai/.build、vendor/winafl/build64_* 等）。

### 10.3 LLM 编排链路（实测已通）

```
平台事件                  llm_agent                    fuzzcore MCP 工具
──────────────────────────────────────────────────────────────────────────
新目标接入   → on_new_target   → recover_structure（事实）→ register_grammar（验证）
                                 → generate_seeds → 种子队列
平台期       → on_plateau      → get_status（观测）→ analyze → generate_seeds（定向）
                                 → execute(restart) 消化（Agent SeedDigestCycle）
崩溃         → on_crash        → triage_crash → 根因假设 → 变体种子
健康检查     → on_healthcheck  → get_status × N → 调度建议
```

已验证：`llm_agent` 冒烟测试（真实 Kimi Code 会话）——LLM 自主发现并调用
`get_status`，拿到真实平台状态（corpus/queue/grammars）。

### 10.3b 完整闭环（2026-09-07，真实引擎 + 真实 LLM 已验证）

补全了 LLM 编排的完整闭环（此前四个断点已修）：

1. **grammar 统一**：`make_corpus_seed_generator` 从 Corpus 按名取 grammar，
   规则自救与 LLM 编排共用同一来源（不再内存对象 vs Corpus 两套）。
2. **种子拉取接通**：`FuzzLoopAgent.step` 自救**先 `pull_seeds`（消费 LLM 队列）
   再 `generate_seeds`（反射弧兜底）**——LLM 种子经 SQLite 队列流入下一轮 pull。
3. **升级钩子**：连续 `escalate_after` 次 `still_plateau` 后经 `on_escalate`
   升级 LLM 编排（不再手动喂事件）。
4. **统一编排器 `FuzzJobRunner`**（`fuzzcore/agent/runner.py`）：新目标接入
   （register grammar + 初始种子）→ 稳态 fuzz → 平台期反射弧自救 → 连续无效
   升级 LLM → LLM 语义种子经队列回流 → 覆盖回升，自驱动状态机 + `JobReport`。

**SeedDigestCycle 延迟判定修正**：第一版 restart 后立即 observe 看不到引擎消化
新种子，误报 still_plateau 导致误升级 LLM。改为 inject 后记基线、下一轮 observe
对比判 recovered/still_plateau——反射弧真有效时不误升级（闭环的省钱设计成立：
引擎+反射弧能解决的门不惊动 LLM）。

**端到端验证**（`fuzzcore/jobrunner_demo.py`，真实 7z harness CRC32 门）：
recovered=2，覆盖 0→310，反射弧穿门成功；`jobrunner_llm_demo.py` 验证真实
Kimi Code 编排链路。

### 10.3c 严格校验 + DeepSeek 后端（2026-09-07）

**IR 严格校验**（`fuzzcore/grammar/ir.py`）：`Field.from_dict` 白名单校验
`magic/checksum/length/blob/raw/uint`。动机是发现一个真实漏洞——LLM 用不规范
type（bytes/u32）时，`SeedSynthesis`/`VerificationGate` 静默跳过这些字段，
种子残缺（只有 blob）且验证门误判通过。严格校验在 `register_grammar` 期拒绝，
错误信息带合法 type + 正确示例（LLM 的自我修正提示）。

**DeepSeek 后端**（`llm_agent/deepseek_orchestrator.py`）：OpenAI-compatible
function calling，进程内执行 fuzzcore 工具（复用 `MCPServer` 实现，无子进程，
比 ACP 轻）。与 Kimi Code ACP 并存可互换。key 经 `OPENAI_API_KEY` 环境变量。

**真实 DeepSeek 验证**（新目标接入，严格校验下自我修正）：DeepSeek 综合 grammar
首次因缺 algorithm 被拒，读错误提示补 crc32 后通过；产出 21 字节真 LZMA 信封
种子（magic props + length + crc32 + blob），5 个全过验证门。对比无严格校验时
Kimi Code 的不规范 type 产出的是 8 字节全零残缺种子且验证门误判通过。

### 10.3d 统一 CLI（2026-09-07）

`fuzzcore/cli.py` + `fuzzcore/__main__.py` 提供统一入口（替代散落的独立脚本）：

```
fuzz run --type binary --harness X [--magic Y --llm deepseek]   # 完整闭环
fuzz run --type protocol --protocol P --host H --port N          # 引擎+观察
fuzz run --type browser                                          # Fuzzilli+QuickJS
fuzz report --out DIR                                            # 任务报告
```

binary 走完整闭环（LLM 综合 grammar → FuzzJobRunner）；LLM 综合不确定时回退
recovery 确定性信封（`--magic` 给定时）。protocol/browser 的语法层（协议状态机/
程序语法）与字节 Grammar 不同构，当前跑引擎+观察+报告，闭环在语法层统一后接入。
端到端验证：DeepSeek 综合 `crc_lzma_envelope` → 闭环覆盖 0→309。

### 10.3e Loop Agent 工作流（2026-09-07）

工具形态的本质修正：`FuzzJobRunner.run(max_rounds=N)` 的外部固定循环改为
**LoopAgent 自主工作流**（`fuzzcore/agent/loop_agent.py`）——agent 是循环的主人：

```
loop_until_done(budget_s):
  while not should_stop():          # agent 自主判断终止(预算/收敛/出bug)
      obs  = observe()              # 覆盖/崩溃/队列/学习数据
      plan = decide(obs)            # 策略选择(continue/reflex/escalate_llm/triage/stop)
      act(plan)                     # 行动(种子/注入/重启消化/分诊)
      learn(obs, plan)              # 学习(策略成功率进 Corpus 跨任务)
  return report()                   # TaskReport(覆盖+崩溃+策略统计+学习结论)
```

五要素（WREN 审定）：隐式状态机(decide 返回动作+phase 调试字段)、双层记忆
(内存+Corpus)、LLM 配额(llm_budget 内最多 N 次, 超出回退反射弧)、保守收敛
(converge_rounds 轮无进展+无崩溃)。

真实引擎验证（7z harness，budget 40s）：agent 自主决策序列
`continue→reflex→recovered(87→96)→still_plateau→escalate_llm→LLM 种子回流→
覆盖 261→293→budget 终止`——反射弧有效用它、无效升级 LLM、自主终止，全绿。

### 10.4 反馈契约（feedback_kind）

`Engine.feedback_kind`：EDGE_COVERAGE（真边覆盖，平台期自救有效）/
PROXY_METRICS（代理指标，如 boofuzz 日志计数，平台期语义降级为"活动停滞"）。
Agent 决策按等级降级，不再对假覆盖信号做覆盖决策。

### 10.5 学习数据归一化

vendored 侧（Session AI / enhanced engine）保持写 JSON（不反向依赖平台）；
`fuzzcore/corpus/learning_import.py` 幂等导入 `learning_events` 表
（文件名分类：engine/session × 协议/全局），Agent/LLM 经
`sync_learning_data` MCP 工具触发同步。`ai_learning_data/*.json` 堆积问题保留
文件层，DB 是唯一查询面。

### 10.6 v2 待办（外部工具链）

- ~~WinAFL/DynamoRIO（Windows 25H2 代码缓存 bug）~~ → **已解决：TinyInst 后端**（§6 Phase 1）
- ~~fuzzillai 构建（swift build + 子模块）~~ → **已完成：FuzzilliCli.exe + QuickJS REPRL Windows 移植**（§6 Phase 6b）
- ~~Grammar IR 的 state_machine~~ → **已完成：ProtocolState**（协议会话状态机）
- Grammar IR 的 container（嵌套 TLV）→ 后续
- v8/d8（depot_tools + gclient sync 网络依赖）→ 浏览器真实目标（QuickJS 已可用）
- cdb.exe 安装 → CrashTriage 实测
