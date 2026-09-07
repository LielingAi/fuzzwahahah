# patches/ — 对 vendored 依赖的定制补丁（新环境初始化用）

`scripts/setup_windows.ps1` 在新 Windows 环境初始化时应用这些补丁，把上游依赖改造成 FuzzWahahah 需要的形态。

## 内容

- **fuzzillai/**（Fuzzilli fork 的定制文件完整副本，覆盖到 `vendor/fuzzillai` 对应位置）：
  - `Package.swift`：摘除 postgres-nio/postgres-kit（swift-nio-ssl 不支持 Windows；postgres 同步属 FoG/EBG，本架构用 fuzzcore MCP 替代）
  - `Sources/Fuzzilli/Database/{DatabasePool,PostgresSQLStorage}.swift`、`Sources/Fuzzilli/Modules/PostgreSQLSync.swift`：`#if !os(Windows)` 包裹（保留上游兼容）
  - `Sources/FuzzilliCli/main.swift`：postgres 参数段条件编译
  - `Sources/libreprl/libreprl-windows.c`：REPRL Windows 实现修复（CreatePipe 逻辑、hChild 初始化、环境块、commandline 拼接、WaitForSingleObject→PeekNamedPipe、通道映射）
  - `Sources/Fuzzilli/Base/Logging.swift`：fatal 消息直通 stderr（Windows stdout 缓冲丢失防护）

- **winafl/winafl_fuzzwahahah.patch**（WinAFL 的 git diff）：
  - `winafl.c`：onexception 崩溃详情增强、instrument_bb_coverage 的 movabs x64 高位地址修复、DR 11.91 废弃 API（drmgr_register_exit_event）
  - `afl-fuzz.c`：崩溃管道详情打印
  - `CMakeLists.txt`：msvcrt.lib + winafl_tinyinst /MD（TinyInst 链接修复）

- **postgres-nio/PoolStateMachine.swift**：postgres-nio 的 Windows 兼容副本（CRT import + Int64 推断修正）。备用——postgres 已摘除时不需要。

## 为什么用完整副本而非 diff

fuzzillai 不是 git 仓库（zip 下载），无法 git diff。完整副本直接覆盖，幂等且与固化版本严格一致。winafl 是 git 仓库，用标准 patch。

上游更新时这些补丁需要重新对齐——它们是 FuzzWahahah 对上游的定制层。
