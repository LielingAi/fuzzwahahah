#Requires -Version 5.1
<#
.SYNOPSIS
  FuzzWahahah Windows 环境初始化脚本（仅 Windows，不考虑 Linux）。

.DESCRIPTION
  在新的 Windows 环境一键搭建 FuzzWahahah 完整工具链：
    1. 前置检查（C: 盘空间 / VS Build Tools / LLVM / node / 7zip / git / cmake）
    2. winget 安装缺失工具（Swift.Toolchain）
    3. 环境配置（开发者模式 symlink / SwiftPM 镜像）
    4. fuzzillai 构建（clone + patch 固化 + swift build + DLL 归位）
    5. QuickJS 编译（vendor/quickjs + clang-cl + trace-pc-guard）
    6. （可选）WinAFL TinyInst 构建
    7. 验证（FuzzilliCli / qjs_fuzzilli / fuzzcore demo）

.PARAMETER SkipWinAFL
  跳过 WinAFL TinyInst 大构建（文件格式黑盒路径，可选）。

.PARAMETER Mirror
  GitHub 镜像前缀（默认 https://ghfast.top/）。直连可用时传空字符串。

.PARAMETER FuzzillaiDir
  fuzzillai 仓库位置（默认 ..\fuzzillai，相对 fuzzwahahah 根目录）。

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\setup_windows.ps1
  powershell -ExecutionPolicy Bypass -File scripts\setup_windows.ps1 -SkipWinAFL
#>
param(
    [switch]$SkipWinAFL,
    [string]$Mirror = "https://ghfast.top/",
    [string]$FuzzillaiDir = ""
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# ---- 路径 ----
$Root = (Resolve-Path "$PSScriptRoot\..").Path          # fuzzwahahah 根目录
if (-not $FuzzillaiDir) { $FuzzillaiDir = Join-Path $Root "vendor\fuzzillai" }
$Patches = Join-Path $Root "patches"
$QuickJSDir = Join-Path $Root "vendor\quickjs"

function Log($msg)  { Write-Host "[setup] $msg" -ForegroundColor Cyan }
function Ok($msg)   { Write-Host "[  OK ] $msg" -ForegroundColor Green }
function Warn($msg) { Write-Host "[ warn] $msg" -ForegroundColor Yellow }
function Die($msg)  { Write-Host "[FAIL ] $msg" -ForegroundColor Red; exit 1 }

function Have($cmd) { return $null -ne (Get-Command $cmd -ErrorAction SilentlyContinue) }

# ============================================================
# 1. 前置检查
# ============================================================
Log "=== 1/7 前置检查 ==="

# C: 盘空间（Swift SDK + 构建需 ~5GB）
$cFree = (Get-PSDrive C).Free / 1GB
if ($cFree -lt 8) {
    Warn "C: 盘剩余空间 ${cFree}GB (<8GB)。Swift 安装曾因磁盘不足失败 (1603)。"
    Warn "建议先清理 `$env:LOCALAPPDATA\Temp（本环境的 wsl-crashes 曾占 8.2GB）。"
} else { Ok "C: 盘空间 ${cFree}GB" }

# VS Build Tools（vcvarsall）
$vcvars = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"
if (-not (Test-Path $vcvars)) {
    $vcvars = Get-ChildItem "C:\Program Files\Microsoft Visual Studio\2022\*\VC\Auxiliary\Build\vcvarsall.bat" -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
}
if (-not $vcvars -or -not (Test-Path $vcvars)) {
    Die "未找到 VS 2022 (vcvarsall.bat)。请先安装 Visual Studio 2022 (含 C++ 工作负载) 或 Build Tools。"
}
Ok "VS 2022: $vcvars"

# LLVM clang-cl
$clangcl = "C:\Program Files\LLVM\bin\clang-cl.exe"
if (-not (Test-Path $clangcl)) {
    Warn "未找到 LLVM clang-cl ($clangcl)，尝试 winget 安装 LLVM..."
    if (Have "winget") { winget install --id LLVM.LLVM --silent --accept-source-agreements --accept-package-agreements }
    if (-not (Test-Path $clangcl)) { Die "LLVM clang-cl 安装失败。请手动安装 LLVM (https://releases.llvm.org)。" }
}
Ok "LLVM clang-cl: $clangcl"

foreach ($t in @("git", "node")) {
    if (-not (Have $t)) { Warn "未找到 $t — 部分功能受限（jsprog 验证门需要 node）。" } else { Ok "$t 可用" }
}

$sevenz = "D:\7-Zip\7z.exe"
if (-not (Test-Path $sevenz)) { $sevenz = "C:\Program Files\7-Zip\7z.exe" }
if (-not (Test-Path $sevenz)) { Warn "未找到 7-Zip（结构恢复/harness 需要）。" } else { Ok "7-Zip: $sevenz" }

# Python（fuzzcore 需要）
if (-not (Have "python")) { Die "未找到 python。fuzzcore 需要 Python 3.10+。" }
Ok "python: $((python --version) 2>&1)"

# ============================================================
# 2. Swift 安装
# ============================================================
Log "=== 2/7 Swift 工具链 ==="
$swiftExe = "$env:LOCALAPPDATA\Programs\Swift\Toolchains\6.3.3+Asserts\usr\bin\swift.exe"
$swiftRtBin = "$env:LOCALAPPDATA\Programs\Swift\Runtimes\6.3.3\usr\bin"
if (-not (Test-Path $swiftExe)) {
    Log "安装 Swift 6.3.3 (winget)。注意: 若失败先看 C: 盘空间 (本环境曾因 4.5GB 失败)。"
    if (-not (Have "winget")) { Die "winget 不可用，无法自动安装 Swift。请手动安装 Swift for Windows。" }
    winget install --id Swift.Toolchain --silent --accept-source-agreements --accept-package-agreements
    if (-not (Test-Path $swiftExe)) { Die "Swift 安装失败（查 C: 盘空间 / RebootPending / 安装日志）。" }
}
Ok "swift: $swiftExe"

# Swift SDKROOT（Swift 6.3 的 SDK 独立装 Platforms/, 需显式 SDKROOT）
$sdkroot = "$env:LOCALAPPDATA\Programs\Swift\Platforms\6.3.3\Windows.platform\Developer\SDKs\Windows.sdk"
if (-not (Test-Path $sdkroot)) { Die "Swift Windows SDK 未找到 ($sdkroot)。windows.msi 未装上。" }
$env:SDKROOT = $sdkroot
Ok "SDKROOT: $sdkroot"

# ============================================================
# 3. 环境配置（开发者模式 + SwiftPM 镜像）
# ============================================================
Log "=== 3/7 环境配置 ==="

# 开发者模式（允许非 admin 创建 symlink — SwiftPM checkout 需要）
$devKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock"
$devVal = (Get-ItemProperty $devKey -Name AllowDevelopmentWithoutDevLicense -ErrorAction SilentlyContinue).AllowDevelopmentWithoutDevLicense
if ($devVal -ne 1) {
    Warn "开发者模式未开（SwiftPM checkout 需 symlink 权限）。尝试设置注册表（需 admin）..."
    try {
        Set-ItemProperty $devKey -Name AllowDevelopmentWithoutDevLicense -Value 1 -ErrorAction Stop
        Ok "开发者模式已开"
    } catch {
        Warn "无法设置开发者模式（非 admin）。请手动: 设置 → 开发者选项 → 开发者模式，或 SwiftPM checkout 会报 symlink Permission denied。"
    }
} else { Ok "开发者模式已开" }

# SwiftPM 镜像（GitHub 直连受限时）
if ($Mirror) {
    $mirrorDir = "$env:USERPROFILE\.swiftpm\configuration"
    New-Item -ItemType Directory -Force -Path $mirrorDir | Out-Null
    $mirrors = @{
        version = 1
        object  = @(
            @{ original = "https://github.com/apple/swift-protobuf.git";    mirror = "${Mirror}https://github.com/apple/swift-protobuf.git" },
            @{ original = "https://github.com/apple/swift-collections.git"; mirror = "${Mirror}https://github.com/apple/swift-collections.git" },
            @{ original = "https://github.com/vapor/postgres-nio.git";      mirror = "${Mirror}https://github.com/vapor/postgres-nio.git" },
            @{ original = "https://github.com/vapor/postgres-kit.git";      mirror = "${Mirror}https://github.com/vapor/postgres-kit.git" },
            @{ original = "https://github.com/apple/swift-crypto.git";      mirror = "${Mirror}https://github.com/apple/swift-crypto.git" }
        )
    }
    $mirrors | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $mirrorDir "mirrors.json") -Encoding UTF8
    Ok "SwiftPM 镜像: $Mirror"
}

# ============================================================
# 4. fuzzillai 构建
# ============================================================
Log "=== 4/7 fuzzillai 构建 ==="

if (-not (Test-Path $FuzzillaiDir)) {
    Log "clone fuzzillai → $FuzzillaiDir"
    $repoUrl = "https://github.com/VRIG-RITSEC/fuzzillai.git"
    if ($Mirror) { $repoUrl = "${Mirror}${repoUrl}" }
    git clone --depth 1 $repoUrl $FuzzillaiDir
    if ($LASTEXITCODE -ne 0) { Die "fuzzillai clone 失败（网络/镜像）。" }
    # IkaCore 子模块
    $ikaUrl = "https://github.com/Squid-Proxy-Lovers/IkaCore.git"
    if ($Mirror) { $ikaUrl = "${Mirror}${ikaUrl}" }
    $ikaDest = Join-Path $FuzzillaiDir "Sources\Agentic_System\IkaCore"
    if (-not (Test-Path $ikaDest)) { git clone --depth 1 $ikaUrl $ikaDest }
}
Ok "fuzzillai: $FuzzillaiDir"

# 应用固化 patch（完整文件覆盖）
Log "应用 fuzzillai patch（postgres 摘除 + libreprl-windows 修复 + Logging）..."
Copy-Item (Join-Path $Patches "fuzzillai\Package.swift") $FuzzillaiDir -Force
Copy-Item (Join-Path $Patches "fuzzillai\Sources\Fuzzilli\Database\DatabasePool.swift") (Join-Path $FuzzillaiDir "Sources\Fuzzilli\Database\") -Force
Copy-Item (Join-Path $Patches "fuzzillai\Sources\Fuzzilli\Database\PostgresSQLStorage.swift") (Join-Path $FuzzillaiDir "Sources\Fuzzilli\Database\") -Force
Copy-Item (Join-Path $Patches "fuzzillai\Sources\Fuzzilli\Modules\PostgreSQLSync.swift") (Join-Path $FuzzillaiDir "Sources\Fuzzilli\Modules\") -Force
Copy-Item (Join-Path $Patches "fuzzillai\Sources\FuzzilliCli\main.swift") (Join-Path $FuzzillaiDir "Sources\FuzzilliCli\") -Force
Copy-Item (Join-Path $Patches "fuzzillai\Sources\libreprl\libreprl-windows.c") (Join-Path $FuzzillaiDir "Sources\libreprl\") -Force
Copy-Item (Join-Path $Patches "fuzzillai\Sources\Fuzzilli\Base\Logging.swift") (Join-Path $FuzzillaiDir "Sources\Fuzzilli\Base\") -Force
Ok "patch 已应用"

# postgres-nio 的 Windows 兼容 patch（checkouts 是 SwiftPM 管理, 首次 resolve 后打）
$poolPatch = Join-Path $Patches "postgres-nio\PoolStateMachine.swift"

# swift build（VC 环境 + Swift PATH/SDKROOT）
$buildBat = Join-Path $env:TEMP "fw_swift_build.bat"
@"
@echo off
set PATH=$env:LOCALAPPDATA\Programs\Swift\Toolchains\6.3.3+Asserts\usr\bin;$swiftRtBin;%PATH%
set SDKROOT=$sdkroot
call "$vcvars" x64 >nul 2>&1
cd /d $FuzzillaiDir
swift build --skip-update 2>&1
"@ | Set-Content $buildBat -Encoding ASCII

Log "swift build fuzzillai（首次 resolve 依赖, 可能 10-20 分钟）..."
cmd /c $buildBat | Tee-Object -FilePath (Join-Path $env:TEMP "fw_swift_build.log") | Select-Object -Last 3

# postgres-nio PoolStateMachine patch（若 checkouts 存在）
$poolTarget = Get-ChildItem (Join-Path $FuzzillaiDir ".build\checkouts\postgres-nio\Sources\ConnectionPoolModule\PoolStateMachine.swift") -ErrorAction SilentlyContinue
if ($poolTarget -and (Test-Path $poolPatch)) {
    attrib -R $poolTarget.FullName
    Copy-Item $poolPatch $poolTarget.FullName -Force
    Ok "postgres-nio PoolStateMachine patch 已应用"
    Log "重新 build（应用 postgres patch 后）..."
    cmd /c $buildBat | Select-Object -Last 3
}

$fuzzilliCli = Join-Path $FuzzillaiDir ".build\debug\FuzzilliCli.exe"
if (-not (Test-Path $fuzzilliCli)) { Die "FuzzilliCli.exe 未产出。查 $env:TEMP\fw_swift_build.log。" }
Ok "FuzzilliCli.exe: $fuzzilliCli"

# Swift runtime DLL 归位（exe 同目录优先加载, 免 PATH 依赖）
Copy-Item "$swiftRtBin\*.dll" (Join-Path $FuzzillaiDir ".build\debug\") -Force -ErrorAction SilentlyContinue
Ok "Swift runtime DLL 已归位"

# ============================================================
# 5. QuickJS 编译
# ============================================================
Log "=== 5/7 QuickJS (vendor/quickjs) 编译 ==="
$qjsBat = Join-Path $env:TEMP "fw_qjs_build.bat"
@"
@echo off
call "$vcvars" x64 >nul 2>&1
cd /d $QuickJSDir
"$clangcl" /nologo /O2 -DFUZZILLI -DCONFIG_BIGNUM -DCONFIG_VERSION=\"2024-01-13\" -D_CRT_SECURE_NO_WARNINGS /I posix_shim /FI posix_shim/qjs_global.h -fsanitize-coverage=trace-pc-guard -fuse-ld=lld qjs.c quickjs.c libregexp.c libunicode.c cutils.c quickjs-libc.c libbf.c reprl_win.c repl_stub.c /link /out:qjs_fuzzilli.exe "C:\Program Files\LLVM\lib\clang\18\lib\windows\clang_rt.builtins-x86_64.lib"
"@ | Set-Content $qjsBat -Encoding ASCII
cmd /c $qjsBat | Select-Object -Last 5
$qjsExe = Join-Path $QuickJSDir "qjs_fuzzilli.exe"
if (-not (Test-Path $qjsExe)) { Die "qjs_fuzzilli.exe 未产出。" }
Ok "qjs_fuzzilli.exe: $qjsExe"

# ============================================================
# 6. （可选）WinAFL TinyInst
# ============================================================
if ($SkipWinAFL) {
    Log "=== 6/7 WinAFL TinyInst（-SkipWinAFL, 跳过） ==="
} else {
    Log "=== 6/7 WinAFL TinyInst 构建 ==="
    $winaflDir = Join-Path $Root "vendor\winafl"
    if (-not (Test-Path $winaflDir)) {
        Warn "winafl 不在 $winaflDir。文件格式黑盒路径需要 WinAFL — 请单独 clone https://github.com/googleprojectzero/winafl 并应用 patches\winafl\winafl_fuzzwahahah.patch + -DTINYINST=1 构建。"
    } else {
        Push-Location $winaflDir
        git apply (Join-Path $Patches "winafl\winafl_fuzzwahahah.patch") 2>&1 | Out-Null
        # TinyInst 子模块（镜像）
        if (-not (Test-Path "third_party\TinyInst\CMakeLists.txt")) {
            $tiZip = Join-Path $env:TEMP "tinyinst.zip"
            Invoke-WebRequest "${Mirror}https://github.com/googleprojectzero/TinyInst/archive/refs/heads/master.zip" -OutFile $tiZip
            Expand-Archive $tiZip -DestinationPath third_party -Force
            Move-Item third_party\TinyInst-master third_party\TinyInst -Force
            foreach ($sub in @("xed", "mbuild")) {
                $subZip = Join-Path $env:TEMP "$sub.zip"
                Invoke-WebRequest "${Mirror}https://github.com/intelxed/$sub/archive/refs/heads/main.zip" -OutFile $subZip
                Expand-Archive $subZip -DestinationPath third_party\TinyInst\third_party -Force
                Move-Item "third_party\TinyInst\third_party\$sub-main" "third_party\TinyInst\third_party\$sub" -Force
            }
        }
        # xed GBK 警告 + /MD
        $xedCmake = "third_party\TinyInst\third_party\CMakeLists.txt"
        $xedContent = Get-Content $xedCmake -Raw
        if ($xedContent -notmatch "wd4819") {
            $xedContent = $xedContent -replace '(mfile\.py \$\{XED_HOST_CPU\})', "`$1`n     --extra-flags=/wd4819`n     --extra-flags=/MD"
            Set-Content $xedCmake $xedContent -NoNewline
        }
        $cmake = "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
        New-Item -ItemType Directory -Force -Path build64_tinyinst | Out-Null
        Push-Location build64_tinyinst
        & $cmake -G "Visual Studio 17 2022" -A x64 -DTINYINST=1 .. | Select-Object -Last 2
        & $cmake --build . --config Release --target afl-showmap afl-fuzz test 2>&1 | Select-Object -Last 3
        Pop-Location
        Pop-Location
        if (Test-Path (Join-Path $winaflDir "build64_tinyinst\bin\Release\afl-fuzz.exe")) { Ok "WinAFL TinyInst: afl-fuzz.exe" }
        else { Warn "WinAFL TinyInst 构建未产出 afl-fuzz.exe（非致命）。" }
    }
}

# ============================================================
# 7. 验证
# ============================================================
Log "=== 7/7 验证 ==="
& $fuzzilliCli --help 2>&1 | Select-Object -First 2 | Out-Null
if ($LASTEXITCODE -eq 0) { Ok "FuzzilliCli --help" } else { Warn "FuzzilliCli --help 异常" }
& $qjsExe -e "print(1+1)" 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) { Ok "qjs_fuzzilli -e" } else { Warn "qjs_fuzzilli -e 异常" }

Push-Location $Root
try {
    python fuzzcore\mcp_demo.py 2>&1 | Select-Object -Last 2
} catch {
    Warn "fuzzcore mcp_demo 验证异常（非致命）: $_"
}
Pop-Location

Write-Host ""
Ok "=== FuzzWahahah Windows 环境初始化完成 ==="
Write-Host "  FuzzilliCli:  $fuzzilliCli"
Write-Host "  qjs_fuzzilli: $qjsExe"
Write-Host "  浏览器路径:   FuzzilliCli --profile=qjs <qjs_fuzzilli.exe>"
Write-Host "  文件格式路径: fuzzcore WinAFLFileEngine (mode=tinyinst) / LibFuzzerFileEngine"
Write-Host "  协议路径:     fuzzcore ProtocolEngine + boofuzz_*_fuzzer.py"
