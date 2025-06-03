# 🚀 FuzzWahahah - AI-Driven Protocol Fuzzing Platform

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Boofuzz](https://img.shields.io/badge/Based%20on-Boofuzz-orange.svg)](https://github.com/jtpereyda/boofuzz)

**FuzzWahahah** 是一个基于 [Boofuzz](https://github.com/jtpereyda/boofuzz) 的下一代智能协议模糊测试平台，集成了AI驱动的测试策略、符号执行引擎和可视化监控界面。

## ✨ 核心特性

### 🤖 AI驱动的智能模糊测试
- **智能变异生成**: 基于机器学习的自适应变异策略
- **自适应测试策略**: AI实时分析测试结果并优化测试路径
- **崩溃模式分析**: 自动识别和分类崩溃模式
- **持久化学习**: 跨会话保存和应用学习数据

### 🔬 符号执行集成
- **路径约束分析**: 基于符号执行的精确测试用例生成
- **协议感知生成**: 针对特定协议的智能数据生成
- **约束求解**: 自动生成满足复杂约束条件的测试数据
- **统一框架**: 简化的符号执行API，易于集成

### 🌐 可视化Web界面
- **实时监控**: 测试进度、崩溃统计、性能指标实时展示
- **交互式配置**: 通过Web界面配置测试参数
- **结果分析**: 详细的测试结果分析和可视化
- **性能优化**: 缓存机制和异步处理提升界面响应速度

### 🎯 多协议支持
支持13+种网络协议的模糊测试：
- **Web协议**: HTTP, HTTP/2
- **数据库**: MySQL, MSSQL, Redis
- **网络服务**: FTP, SMTP, SSH, Telnet, DNS
- **IoT协议**: MQTT, Echo
- **远程桌面**: RDP

### 🛠️ 零配置使用
- **自动协议识别**: 智能检测目标服务协议类型
- **模板化配置**: 预置协议模板，快速开始测试
- **智能生成器**: 基于配置自动生成模糊测试脚本

## 📁 项目结构

```
fuzzwahahah/
├── boofuzz/                    # 增强的Boofuzz核心库
│   ├── primitives/            # 智能化的原语组件
│   │   ├── smart_string.py    # AI增强的字符串生成器
│   │   ├── random_data.py     # 优化的随机数据生成器
│   │   └── optimized_numeric.py # 优化的数值生成器
│   ├── utils/                 # 工具模块
│   │   ├── enhanced_symbolic_execution.py # 符号执行引擎
│   │   └── symbolic_execution.py # 基础符号执行
│   ├── sessions/              # 会话管理
│   │   └── session.py         # AI增强的会话管理
│   └── web/                   # Web界面
│       └── app.py             # 优化的Web应用
├── protocol_templates/         # 协议模板库
│   ├── http.json              # HTTP协议模板
│   ├── mqtt.json              # MQTT协议模板
│   ├── mysql.json             # MySQL协议模板
│   └── ...                    # 其他协议模板
├── protocol_configs/           # 协议配置文件
│   ├── mqtt_config.yaml       # MQTT配置示例
│   ├── echo_config.yaml       # Echo配置示例
│   └── ...                    # 其他配置文件
├── ai_learning_data/          # AI学习数据
│   └── global_learning_data.json # 全局学习数据
├── boofuzz_*_fuzzer.py        # 协议特定的模糊测试器
├── protocol_fuzzer_generator.py # 智能模糊测试器生成器
└── process_monitor.py         # 进程监控工具
```

## 🚀 快速开始

### 环境要求
- Python 3.8+
- 依赖包：见 `requirements.txt`

### 安装
```bash
git clone https://github.com/your-repo/fuzzwahahah.git
cd fuzzwahahah
pip install -r requirements.txt
```

### 基础使用

#### 1. 使用预置协议模糊测试器
```bash
# HTTP协议模糊测试
python boofuzz_http_fuzzer.py 192.168.1.100 80 --web-port 26000

# MQTT协议模糊测试
python boofuzz_mqtt_fuzzer.py 192.168.1.100 1883 --web-port 26001

# MySQL协议模糊测试
python boofuzz_mysql_fuzzer.py 192.168.1.100 3306 --web-port 26002
```

#### 2. 生成自定义协议模糊测试器
```bash
# 查看支持的协议
python protocol_fuzzer_generator.py --list-templates

# 创建配置模板
python protocol_fuzzer_generator.py --create-sample mqtt

# 生成模糊测试器
python protocol_fuzzer_generator.py --config mqtt_config.yaml --symbolic protocol_templates/mqtt.json
```

#### 3. Web界面监控
访问 `http://localhost:26000` 查看实时测试状态、结果分析和性能指标。

## 🧠 AI增强功能

### 智能变异策略
```python
# AI自适应策略在会话中自动启用
session.ai_strategy_enabled = True
session.ai_decision_threshold = 0.15  # 决策阈值
session.ai_adaptation_interval = 50   # 适应间隔
```

### 符号执行集成
```python
from boofuzz.utils.enhanced_symbolic_execution import generate_protocol_data

# 生成协议特定的测试数据
test_data = generate_protocol_data("http", "paths", count=100, use_ai=True)
```

### 学习数据管理
- 自动保存测试结果和有效变异模式
- 跨会话持久化学习数据
- 基于历史数据优化测试策略

## 📊 监控与分析

### Web界面功能
- **实时仪表板**: 测试进度、成功率、崩溃统计
- **详细日志**: 完整的测试日志和错误信息
- **性能监控**: CPU、内存使用情况和响应时间
- **结果导出**: 支持多种格式的结果导出

### API端点
- `/api/current-test-case`: 当前测试用例信息
- `/api/stats`: 测试统计数据
- `/api/optimization-stats`: 优化统计信息
- `/api/performance-metrics`: 性能指标

## 🔧 高级配置

### 协议配置文件示例
```yaml
protocol:
  name: "MQTT"
  port: 1883
  transport: "tcp"
  is_text_protocol: false
  dangerous: false

description: "MQTT Protocol Fuzzer with AI Enhancement"
web_port: 26000

symbolic_data:
  topics:
    type: "topics"
    count: 50
  messages:
    type: "messages"
    count: 100

requests:
  - name: "MQTT Connect"
    id: "MQTT_CONNECT"
    fields:
      - type: "bytes"
        value: "\\x10\\x0e\\x00\\x04MQTT\\x04\\x02\\x00\\x3c\\x00\\x04test"
```

### 自定义AI策略
```python
# 自定义决策阈值和适应参数
session.ai_decision_threshold = 0.1    # 更激进的策略
session.ai_adaptation_interval = 25    # 更频繁的适应
```

## 🛡️ 安全注意事项

⚠️ **重要警告**:
- 本工具仅用于授权的安全测试
- 对生产环境进行测试前请确保有适当的授权
- 某些协议的模糊测试可能导致服务中断
- 建议在隔离的测试环境中使用

## 🤝 贡献指南

1. Fork 项目
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

## 📄 许可证

本项目基于 MIT 许可证开源 - 查看 [LICENSE](LICENSE) 文件了解详情。

## 🙏 致谢

- [Boofuzz](https://github.com/jtpereyda/boofuzz) - 优秀的模糊测试框架
- 所有贡献者和测试人员

## 📞 联系方式

- 项目主页: [GitHub Repository](https://github.com/J0hnFFFF/fuzzwahahah)
- 问题反馈: [Issues](https://github.com/J0hnFFFF/fuzzwahahah/issues)
- 文档: [Wiki](https://github.com/J0hnFFFF/fuzzwahahah/wiki)

---

**让模糊测试更智能，让安全测试更高效！** 🎯