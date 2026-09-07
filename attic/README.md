# attic/

已隔离的危险文件——仅供研究，不可作为正常工具使用：

- `test.py` — pickle RCE payload 生成器
- `redis_client_fuzzer.py` / `redis_client_fuzzer2.py` / `redis_mock.py` — 内嵌 XSS + pickle RCE 的恶意 Redis 客户端 mock

来源：早期实验代码。隔离原因：内含攻击性 payload 生成逻辑，与项目正规的 fuzzer 工具链混放有误用风险。

若要重新启用，需先去除恶意载荷再迁回根目录。
