"""VerificationGate - 验证种子是否结构合法（ARCHITECTURE.md §5.1 验证门）。

拦掉坏种子：magic 不匹配、checksum 错误、length 不一致的种子在进入语料前被拒绝。
"""
from __future__ import annotations

from .ir import Grammar
from .seed_synthesis import SeedSynthesis, crc32


class VerificationGate:
    def __init__(self, grammar: Grammar):
        self.grammar = grammar
        self.synthesis = SeedSynthesis(grammar)

    def validate(self, seed: bytes) -> bool:
        """结构验证：magic 匹配 + checksum 正确 + length 一致。"""
        try:
            parsed = self.synthesis.parse(seed)
        except Exception:
            return False

        try:
            for f in self.grammar.fields:
                if f.type == "magic":
                    if parsed.get(f.name) != bytes.fromhex(f.value):
                        return False
                elif f.type == "checksum":
                    data = b"".join(parsed.get(n, b"") for n in f.over)
                    expect = int.from_bytes(parsed[f.name], f.endian)
                    if self._checksum(f.algorithm, data) != expect:
                        return False
                elif f.type == "length" and f.length_of:
                    expect = len(parsed.get(f.length_of, b""))
                    if int.from_bytes(parsed[f.name], f.endian) != expect:
                        return False
        except (ValueError, TypeError, KeyError):
            # magic 值非法 hex / 字段缺失 / 字节序非法 -> 坏种子
            return False
        return True

    # ---- 协议会话验证（kind=protocol, Grammar.states）----

    def validate_session(self, session: list[bytes]) -> bool:
        """协议会话验证：非空 + 从 initial 状态沿合法转移展开 +
        每个请求匹配所在状态的静态字段前缀（magic/raw）。"""
        states = self.grammar.states
        if not states or not session:
            return False
        current = next((s for s in states if s.initial), states[0])
        for i, request in enumerate(session):
            if not self._match_state_request(current, request):
                return False
            if i < len(session) - 1:
                nexts = [self.grammar.state(t) for t in current.transitions]
                nexts = [s for s in nexts
                         if s is not None and self._match_state_request(s, session[i + 1])]
                if not nexts:
                    return False
                current = nexts[0]
        return True

    def _match_state_request(self, state, request: bytes) -> bool:
        """请求与状态的静态字段前缀匹配：magic/raw 字段按序占据请求开头。"""
        pos = 0
        for f in state.request:
            if f.type in ("magic", "raw") and (f.value or f.default):
                expected = bytes.fromhex(f.value or f.default)
                if request[pos:pos + len(expected)] != expected:
                    return False
                pos += len(expected)
            elif f.type in ("blob", "uint", "length", "checksum"):
                break  # 变长内容, 静态匹配到此为止
        return True

    @staticmethod
    def _checksum(algorithm: str, data: bytes) -> int:
        if algorithm == "crc32":
            return crc32(data)
        raise ValueError(f"unsupported checksum algorithm: {algorithm}")
