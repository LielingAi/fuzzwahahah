"""SeedSynthesis - 从 Grammar 合成合法种子 + 保结构变异（ARCHITECTURE.md §5.1）。"""
from __future__ import annotations

import random
import zlib
from typing import Optional

from .ir import Field, Grammar


def crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


class SeedSynthesis:
    def __init__(self, grammar: Grammar):
        self.grammar = grammar

    # ---- 生成 ----

    def generate(self, overrides: Optional[dict[str, bytes]] = None) -> bytes:
        """生成一个结构合法的种子：magic 固定、checksum/length 重算。"""
        overrides = overrides or {}
        parts: dict[str, bytes] = {}

        # 1. 基础内容字段（checksum/length 稍后重算，不取 override）
        for f in self.grammar.fields:
            if f.type in ("checksum", "length"):
                continue
            if f.name in overrides:
                parts[f.name] = overrides[f.name]
            elif f.type == "magic":
                parts[f.name] = bytes.fromhex(f.value)
            elif f.type == "raw":
                parts[f.name] = (bytes.fromhex(f.default) if f.default
                                 else b"\x00" * (f.size or 0))
            elif f.type == "blob":
                parts[f.name] = (bytes.fromhex(f.default) if f.default
                                 else b"\x00" * 8)
            elif f.type == "uint":
                parts[f.name] = (0).to_bytes(f.size or 4, f.endian)

        # 2. 依赖字段：length / checksum
        self._resolve_dependent(self.grammar.fields, parts)

        return self._assemble(parts)

    # ---- 协议会话（kind=protocol, Grammar.states）----

    def generate_session(self, max_steps: int = 8) -> list[bytes]:
        """合成一个协议会话序列：从 initial 状态沿 state_machine 走一条路径,
        每个状态合成一个请求（字段级合成, 与 generate 同套规则）。"""
        states = self.grammar.states
        if not states:
            return []
        current = next((s for s in states if s.initial), states[0])
        session: list[bytes] = []
        visited: set[str] = set()
        for _ in range(max_steps):
            session.append(self._render_fields(current.request, {}))
            visited.add(current.name)
            if not current.transitions:
                break
            nexts = [self.grammar.state(t) for t in current.transitions]
            nexts = [s for s in nexts if s is not None]
            unvisited = [s for s in nexts if s.name not in visited]
            pool = unvisited or nexts
            if not pool:
                break
            current = random.choice(pool)
        return session

    def _render_fields(self, fields: list[Field],
                       overrides: dict[str, bytes]) -> bytes:
        """按字段列表渲染字节（generate 的核心, 会话请求复用）。"""
        parts: dict[str, bytes] = {}
        for f in fields:
            if f.type in ("checksum", "length"):
                continue
            if f.name in overrides:
                parts[f.name] = overrides[f.name]
            elif f.type == "magic":
                parts[f.name] = bytes.fromhex(f.value)
            elif f.type == "raw":
                parts[f.name] = (bytes.fromhex(f.default) if f.default
                                 else b"\x00" * (f.size or 0))
            elif f.type == "blob":
                parts[f.name] = (bytes.fromhex(f.default) if f.default
                                 else b"\x00" * 8)
            elif f.type == "uint":
                parts[f.name] = (0).to_bytes(f.size or 4, f.endian)
        self._resolve_dependent(fields, parts)
        return self._assemble(parts, fields)

    def _resolve_dependent(self, fields: list[Field], parts: dict[str, bytes]) -> None:
        """第二遍: 重算 length / checksum 依赖字段。"""
        for f in fields:
            if f.type == "length" and f.length_of and f.length_of in parts:
                parts[f.name] = len(parts[f.length_of]).to_bytes(f.size or 4, f.endian)
            elif f.type == "checksum":
                data = b"".join(parts[n] for n in f.over if n in parts)
                parts[f.name] = self._checksum(f.algorithm, data).to_bytes(f.size or 4, f.endian)

    # ---- 变异 ----

    def mutate(self, seed: bytes, keep_structure: bool = True) -> bytes:
        """变异种子。keep_structure=True 时只改内容字段并重算 checksum/length。"""
        parsed = self.parse(seed)
        mutable = [f for f in self.grammar.fields if f.type in ("blob", "raw")]
        if not mutable:
            return seed

        target = random.choice(mutable)
        content = bytearray(parsed.get(target.name, b""))
        if not content:
            content = bytearray(b"\x00")
        i = random.randrange(len(content))
        content[i] ^= random.randint(1, 255)

        if keep_structure:
            return self.generate({**parsed, target.name: bytes(content)})
        # 不保结构：直接改字节，不重算校验和
        return self._assemble({**parsed, target.name: bytes(content)})

    # ---- 解析 / 组装 ----

    def parse(self, seed: bytes) -> dict[str, bytes]:
        """把种子按 grammar 拆成字段。变长 blob 取到末尾。"""
        result: dict[str, bytes] = {}
        pos = 0
        for f in self.grammar.ordered_fields():
            if f.type == "blob":
                result[f.name] = seed[pos:]
                break
            size = f.size or 0
            result[f.name] = seed[pos:pos + size]
            pos += size
        return result

    def _assemble(self, parts: dict[str, bytes],
                  fields: Optional[list[Field]] = None) -> bytes:
        ordered = [f for f in (fields or self.grammar.ordered_fields()) if f.name in parts]
        # blob 必须排在最后（变长），其余按 offset
        fixed = [f for f in ordered if f.type != "blob"]
        blobs = [f for f in ordered if f.type == "blob"]
        return b"".join(parts[f.name] for f in fixed + blobs)

    # ---- 工具 ----

    def _checksum(self, algorithm: str, data: bytes) -> int:
        if algorithm == "crc32":
            return crc32(data)
        raise ValueError(f"unsupported checksum algorithm: {algorithm}")
