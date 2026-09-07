"""Grammar IR - 输入格式结构描述（ARCHITECTURE.md §4）。

统一描述格式：字段、类型、长度、校验和、嵌套容器、协议会话状态机。
是结构恢复(StructureRecovery)的产出、种子合成(SeedSynthesis)的输入。
Phase 2 落地字段级子集（magic/checksum/length/blob/raw/uint），
架构 v2 战线 3 落地 ProtocolState（kind=protocol 的会话状态机）；
container 嵌套留待后续扩展。
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Optional

# Grammar 字段类型白名单（严格校验：未知 type 会导致 SeedSynthesis/VerificationGate
# 静默跳过该字段, 产出残缺种子且验证门误判通过 —— 必须在注册期拒绝）
FIELD_TYPES = ("magic", "checksum", "length", "blob", "raw", "uint")

_FIELD_TYPE_EXAMPLE = (
    "示例: {\"name\": \"magic\", \"type\": \"magic\", \"offset\": 0, \"size\": 5, "
    "\"value\": \"89504e47\"}; {\"name\": \"len\", \"type\": \"length\", \"size\": 4, "
    "\"length_of\": \"blob\"}; {\"name\": \"crc\", \"type\": \"checksum\", \"size\": 4, "
    "\"algorithm\": \"crc32\", \"over\": [\"blob\"]}; {\"name\": \"blob\", \"type\": \"blob\"}"
)


def validate_field_type(type_str: str) -> None:
    """严格校验字段类型在白名单内，否则抛出带合法 type 与示例的 ValueError。"""
    if type_str not in FIELD_TYPES:
        raise ValueError(
            f"unknown field type {type_str!r}; 合法 type: "
            f"{'/'.join(FIELD_TYPES)}. {_FIELD_TYPE_EXAMPLE}"
        )


@dataclass
class Field:
    name: str
    type: str                      # magic | checksum | length | blob | raw | uint
    offset: int = 0
    size: Optional[int] = None     # 固定大小（magic/raw/uint/checksum/length）
    endian: str = "little"         # uint/length/checksum 的字节序
    value: str = ""                # magic 的固定值（hex）
    algorithm: str = ""            # checksum 算法：crc32
    over: list[str] = field(default_factory=list)  # checksum 覆盖的字段名（按序）
    length_of: Optional[str] = None  # length 字段引用的 blob 字段名
    default: str = ""              # raw/blob 的默认内容（hex）

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Field":
        f = cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})
        validate_field_type(f.type)
        return f


@dataclass
class ProtocolState:
    """协议会话状态（kind=protocol 的 Grammar 使用）。

    name:        状态名（如 "login" / "command"）
    request:     该状态发出的请求字段（复用 Field 表达）
    transitions: 允许的后继状态名（空列表 = 终态）
    initial:     是否为会话初始状态
    """
    name: str
    request: list[Field] = field(default_factory=list)
    transitions: list[str] = field(default_factory=list)
    initial: bool = False

    def to_dict(self) -> dict:
        return {"name": self.name,
                "request": [f.to_dict() for f in self.request],
                "transitions": list(self.transitions),
                "initial": self.initial}

    @classmethod
    def from_dict(cls, d: dict) -> "ProtocolState":
        return cls(name=d["name"],
                   request=[Field.from_dict(f) for f in d.get("request", [])],
                   transitions=list(d.get("transitions", [])),
                   initial=bool(d.get("initial", False)))


@dataclass
class Grammar:
    name: str
    kind: str = "binary_file"       # binary_file | protocol | dom
    fields: list[Field] = field(default_factory=list)
    states: list[ProtocolState] = field(default_factory=list)  # kind=protocol 的会话状态机

    def field(self, name: str) -> Optional[Field]:
        for f in self.fields:
            if f.name == name:
                return f
        return None

    def state(self, name: str) -> Optional[ProtocolState]:
        for s in self.states:
            if s.name == name:
                return s
        return None

    def ordered_fields(self) -> list[Field]:
        return sorted(self.fields, key=lambda f: f.offset)

    def to_dict(self) -> dict:
        return {"name": self.name, "kind": self.kind,
                "fields": [f.to_dict() for f in self.fields],
                "states": [s.to_dict() for s in self.states]}

    @classmethod
    def from_dict(cls, d: dict) -> "Grammar":
        return cls(name=d["name"], kind=d.get("kind", "binary_file"),
                   fields=[Field.from_dict(f) for f in d.get("fields", [])],
                   states=[ProtocolState.from_dict(s) for s in d.get("states", [])])


@dataclass
class Grammar:
    name: str
    kind: str = "binary_file"       # binary_file | protocol | dom
    fields: list[Field] = field(default_factory=list)
    states: list["ProtocolState"] = field(default_factory=list)  # kind=protocol 时的会话状态机

    def field(self, name: str) -> Optional[Field]:
        for f in self.fields:
            if f.name == name:
                return f
        return None

    def state(self, name: str) -> Optional["ProtocolState"]:
        for s in self.states:
            if s.name == name:
                return s
        return None

    def ordered_fields(self) -> list[Field]:
        return sorted(self.fields, key=lambda f: f.offset)

    def to_dict(self) -> dict:
        return {"name": self.name, "kind": self.kind,
                "fields": [f.to_dict() for f in self.fields],
                "states": [s.to_dict() for s in self.states]}

    @classmethod
    def from_dict(cls, d: dict) -> "Grammar":
        return cls(name=d["name"], kind=d.get("kind", "binary_file"),
                   fields=[Field.from_dict(f) for f in d.get("fields", [])],
                   states=[ProtocolState.from_dict(s) for s in d.get("states", [])])


@dataclass
class ProtocolState:
    """协议会话状态（kind=protocol 的 Grammar 使用）。

    name:        状态名（如 "login" / "command"）
    request:     该状态发出的请求字段（复用 Field 表达, blob/raw/string 文本内容）
    transitions: 允许的后继状态名（空列表 = 终态）
    initial:     是否为会话初始状态
    """
    name: str
    request: list[Field] = field(default_factory=list)
    transitions: list[str] = field(default_factory=list)
    initial: bool = False

    def to_dict(self) -> dict:
        return {"name": self.name,
                "request": [f.to_dict() for f in self.request],
                "transitions": list(self.transitions),
                "initial": self.initial}

    @classmethod
    def from_dict(cls, d: dict) -> "ProtocolState":
        return cls(name=d["name"],
                   request=[Field.from_dict(f) for f in d.get("request", [])],
                   transitions=list(d.get("transitions", [])),
                   initial=bool(d.get("initial", False)))
