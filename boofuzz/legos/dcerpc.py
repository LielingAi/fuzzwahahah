# MSRPC NDR TYPES
"""
Microsoft RPC Network Data Representation (NDR) types for fuzzing.

This module provides optimized implementations of NDR string types used in MSRPC
for protocol fuzzing. The classes represent NDR data structures and handle proper
encoding, padding, and length prefixing according to NDR specifications.
"""
import struct
from typing import Optional, Dict, Any

from .. import blocks, exception, helpers, primitives
from ..helpers import calculate_four_byte_padding


# 模糊测试客户端如何处理 MSRPC NDR 字符串提供了基础结构，通过定义特定的渲染格式来模拟真实的 NDR 字符串数据。


class _BaseNdrType(blocks.Block):
    """Base class for NDR types to reduce code duplication and ensure consistency."""

    def __init__(self, name: str, request, value: str, options: Optional[Dict[str, Any]] = None):
        if options is None:
            options = {}

        super(_BaseNdrType, self).__init__(name, request)

        self.value = value
        self.options = options

        if not self.value:
            raise exception.SullyRuntimeError(f"MISSING LEGO.{self.__class__.__name__.lower()} DEFAULT VALUE")

    def _handle_empty_string(self) -> bytes:
        """Handle empty string rendering consistently across all NDR types."""
        return b"\x00\x00\x00\x00"

    def _pack_length_fields(self, length: int) -> bytes:
        """Pack length fields for NDR string types."""
        return struct.pack("<LLL", length, 0, length)

class NdrConformantArray(_BaseNdrType):
    """
    Note: this is not for fuzzing the RPC protocol but rather just representing an NDR string for fuzzing the actual
    client.
    表示一个 NDR conforment 数组，即长度前缀的字符串。
    """

    def __init__(self, name: str, request, value: str, options: Optional[Dict[str, Any]] = None):
        super(NdrConformantArray, self).__init__(name, request, value, options)

        if not name:
            raise exception.SullyRuntimeError("MISSING LEGO.ndr_conformant_array NAME")

        self.push(primitives.String())

    def render(self, mutation_context=None):
        """
        We overload and extend the render routine in order to properly pad and prefix the string.

        [dword length][array][pad]
        重载了渲染方法，用于在字符串前添加长度前缀和必要的填充。
        """

        # let the parent do the initial render.
        blocks.Block.render(self)

        # encode the empty string correctly:
        if self._rendered == b"":
            self._rendered = self._handle_empty_string()
        else:
            # Calculate padding once and reuse
            padding = calculate_four_byte_padding(self._rendered)
            length_header = struct.pack("<L", len(self._rendered))
            self._rendered = length_header + self._rendered + padding

        return helpers.str_to_bytes(self._rendered)


class NdrString(_BaseNdrType):
    """
    Note: this is not for fuzzing the RPC protocol but rather just representing an NDR string for fuzzing the actual
    client.
    表示一个 NDR 字符串。
    """

    def __init__(self, name: str, request, value: str, options: Optional[Dict[str, Any]] = None):
        super(NdrString, self).__init__(name, request, value, options)

        if not name:
            raise exception.SullyRuntimeError("MISSING LEGO.ndr_string NAME")

        self.push(primitives.String(name=name + "_STR", default_value=""))

    def render(self, mutation_context=None):
        """
        We overload and extend the render routine in order to properly pad and prefix the string.

        [dword length][dword offset][dword passed size][string][pad]
        重载了渲染方法，用于在字符串前添加长度、偏移和传递大小前缀，并确保字符串以 null 结尾。
        """

        # let the parent do the initial render.
        blocks.Block.render(self)

        # encode the empty string correctly:
        if self._rendered == b"":
            self._rendered = self._handle_empty_string()
        else:
            # ensure null termination.
            self._rendered += b"\x00"

            # format accordingly.
            length = len(self._rendered)
            length_fields = self._pack_length_fields(length)
            padding = calculate_four_byte_padding(self._rendered)
            self._rendered = length_fields + self._rendered + padding

        return helpers.str_to_bytes(self._rendered)


class NdrWString(_BaseNdrType):
    """
    Note: this is not for fuzzing the RPC protocol but rather just representing an NDR string for fuzzing the actual
    client.
    表示一个 NDR 宽字符串（UTF-16 编码）。
    """

    def __init__(self, name: str, request, value: str, options: Optional[Dict[str, Any]] = None):
        super(NdrWString, self).__init__(name, request, value, options)

        if not name:
            raise exception.SullyRuntimeError("MISSING LEGO.ndr_wstring NAME")

        self.push(primitives.String())

    def render(self, mutation_context=None):
        """
        We overload and extend the render routine in order to properly pad and prefix the string.

        [dword length][dword offset][dword passed size][string][pad]
        重载了渲染方法，用于在宽字符串前添加长度、偏移和传递大小前缀，并确保字符串以 null 结尾。
        """

        # let the parent do the initial render.
        blocks.Block.render(self)

        # encode the empty string correctly:
        if self._rendered == b"":
            self._rendered = self._handle_empty_string()
        else:
            try:
                # unicode encode and null terminate.
                self._rendered = self._rendered.encode("utf-16le") + b"\x00"
            except UnicodeEncodeError as e:
                # Handle encoding errors gracefully
                raise exception.SullyRuntimeError(f"Failed to encode string as UTF-16LE: {e}")

            # format accordingly.
            length = len(self._rendered)
            length_fields = self._pack_length_fields(length)
            padding = calculate_four_byte_padding(self._rendered)
            self._rendered = length_fields + self._rendered + padding

        return helpers.str_to_bytes(self._rendered)
