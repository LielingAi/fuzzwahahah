import struct
from typing import Iterator

from boofuzz.primitives.bit_field import BitField
from boofuzz.primitives.optimized_numeric import OptimizedNumericBase


class DWord(BitField, OptimizedNumericBase):
    """The 4 byte sized bit field primitive.

    :type  name: str, optional
    :param name: Name, for referencing later. Names should always be provided, but if not, a default name will be given,
        defaults to None
    :type  default_value: int, optional
    :param default_value: Default integer value, defaults to 0
    :type  max_num: int, optional
    :param max_num: Maximum number to iterate up to, defaults to None
    :type  endian: char, optional
    :param endian: Endianness of the bit field (LITTLE_ENDIAN: <, BIG_ENDIAN: >), defaults to LITTLE_ENDIAN
    :type  output_format: str, optional
    :param output_format: Output format, "binary" or "ascii", defaults to binary
    :type  signed: bool, optional
    :param signed: Make size signed vs. unsigned (applicable only with format="ascii"), defaults to False
    :type  full_range: bool, optional
    :param full_range: If enabled the field mutates through *all* possible values, defaults to False
    :type  fuzz_values: list, optional
    :param fuzz_values: List of custom fuzz values to add to the normal mutations, defaults to None
    :type  fuzzable: bool, optional
    :param fuzzable: Enable/disable fuzzing of this primitive, defaults to true
    """

    def __init__(self, *args, **kwargs):
        # Inject our width argument
        super(DWord, self).__init__(width=32, *args, **kwargs)
        # Initialize optimization components
        OptimizedNumericBase.__init__(self, cache_size_multiplier=1.5)

    def _get_format_string(self) -> str:
        """Get struct format string for DWord."""
        return self.endian + "L"

    def _get_byte_size(self) -> int:
        """Get byte size for DWord."""
        return 4

    def _get_min_value(self) -> int:
        """Get minimum value for DWord."""
        return 0

    def _get_max_value(self) -> int:
        """Get maximum value for DWord."""
        return 0xFFFFFFFF

    def mutations(self, default_value) -> Iterator[int]:
        """Generate optimized mutations using advanced caching and deduplication."""
        # Use optimized generation if available
        if hasattr(self, '_generate_mutations_optimized'):
            for mutation in self._generate_mutations_optimized(default_value):
                yield mutation
        else:
            # Fallback to original method
            for val in super(DWord, self).mutations(default_value):
                yield val

    def encode(self, value, mutation_context):
        if not isinstance(value, (int, list, tuple)):
            value = struct.unpack(self.endian + "L", value)[0]
        return super(DWord, self).encode(value, mutation_context)
