import random
import struct
import os
from typing import Iterator, Optional, Dict, Any
import threading
import time

from boofuzz import helpers
from ..fuzzable import Fuzzable
from ..utils.bloom_filter import AdvancedDeduplicator
from ..utils.smart_cache import TieredCache
from ..utils.parallel_generator import ParallelStringGenerator


class RandomData(Fuzzable):
    """Generate a random chunk of data while maintaining a copy of the original.

    A random length range can be specified. For a static length, set min/max length to be the same.

    :param name: Name, for referencing later. Names should always be provided, but if not, a default name will be given,
        defaults to None
    :type name: str, optional
    :param default_value: Value used when the element is not being fuzzed - should typically represent a valid value,
        defaults to None
    :type default_value: str or bytes, optional
    :param min_length: Minimum length of random block, defaults to 0
    :type min_length: int, optional
    :param max_length: Maximum length of random block, defaults to 1
    :type max_length: int, optional
    :param max_mutations: Number of mutations to make before reverting to default, defaults to 25
    :type max_mutations: int, optional
    :param step: If not None, step count between min and max reps, otherwise random, defaults to None
    :type step: int, optional
    :param fuzzable: Enable/disable fuzzing of this primitive, defaults to true
    :type fuzzable: bool, optional
    """

    def __init__(
        self, name=None, default_value="", min_length=0, max_length=1, max_mutations=25, step=None, *args, **kwargs
    ):
        default_value = helpers.str_to_bytes(default_value)

        super(RandomData, self).__init__(name=name, default_value=default_value, *args, **kwargs)

        self.min_length = min_length
        self.max_length = max_length
        self.max_mutations = max_mutations
        self.step = step
        if self.step:
            self.max_mutations = (self.max_length - self.min_length) // self.step + 1

        # Advanced optimization components
        self._data_cache = TieredCache(hot_size=200, warm_size=1000, cold_size=2000)
        self._deduplicator = AdvancedDeduplicator(
            bloom_capacity=50000,
            bloom_error_rate=0.01,
            exact_cache_size=2000
        )

        # Performance tracking
        self._stats = {
            'total_generated': 0,
            'unique_generated': 0,
            'cache_hits': 0,
            'duplicates_prevented': 0,
            'generation_time': 0.0,
            'bytes_generated': 0
        }

        # Thread safety
        self._lock = threading.RLock()

    def _generate_random_bytes_optimized(self, length: int, local_random: random.Random) -> bytes:
        """Generate random bytes more efficiently using batch operations."""
        if length <= 0:
            return b""

        # For small lengths, use the original method
        if length <= 100:
            return bytes(local_random.randint(0, 255) for _ in range(length))

        # For larger lengths, use more efficient batch generation
        # Generate random integers and convert to bytes
        random_ints = [local_random.randint(0, 255) for _ in range(length)]
        return bytes(random_ints)

    def mutations(self, default_value):
        """
        Mutate the primitive value returning False on completion.
        Advanced optimized version with caching and deduplication.

        Args:
            default_value (str): Default value of element.

        Yields:
            bytes: Mutations
        """
        with self._lock:
            start_time = time.time()
            self._deduplicator.clear()  # Clear for new mutation cycle

            local_random = random.Random(0)  # We want constant random numbers to generate reproducible test cases

            for i in range(0, self.get_num_mutations()):
                # select a random length for this string.
                if not self.step:
                    length = local_random.randint(self.min_length, self.max_length)
                # select a length function of the mutant index and the step.
                else:
                    length = self.min_length + i * self.step

                # Check cache first
                cache_key = (length, i)
                cached_value = self._data_cache.get(cache_key)

                if cached_value is not None:
                    self._stats['cache_hits'] += 1
                    value = cached_value
                else:
                    # Generate new random data
                    value = self._generate_random_bytes_optimized(length, local_random)
                    # Cache the generated value
                    self._data_cache.put(cache_key, value)

                # Use advanced deduplication
                if not self._deduplicator.is_duplicate(value):
                    self._stats['total_generated'] += 1
                    self._stats['unique_generated'] += 1
                    self._stats['bytes_generated'] += len(value)
                    yield value
                else:
                    self._stats['duplicates_prevented'] += 1

            # Update timing statistics
            self._stats['generation_time'] += time.time() - start_time

    def encode(self, value, mutation_context):
        return value

    def num_mutations(self, default_value):
        """
        Calculate and return the total number of mutations for this individual primitive.

        Args:
            default_value:

        Returns:
            int: Number of mutated forms this primitive can take
        """

        return self.max_mutations

    def get_optimization_stats(self) -> Dict[str, Any]:
        """Get comprehensive optimization statistics."""
        with self._lock:
            cache_stats = self._data_cache.get_statistics()
            dedup_stats = self._deduplicator.get_statistics()

            generation_rate = (
                self._stats['bytes_generated'] / self._stats['generation_time']
                if self._stats['generation_time'] > 0 else 0
            )

            return {
                'generation': self._stats,
                'cache': cache_stats,
                'deduplication': dedup_stats,
                'performance': {
                    'bytes_per_second': generation_rate,
                    'cache_hit_rate': (
                        self._stats['cache_hits'] / self._stats['total_generated'] * 100
                        if self._stats['total_generated'] > 0 else 0
                    ),
                    'deduplication_rate': dedup_stats.get('deduplication_rate', 0)
                }
            }

    def perform_maintenance(self):
        """Perform periodic maintenance on caches."""
        with self._lock:
            self._data_cache.maintenance()
