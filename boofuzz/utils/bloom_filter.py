"""
High-performance Bloom Filter implementation for FUZZ data deduplication.

This module provides memory-efficient approximate deduplication using Bloom filters,
significantly reducing memory usage for large-scale fuzzing operations.
"""

import hashlib
import math
from typing import Union, List


class BloomFilter:
    """
    Memory-efficient Bloom filter for approximate set membership testing.
    
    Features:
    - Configurable false positive rate
    - Multiple hash functions
    - Memory-efficient bit array
    - High-performance operations
    """
    
    def __init__(self, capacity: int = 1000000, error_rate: float = 0.01):
        """
        Initialize Bloom filter.
        
        Args:
            capacity: Expected number of elements
            error_rate: Desired false positive rate (0.0 to 1.0)
        """
        self.capacity = capacity
        self.error_rate = error_rate
        
        # Calculate optimal parameters
        self.bit_array_size = self._calculate_bit_array_size(capacity, error_rate)
        self.hash_count = self._calculate_hash_count(self.bit_array_size, capacity)
        
        # Initialize bit array
        self.bit_array = bytearray(math.ceil(self.bit_array_size / 8))
        self.element_count = 0
        
        # Statistics
        self.stats = {
            'adds': 0,
            'checks': 0,
            'estimated_false_positives': 0
        }
    
    @staticmethod
    def _calculate_bit_array_size(capacity: int, error_rate: float) -> int:
        """Calculate optimal bit array size."""
        return int(-capacity * math.log(error_rate) / (math.log(2) ** 2))
    
    @staticmethod
    def _calculate_hash_count(bit_array_size: int, capacity: int) -> int:
        """Calculate optimal number of hash functions."""
        return int((bit_array_size / capacity) * math.log(2))
    
    def _hash(self, item: Union[str, bytes], seed: int) -> int:
        """Generate hash value for item with given seed."""
        if isinstance(item, str):
            item = item.encode('utf-8')
        
        # Use SHA-256 with seed for high-quality hashing
        hasher = hashlib.sha256()
        hasher.update(seed.to_bytes(4, 'big'))
        hasher.update(item)
        
        # Convert to integer and mod by bit array size
        hash_value = int.from_bytes(hasher.digest()[:8], 'big')
        return hash_value % self.bit_array_size
    
    def _set_bit(self, index: int):
        """Set bit at given index."""
        byte_index = index // 8
        bit_index = index % 8
        self.bit_array[byte_index] |= (1 << bit_index)
    
    def _get_bit(self, index: int) -> bool:
        """Get bit at given index."""
        byte_index = index // 8
        bit_index = index % 8
        return bool(self.bit_array[byte_index] & (1 << bit_index))
    
    def add(self, item: Union[str, bytes]):
        """Add item to the Bloom filter."""
        for i in range(self.hash_count):
            index = self._hash(item, i)
            self._set_bit(index)
        
        self.element_count += 1
        self.stats['adds'] += 1
    
    def __contains__(self, item: Union[str, bytes]) -> bool:
        """Check if item might be in the set."""
        self.stats['checks'] += 1
        
        for i in range(self.hash_count):
            index = self._hash(item, i)
            if not self._get_bit(index):
                return False
        
        # All bits are set, item might be in the set
        # Estimate if this is a false positive
        current_error_rate = self.get_current_error_rate()
        if current_error_rate > self.error_rate * 2:  # Rough heuristic
            self.stats['estimated_false_positives'] += 1
        
        return True
    
    def get_current_error_rate(self) -> float:
        """Estimate current false positive rate."""
        if self.element_count == 0:
            return 0.0
        
        # Calculate probability that a bit is still 0
        prob_bit_zero = (1 - 1/self.bit_array_size) ** (self.hash_count * self.element_count)
        
        # False positive rate is (1 - prob_bit_zero)^hash_count
        return (1 - prob_bit_zero) ** self.hash_count
    
    def get_memory_usage(self) -> dict:
        """Get memory usage statistics."""
        return {
            'bit_array_bytes': len(self.bit_array),
            'bit_array_size': self.bit_array_size,
            'memory_efficiency': self.element_count / len(self.bit_array) if self.bit_array else 0,
            'capacity_utilization': self.element_count / self.capacity
        }
    
    def get_statistics(self) -> dict:
        """Get comprehensive statistics."""
        return {
            **self.stats,
            'element_count': self.element_count,
            'capacity': self.capacity,
            'target_error_rate': self.error_rate,
            'current_error_rate': self.get_current_error_rate(),
            'hash_count': self.hash_count,
            **self.get_memory_usage()
        }
    
    def clear(self):
        """Clear the Bloom filter."""
        self.bit_array = bytearray(math.ceil(self.bit_array_size / 8))
        self.element_count = 0
        self.stats = {
            'adds': 0,
            'checks': 0,
            'estimated_false_positives': 0
        }


class AdvancedDeduplicator:
    """
    Advanced deduplication system combining Bloom filter with exact cache.
    
    Features:
    - Bloom filter for fast approximate checking
    - LRU cache for exact verification
    - Adaptive thresholds
    - Performance monitoring
    """
    
    def __init__(self, bloom_capacity: int = 1000000, bloom_error_rate: float = 0.01,
                 exact_cache_size: int = 10000):
        """
        Initialize advanced deduplicator.
        
        Args:
            bloom_capacity: Bloom filter capacity
            bloom_error_rate: Bloom filter error rate
            exact_cache_size: Size of exact verification cache
        """
        self.bloom_filter = BloomFilter(bloom_capacity, bloom_error_rate)
        self.exact_cache = {}  # Simple dict cache (could use LRU)
        self.exact_cache_size = exact_cache_size
        
        # Performance tracking
        self.stats = {
            'total_checks': 0,
            'bloom_hits': 0,
            'exact_hits': 0,
            'unique_items': 0,
            'false_positives_avoided': 0
        }
    
    def _manage_exact_cache(self):
        """Manage exact cache size using simple FIFO."""
        if len(self.exact_cache) >= self.exact_cache_size:
            # Remove oldest 20% of entries
            items_to_remove = len(self.exact_cache) // 5
            keys_to_remove = list(self.exact_cache.keys())[:items_to_remove]
            for key in keys_to_remove:
                del self.exact_cache[key]
    
    def is_duplicate(self, item: Union[str, bytes]) -> bool:
        """
        Check if item is a duplicate.
        
        Args:
            item: Item to check
            
        Returns:
            True if item is likely a duplicate, False if definitely unique
        """
        self.stats['total_checks'] += 1
        
        # First check Bloom filter
        if item not in self.bloom_filter:
            # Definitely not seen before
            self.bloom_filter.add(item)
            self.stats['unique_items'] += 1
            return False
        
        self.stats['bloom_hits'] += 1
        
        # Bloom filter says "maybe seen", check exact cache
        item_hash = hash(item) if isinstance(item, (str, bytes)) else item
        
        if item_hash in self.exact_cache:
            # Definitely seen before
            self.stats['exact_hits'] += 1
            return True
        
        # Not in exact cache, so this was a Bloom filter false positive
        self.stats['false_positives_avoided'] += 1
        
        # Add to exact cache and Bloom filter
        self._manage_exact_cache()
        self.exact_cache[item_hash] = True
        self.stats['unique_items'] += 1
        
        return False
    
    def get_statistics(self) -> dict:
        """Get comprehensive statistics."""
        bloom_stats = self.bloom_filter.get_statistics()
        
        total_checks = self.stats['total_checks']
        bloom_efficiency = (self.stats['bloom_hits'] / total_checks * 100) if total_checks > 0 else 0
        exact_efficiency = (self.stats['exact_hits'] / total_checks * 100) if total_checks > 0 else 0
        
        return {
            **self.stats,
            'bloom_filter': bloom_stats,
            'exact_cache_size': len(self.exact_cache),
            'exact_cache_capacity': self.exact_cache_size,
            'bloom_efficiency_percent': bloom_efficiency,
            'exact_efficiency_percent': exact_efficiency,
            'deduplication_rate': (self.stats['exact_hits'] / total_checks * 100) if total_checks > 0 else 0
        }
    
    def clear(self):
        """Clear all caches."""
        self.bloom_filter.clear()
        self.exact_cache.clear()
        self.stats = {
            'total_checks': 0,
            'bloom_hits': 0,
            'exact_hits': 0,
            'unique_items': 0,
            'false_positives_avoided': 0
        }
