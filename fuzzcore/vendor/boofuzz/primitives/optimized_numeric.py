"""
Optimized numeric primitive base class with advanced caching and deduplication.

This module provides a high-performance base class for all numeric primitives
with built-in optimization features.
"""

import threading
import time
import struct
from typing import Dict, Any, List, Iterator, Union
from abc import ABC, abstractmethod

from ..utils.bloom_filter import AdvancedDeduplicator
from ..utils.smart_cache import TieredCache


class OptimizedNumericBase(ABC):
    """
    Base class for optimized numeric primitives.
    
    Features:
    - Advanced caching with tiered storage
    - Bloom filter deduplication
    - Performance monitoring
    - Thread-safe operations
    - Batch generation capabilities
    """
    
    def __init__(self, cache_size_multiplier: float = 1.0):
        """
        Initialize optimization components.
        
        Args:
            cache_size_multiplier: Multiplier for cache sizes (adjust based on expected usage)
        """
        # Calculate cache sizes based on multiplier
        hot_size = int(100 * cache_size_multiplier)
        warm_size = int(500 * cache_size_multiplier)
        cold_size = int(1000 * cache_size_multiplier)
        
        # Advanced optimization components
        self._value_cache = TieredCache(
            hot_size=hot_size,
            warm_size=warm_size, 
            cold_size=cold_size
        )
        self._deduplicator = AdvancedDeduplicator(
            bloom_capacity=int(25000 * cache_size_multiplier),
            bloom_error_rate=0.01,
            exact_cache_size=int(1000 * cache_size_multiplier)
        )
        
        # Performance tracking
        self._stats = {
            'total_generated': 0,
            'unique_generated': 0,
            'cache_hits': 0,
            'duplicates_prevented': 0,
            'generation_time': 0.0,
            'values_processed': 0,
            'batch_generations': 0
        }
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Numeric-specific optimizations
        self._interesting_values_cache = {}
        self._boundary_values_cache = {}
    
    @abstractmethod
    def _get_format_string(self) -> str:
        """Get struct format string for this numeric type."""
        pass
    
    @abstractmethod
    def _get_byte_size(self) -> int:
        """Get byte size for this numeric type."""
        pass
    
    @abstractmethod
    def _get_min_value(self) -> int:
        """Get minimum value for this numeric type."""
        pass
    
    @abstractmethod
    def _get_max_value(self) -> int:
        """Get maximum value for this numeric type."""
        pass
    
    def _generate_interesting_values(self) -> List[int]:
        """Generate interesting values for this numeric type."""
        cache_key = f"interesting_{self._get_byte_size()}"
        
        if cache_key in self._interesting_values_cache:
            return self._interesting_values_cache[cache_key]
        
        min_val = self._get_min_value()
        max_val = self._get_max_value()
        byte_size = self._get_byte_size()
        
        # Base interesting values
        interesting = [
            0, 1, -1,  # Basic values
            min_val, max_val,  # Boundaries
            min_val + 1, max_val - 1,  # Near boundaries
        ]
        
        # Powers of 2 and their neighbors
        for i in range(byte_size * 8):
            val = 2 ** i
            if min_val <= val <= max_val:
                interesting.extend([val, val - 1, val + 1])
            
            neg_val = -(2 ** i)
            if min_val <= neg_val <= max_val:
                interesting.extend([neg_val, neg_val - 1, neg_val + 1])
        
        # Common problematic values
        problematic = [
            0x7F, 0x80, 0xFF,  # 8-bit boundaries
            0x7FFF, 0x8000, 0xFFFF,  # 16-bit boundaries
            0x7FFFFFFF, 0x80000000, 0xFFFFFFFF,  # 32-bit boundaries
            0x7FFFFFFFFFFFFFFF, 0x8000000000000000, 0xFFFFFFFFFFFFFFFF,  # 64-bit boundaries
        ]
        
        for val in problematic:
            if min_val <= val <= max_val:
                interesting.append(val)
            
            # Negative versions for signed types
            if min_val < 0 and min_val <= -val <= max_val:
                interesting.append(-val)
        
        # Remove duplicates and sort
        interesting = sorted(list(set(interesting)))
        
        # Cache the result
        self._interesting_values_cache[cache_key] = interesting
        
        return interesting
    
    def _pack_value_optimized(self, value: int) -> bytes:
        """Pack value to bytes with caching."""
        cache_key = (value, self._get_format_string())
        
        # Check cache first
        cached_result = self._value_cache.get(cache_key)
        if cached_result is not None:
            self._stats['cache_hits'] += 1
            return cached_result
        
        # Generate and cache
        try:
            if self._get_format_string().startswith('<'):
                # Little endian
                packed = struct.pack(self._get_format_string(), value)
            else:
                # Big endian or native
                packed = struct.pack(self._get_format_string(), value)
            
            self._value_cache.put(cache_key, packed)
            return packed
            
        except struct.error:
            # Value out of range, return empty bytes
            return b''
    
    def _generate_mutations_optimized(self, default_value: int) -> Iterator[bytes]:
        """Generate optimized mutations with caching and deduplication."""
        with self._lock:
            start_time = time.time()
            self._deduplicator.clear()  # Clear for new mutation cycle
            
            # Get interesting values
            interesting_values = self._generate_interesting_values()
            
            # Add default value variations
            all_values = interesting_values.copy()
            if default_value not in all_values:
                all_values.append(default_value)
            
            # Add some variations of default value
            variations = [
                default_value * 2,
                default_value * 10,
                default_value * 100,
                default_value + 1,
                default_value - 1,
                default_value ^ 0xFFFFFFFF,  # Bit flip
            ]
            
            for var in variations:
                if self._get_min_value() <= var <= self._get_max_value():
                    all_values.append(var)
            
            # Remove duplicates
            all_values = list(set(all_values))
            
            # Generate mutations
            for value in all_values:
                packed = self._pack_value_optimized(value)
                
                if packed and not self._deduplicator.is_duplicate(packed):
                    self._stats['total_generated'] += 1
                    self._stats['unique_generated'] += 1
                    self._stats['values_processed'] += 1
                    yield packed
                else:
                    if packed:  # Only count as duplicate if packing succeeded
                        self._stats['duplicates_prevented'] += 1
            
            # Update timing statistics
            self._stats['generation_time'] += time.time() - start_time
    
    def _generate_batch_mutations(self, values: List[int]) -> List[bytes]:
        """Generate mutations for a batch of values efficiently."""
        with self._lock:
            self._stats['batch_generations'] += 1
            results = []
            
            for value in values:
                packed = self._pack_value_optimized(value)
                if packed and not self._deduplicator.is_duplicate(packed):
                    results.append(packed)
                    self._stats['unique_generated'] += 1
                else:
                    if packed:
                        self._stats['duplicates_prevented'] += 1
            
            self._stats['total_generated'] += len(results)
            self._stats['values_processed'] += len(values)
            
            return results
    
    def get_optimization_stats(self) -> Dict[str, Any]:
        """Get comprehensive optimization statistics."""
        with self._lock:
            cache_stats = self._value_cache.get_statistics()
            dedup_stats = self._deduplicator.get_statistics()
            
            processing_rate = (
                self._stats['values_processed'] / self._stats['generation_time']
                if self._stats['generation_time'] > 0 else 0
            )
            
            return {
                'generation': self._stats,
                'cache': cache_stats,
                'deduplication': dedup_stats,
                'performance': {
                    'values_per_second': processing_rate,
                    'cache_hit_rate': (
                        self._stats['cache_hits'] / self._stats['total_generated'] * 100
                        if self._stats['total_generated'] > 0 else 0
                    ),
                    'deduplication_rate': dedup_stats.get('deduplication_rate', 0),
                    'batch_efficiency': (
                        self._stats['batch_generations'] / self._stats['total_generated']
                        if self._stats['total_generated'] > 0 else 0
                    )
                },
                'numeric_info': {
                    'format_string': self._get_format_string(),
                    'byte_size': self._get_byte_size(),
                    'min_value': self._get_min_value(),
                    'max_value': self._get_max_value(),
                    'interesting_values_count': len(self._generate_interesting_values())
                }
            }
    
    def perform_maintenance(self):
        """Perform periodic maintenance on caches."""
        with self._lock:
            self._value_cache.maintenance()
    
    def clear_caches(self):
        """Clear all caches (useful for testing or memory management)."""
        with self._lock:
            self._value_cache.clear()
            self._deduplicator.clear()
            self._interesting_values_cache.clear()
            self._boundary_values_cache.clear()
            
            # Reset statistics
            self._stats = {
                'total_generated': 0,
                'unique_generated': 0,
                'cache_hits': 0,
                'duplicates_prevented': 0,
                'generation_time': 0.0,
                'values_processed': 0,
                'batch_generations': 0
            }
