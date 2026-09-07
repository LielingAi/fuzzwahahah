"""
Smart caching system for FUZZ data generation optimization.

This module provides multi-tier caching with intelligent eviction policies,
compression, and performance monitoring.
"""

import time
import threading
import pickle
import zlib
from typing import Any, Dict, Optional, Tuple, List
from collections import OrderedDict
from dataclasses import dataclass
from enum import Enum


class CacheLevel(Enum):
    """Cache levels for tiered caching."""
    HOT = "hot"      # Frequently accessed, in-memory
    WARM = "warm"    # Moderately accessed, in-memory
    COLD = "cold"    # Rarely accessed, compressed


@dataclass
class CacheEntry:
    """Cache entry with metadata."""
    value: Any
    access_count: int
    last_access: float
    creation_time: float
    size_bytes: int
    compressed: bool = False


class LRUCache:
    """
    Thread-safe LRU cache with size limits.
    
    Features:
    - Thread-safe operations
    - Size-based eviction
    - Access tracking
    - Performance monitoring
    """
    
    def __init__(self, max_size: int = 1000, max_memory_mb: int = 100):
        """
        Initialize LRU cache.
        
        Args:
            max_size: Maximum number of entries
            max_memory_mb: Maximum memory usage in MB
        """
        self.max_size = max_size
        self.max_memory_bytes = max_memory_mb * 1024 * 1024
        
        self._cache = OrderedDict()
        self._lock = threading.RLock()
        
        # Statistics
        self.stats = {
            'hits': 0,
            'misses': 0,
            'evictions': 0,
            'memory_usage': 0,
            'total_accesses': 0
        }
    
    def get(self, key: Any) -> Optional[Any]:
        """Get value from cache."""
        with self._lock:
            self.stats['total_accesses'] += 1
            
            if key in self._cache:
                # Move to end (most recently used)
                entry = self._cache.pop(key)
                entry.access_count += 1
                entry.last_access = time.time()
                self._cache[key] = entry
                
                self.stats['hits'] += 1
                return entry.value
            
            self.stats['misses'] += 1
            return None
    
    def put(self, key: Any, value: Any) -> bool:
        """Put value in cache."""
        with self._lock:
            # Calculate size
            try:
                size_bytes = len(pickle.dumps(value))
            except:
                size_bytes = 1024  # Estimate
            
            # Check if we need to evict
            while (len(self._cache) >= self.max_size or 
                   self.stats['memory_usage'] + size_bytes > self.max_memory_bytes):
                if not self._evict_lru():
                    return False  # Cannot evict
            
            # Create entry
            entry = CacheEntry(
                value=value,
                access_count=1,
                last_access=time.time(),
                creation_time=time.time(),
                size_bytes=size_bytes
            )
            
            # Remove existing entry if present
            if key in self._cache:
                old_entry = self._cache[key]
                self.stats['memory_usage'] -= old_entry.size_bytes
            
            # Add new entry
            self._cache[key] = entry
            self.stats['memory_usage'] += size_bytes
            
            return True
    
    def _evict_lru(self) -> bool:
        """Evict least recently used entry."""
        if not self._cache:
            return False
        
        # Remove oldest entry
        key, entry = self._cache.popitem(last=False)
        self.stats['memory_usage'] -= entry.size_bytes
        self.stats['evictions'] += 1
        
        return True
    
    def clear(self):
        """Clear the cache."""
        with self._lock:
            self._cache.clear()
            self.stats['memory_usage'] = 0
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self._lock:
            hit_rate = (self.stats['hits'] / self.stats['total_accesses'] * 100 
                       if self.stats['total_accesses'] > 0 else 0)
            
            return {
                **self.stats,
                'size': len(self._cache),
                'max_size': self.max_size,
                'hit_rate_percent': hit_rate,
                'memory_usage_mb': self.stats['memory_usage'] / (1024 * 1024),
                'max_memory_mb': self.max_memory_bytes / (1024 * 1024)
            }


class TieredCache:
    """
    Multi-tier cache system with intelligent promotion/demotion.
    
    Features:
    - Hot/Warm/Cold tiers
    - Automatic promotion/demotion
    - Compression for cold storage
    - Adaptive thresholds
    """
    
    def __init__(self, hot_size: int = 1000, warm_size: int = 5000, cold_size: int = 10000):
        """
        Initialize tiered cache.
        
        Args:
            hot_size: Size of hot cache
            warm_size: Size of warm cache
            cold_size: Size of cold cache
        """
        self.hot_cache = LRUCache(hot_size, 50)    # 50MB for hot
        self.warm_cache = LRUCache(warm_size, 100)  # 100MB for warm
        self.cold_cache = LRUCache(cold_size, 200)  # 200MB for cold
        
        self._lock = threading.RLock()
        
        # Promotion/demotion thresholds
        self.hot_threshold = 5      # Access count for promotion to hot
        self.warm_threshold = 2     # Access count for promotion to warm
        self.cold_threshold = 24 * 3600  # Age in seconds for demotion to cold
        
        # Statistics
        self.stats = {
            'total_gets': 0,
            'hot_hits': 0,
            'warm_hits': 0,
            'cold_hits': 0,
            'misses': 0,
            'promotions': 0,
            'demotions': 0,
            'compressions': 0,
            'decompressions': 0
        }
    
    def get(self, key: Any) -> Optional[Any]:
        """Get value from tiered cache."""
        with self._lock:
            self.stats['total_gets'] += 1
            
            # Check hot cache first
            value = self.hot_cache.get(key)
            if value is not None:
                self.stats['hot_hits'] += 1
                return value
            
            # Check warm cache
            value = self.warm_cache.get(key)
            if value is not None:
                self.stats['warm_hits'] += 1
                # Consider promotion to hot
                self._consider_promotion(key, value, CacheLevel.WARM)
                return value
            
            # Check cold cache
            entry = self.cold_cache.get(key)
            if entry is not None:
                self.stats['cold_hits'] += 1
                
                # Decompress if needed
                if entry.compressed:
                    try:
                        value = pickle.loads(zlib.decompress(entry.value))
                        self.stats['decompressions'] += 1
                    except:
                        # Decompression failed, treat as miss
                        self.stats['misses'] += 1
                        return None
                else:
                    value = entry.value
                
                # Consider promotion to warm
                self._consider_promotion(key, value, CacheLevel.COLD)
                return value
            
            self.stats['misses'] += 1
            return None
    
    def put(self, key: Any, value: Any):
        """Put value in tiered cache."""
        with self._lock:
            # Start in warm cache by default
            success = self.warm_cache.put(key, value)
            if not success:
                # Warm cache full, try cold with compression
                self._put_cold_compressed(key, value)
    
    def _put_cold_compressed(self, key: Any, value: Any):
        """Put value in cold cache with compression."""
        try:
            compressed_value = zlib.compress(pickle.dumps(value))
            
            # Create compressed entry
            entry = CacheEntry(
                value=compressed_value,
                access_count=1,
                last_access=time.time(),
                creation_time=time.time(),
                size_bytes=len(compressed_value),
                compressed=True
            )
            
            self.cold_cache.put(key, entry)
            self.stats['compressions'] += 1
            
        except Exception as e:
            print(f"Failed to compress cache entry: {e}")
    
    def _consider_promotion(self, key: Any, value: Any, current_level: CacheLevel):
        """Consider promoting an entry to a higher tier."""
        if current_level == CacheLevel.WARM:
            # Get access count from warm cache
            warm_entry = self.warm_cache._cache.get(key)
            if warm_entry and warm_entry.access_count >= self.hot_threshold:
                # Promote to hot
                if self.hot_cache.put(key, value):
                    # Remove from warm cache
                    self.warm_cache._cache.pop(key, None)
                    self.stats['promotions'] += 1
        
        elif current_level == CacheLevel.COLD:
            # Promote to warm
            if self.warm_cache.put(key, value):
                # Remove from cold cache
                self.cold_cache._cache.pop(key, None)
                self.stats['promotions'] += 1
    
    def _demote_old_entries(self):
        """Demote old entries from hot/warm to lower tiers."""
        current_time = time.time()
        
        # Check hot cache for old entries
        hot_to_demote = []
        for key, entry in self.hot_cache._cache.items():
            if current_time - entry.last_access > self.cold_threshold / 2:
                hot_to_demote.append((key, entry.value))
        
        for key, value in hot_to_demote:
            if self.warm_cache.put(key, value):
                self.hot_cache._cache.pop(key, None)
                self.stats['demotions'] += 1
        
        # Check warm cache for old entries
        warm_to_demote = []
        for key, entry in self.warm_cache._cache.items():
            if current_time - entry.last_access > self.cold_threshold:
                warm_to_demote.append((key, entry.value))
        
        for key, value in warm_to_demote:
            self._put_cold_compressed(key, value)
            self.warm_cache._cache.pop(key, None)
            self.stats['demotions'] += 1
    
    def maintenance(self):
        """Perform cache maintenance (call periodically)."""
        with self._lock:
            self._demote_old_entries()
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive cache statistics."""
        with self._lock:
            total_gets = self.stats['total_gets']
            
            return {
                **self.stats,
                'hot_cache': self.hot_cache.get_statistics(),
                'warm_cache': self.warm_cache.get_statistics(),
                'cold_cache': self.cold_cache.get_statistics(),
                'overall_hit_rate': (
                    (total_gets - self.stats['misses']) / total_gets * 100
                    if total_gets > 0 else 0
                ),
                'tier_distribution': {
                    'hot_percent': self.stats['hot_hits'] / total_gets * 100 if total_gets > 0 else 0,
                    'warm_percent': self.stats['warm_hits'] / total_gets * 100 if total_gets > 0 else 0,
                    'cold_percent': self.stats['cold_hits'] / total_gets * 100 if total_gets > 0 else 0
                }
            }
    
    def clear(self):
        """Clear all cache tiers."""
        with self._lock:
            self.hot_cache.clear()
            self.warm_cache.clear()
            self.cold_cache.clear()
            
            # Reset statistics
            self.stats = {
                'total_gets': 0,
                'hot_hits': 0,
                'warm_hits': 0,
                'cold_hits': 0,
                'misses': 0,
                'promotions': 0,
                'demotions': 0,
                'compressions': 0,
                'decompressions': 0
            }
