"""
Smart String primitive with intelligent mutation prioritization and protocol awareness.

This module extends the basic String primitive with advanced features:
- Priority-based mutation ordering
- Protocol-specific mutation patterns
- Adaptive generation based on feedback
- Coverage-guided fuzzing support
"""

import itertools
import random
from typing import Dict, List, Tuple, Optional, Set
from enum import Enum
from functools import lru_cache

from .string import String
from ..fuzzable import Fuzzable


class MutationPriority(Enum):
    """Priority levels for different types of mutations."""
    CRITICAL = 1    # Known vulnerability patterns
    HIGH = 2        # Common edge cases
    MEDIUM = 3      # Standard fuzzing patterns
    LOW = 4         # Exhaustive patterns


class ProtocolType(Enum):
    """Supported protocol types for specialized fuzzing."""
    HTTP = "http"
    SQL = "sql"
    XML = "xml"
    JSON = "json"
    BINARY = "binary"
    GENERIC = "generic"


class SmartString(String):
    """
    Enhanced String primitive with intelligent mutation strategies.
    
    Features:
    - Priority-based mutation ordering
    - Protocol-specific patterns
    - Adaptive generation
    - Coverage tracking
    """
    
    # High-priority vulnerability patterns
    _critical_patterns = [
        # Buffer overflow patterns
        "A" * 4096,
        "A" * 8192,
        "A" * 65536,
        
        # Format string vulnerabilities
        "%n" * 100,
        "%s" * 100,
        "%x" * 100,
        
        # Injection patterns
        "'; DROP TABLE users; --",
        "' OR '1'='1",
        "<script>alert('xss')</script>",
        "../../../../etc/passwd",
        
        # Unicode and encoding issues
        "\x00" * 100,
        "\xff" * 100,
        "\u0000" * 100,
        "\uffff" * 100,
    ]
    
    # Protocol-specific patterns
    _protocol_patterns = {
        ProtocolType.HTTP: [
            "GET /" + "A" * 8192 + " HTTP/1.1\r\n\r\n",
            "POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: " + "A" * 100,
            "\r\n\r\n" + "A" * 65536,
        ],
        ProtocolType.SQL: [
            "'; WAITFOR DELAY '00:00:10'; --",
            "' UNION SELECT NULL, NULL, NULL --",
            "'; EXEC xp_cmdshell('dir'); --",
            "' AND 1=CONVERT(int, (SELECT @@version)) --",
        ],
        ProtocolType.XML: [
            "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>",
            "<![CDATA[" + "A" * 65536 + "]]>",
            "<?xml version='1.0' encoding='UTF-8'?>" + "<root>" * 10000 + "</root>" * 10000,
        ],
        ProtocolType.JSON: [
            '{"key": "' + "A" * 65536 + '"}',
            '{"key": ' + "1" * 1000 + '}',
            '[' + '{"a":1},' * 10000 + ']',
            '{"' + "A" * 1000 + '": "value"}',
        ]
    }
    
    def __init__(self, name=None, default_value="", protocol_type=ProtocolType.GENERIC, 
                 priority_mode=True, adaptive=True, *args, **kwargs):
        """
        Initialize SmartString with enhanced capabilities.
        
        Args:
            protocol_type: Type of protocol for specialized patterns
            priority_mode: Enable priority-based mutation ordering
            adaptive: Enable adaptive generation based on feedback
        """
        super(SmartString, self).__init__(name=name, default_value=default_value, *args, **kwargs)
        
        self.protocol_type = protocol_type
        self.priority_mode = priority_mode
        self.adaptive = adaptive
        
        # Tracking for adaptive behavior
        self.mutation_feedback = {}  # mutation -> effectiveness score
        self.coverage_data = set()   # Track what has been tested
        self.success_patterns = []   # Patterns that found issues
        
        # Performance metrics
        self.generation_stats = {
            'total_generated': 0,
            'unique_generated': 0,
            'critical_generated': 0,
            'protocol_specific': 0
        }

    def _get_prioritized_mutations(self, default_value: str) -> List[Tuple[str, MutationPriority]]:
        """
        Get mutations ordered by priority.
        
        Returns:
            List of (mutation, priority) tuples ordered by priority
        """
        mutations = []
        
        # Critical patterns (highest priority)
        for pattern in self._critical_patterns:
            if self.max_len is None or len(pattern) <= self.max_len:
                mutations.append((pattern, MutationPriority.CRITICAL))
        
        # Protocol-specific patterns
        if self.protocol_type in self._protocol_patterns:
            for pattern in self._protocol_patterns[self.protocol_type]:
                if self.max_len is None or len(pattern) <= self.max_len:
                    mutations.append((pattern, MutationPriority.HIGH))
        
        # Adaptive patterns based on previous success
        for pattern in self.success_patterns:
            if self.max_len is None or len(pattern) <= self.max_len:
                mutations.append((pattern, MutationPriority.HIGH))
        
        # Standard fuzzing library (medium priority)
        for pattern in self._fuzz_library:
            mutations.append((pattern, MutationPriority.MEDIUM))
        
        # Variable mutations
        for pattern in self._yield_variable_mutations(default_value):
            mutations.append((pattern, MutationPriority.MEDIUM))
        
        # Long strings (lower priority for exhaustive testing)
        for pattern in self._yield_long_strings(self.long_string_seeds):
            mutations.append((pattern, MutationPriority.LOW))
        
        # Sort by priority if enabled
        if self.priority_mode:
            mutations.sort(key=lambda x: x[1].value)
        
        return mutations

    def _calculate_mutation_score(self, mutation: str) -> float:
        """
        Calculate effectiveness score for a mutation.
        
        Args:
            mutation: The mutation string
            
        Returns:
            Effectiveness score (higher is better)
        """
        score = 0.0
        
        # Base score from feedback
        if mutation in self.mutation_feedback:
            score += self.mutation_feedback[mutation]
        
        # Bonus for critical patterns
        if mutation in self._critical_patterns:
            score += 10.0
        
        # Bonus for protocol-specific patterns
        if self.protocol_type in self._protocol_patterns:
            if mutation in self._protocol_patterns[self.protocol_type]:
                score += 5.0
        
        # Bonus for length-based edge cases
        if len(mutation) in [0, 1, 255, 256, 65535, 65536]:
            score += 3.0
        
        # Bonus for special characters
        special_chars = set(mutation) & set('\x00\xff\n\r\t"\'<>&;|`$()[]{}')
        score += len(special_chars) * 0.5
        
        return score

    def mutations(self, default_value):
        """
        Generate mutations with intelligent prioritization.
        
        Args:
            default_value: Default value for the field
            
        Yields:
            str: Prioritized mutations
        """
        self.generation_stats['total_generated'] = 0
        self.generation_stats['unique_generated'] = 0
        
        # Get prioritized mutations
        prioritized_mutations = self._get_prioritized_mutations(default_value)
        
        # Apply adaptive scoring if enabled
        if self.adaptive:
            prioritized_mutations.sort(
                key=lambda x: self._calculate_mutation_score(x[0]), 
                reverse=True
            )
        
        # Generate mutations with deduplication
        seen_hashes = set()
        
        for mutation, priority in prioritized_mutations:
            # Apply size constraints
            adjusted_mutation = self._adjust_mutation_for_size(mutation)
            
            # Deduplication
            mutation_hash = self._get_mutation_hash(adjusted_mutation)
            if mutation_hash in seen_hashes:
                continue
            
            seen_hashes.add(mutation_hash)
            
            # Update statistics
            self.generation_stats['total_generated'] += 1
            self.generation_stats['unique_generated'] += 1
            
            if priority == MutationPriority.CRITICAL:
                self.generation_stats['critical_generated'] += 1
            
            if self.protocol_type != ProtocolType.GENERIC and priority == MutationPriority.HIGH:
                self.generation_stats['protocol_specific'] += 1
            
            yield adjusted_mutation

    def record_feedback(self, mutation: str, effectiveness: float):
        """
        Record feedback about mutation effectiveness.
        
        Args:
            mutation: The mutation that was tested
            effectiveness: Effectiveness score (0.0 to 10.0)
        """
        self.mutation_feedback[mutation] = effectiveness
        
        # Track successful patterns
        if effectiveness >= 7.0 and mutation not in self.success_patterns:
            self.success_patterns.append(mutation)
            
        # Limit success patterns to prevent memory growth
        if len(self.success_patterns) > 100:
            self.success_patterns = self.success_patterns[-50:]

    def get_generation_stats(self) -> Dict:
        """Get statistics about mutation generation."""
        return self.generation_stats.copy()

    def reset_adaptive_data(self):
        """Reset adaptive learning data."""
        self.mutation_feedback.clear()
        self.success_patterns.clear()
        self.coverage_data.clear()

    def export_learned_patterns(self) -> List[str]:
        """Export learned successful patterns for reuse."""
        return self.success_patterns.copy()

    def import_learned_patterns(self, patterns: List[str]):
        """Import previously learned patterns."""
        self.success_patterns.extend(patterns)
        # Remove duplicates while preserving order
        seen = set()
        self.success_patterns = [
            x for x in self.success_patterns 
            if not (x in seen or seen.add(x))
        ]
