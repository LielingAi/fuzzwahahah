"""
Intelligent Mutation Manager for coordinating FUZZ data generation.

This module provides centralized management of mutation strategies,
including priority scheduling, resource allocation, and feedback processing.
"""

import time
import threading
from typing import Dict, List, Tuple, Optional, Any, Iterator
from enum import Enum
from collections import defaultdict, deque
from dataclasses import dataclass
import heapq


class MutationStrategy(Enum):
    """Different mutation strategies available."""
    RANDOM = "random"
    TARGETED = "targeted"
    COVERAGE_GUIDED = "coverage_guided"
    ADAPTIVE = "adaptive"
    EXHAUSTIVE = "exhaustive"


@dataclass
class MutationTask:
    """Represents a mutation generation task."""
    priority: int
    strategy: MutationStrategy
    primitive_name: str
    parameters: Dict[str, Any]
    created_at: float
    
    def __lt__(self, other):
        return self.priority < other.priority


@dataclass
class MutationResult:
    """Result of a mutation generation."""
    task_id: str
    mutation_data: bytes
    generation_time: float
    metadata: Dict[str, Any]


class MutationManager:
    """
    Centralized manager for intelligent mutation generation.
    
    Features:
    - Priority-based task scheduling
    - Resource allocation and throttling
    - Performance monitoring
    - Feedback processing
    - Strategy adaptation
    """
    
    def __init__(self, max_concurrent_tasks=4, max_queue_size=1000):
        """
        Initialize the mutation manager.
        
        Args:
            max_concurrent_tasks: Maximum number of concurrent generation tasks
            max_queue_size: Maximum size of the task queue
        """
        self.max_concurrent_tasks = max_concurrent_tasks
        self.max_queue_size = max_queue_size
        
        # Task management
        self.task_queue = []  # Priority queue of MutationTask
        self.active_tasks = {}  # task_id -> task info
        self.completed_tasks = deque(maxlen=10000)  # Recent completed tasks
        
        # Performance tracking
        self.performance_stats = {
            'total_tasks': 0,
            'completed_tasks': 0,
            'failed_tasks': 0,
            'average_generation_time': 0.0,
            'mutations_per_second': 0.0,
            'strategy_performance': defaultdict(list)
        }
        
        # Feedback and adaptation
        self.effectiveness_scores = defaultdict(list)  # strategy -> [scores]
        self.coverage_data = set()
        self.successful_patterns = []
        
        # Threading
        self._lock = threading.RLock()
        self._shutdown = False
        self._worker_threads = []
        
        # Start worker threads
        self._start_workers()

    def _start_workers(self):
        """Start worker threads for mutation generation."""
        for i in range(self.max_concurrent_tasks):
            worker = threading.Thread(
                target=self._worker_loop,
                name=f"MutationWorker-{i}",
                daemon=True
            )
            worker.start()
            self._worker_threads.append(worker)

    def _worker_loop(self):
        """Main loop for worker threads."""
        while not self._shutdown:
            try:
                task = self._get_next_task()
                if task is None:
                    time.sleep(0.01)  # Brief sleep when no tasks
                    continue
                
                # Execute the task
                result = self._execute_task(task)
                
                # Record completion
                self._record_task_completion(task, result)
                
            except Exception as e:
                print(f"Worker error: {e}")
                time.sleep(0.1)

    def _get_next_task(self) -> Optional[MutationTask]:
        """Get the next highest priority task."""
        with self._lock:
            if self.task_queue:
                return heapq.heappop(self.task_queue)
            return None

    def _execute_task(self, task: MutationTask) -> MutationResult:
        """Execute a mutation generation task."""
        start_time = time.time()
        
        try:
            # Generate mutation based on strategy
            if task.strategy == MutationStrategy.RANDOM:
                mutation_data = self._generate_random_mutation(task.parameters)
            elif task.strategy == MutationStrategy.TARGETED:
                mutation_data = self._generate_targeted_mutation(task.parameters)
            elif task.strategy == MutationStrategy.COVERAGE_GUIDED:
                mutation_data = self._generate_coverage_guided_mutation(task.parameters)
            elif task.strategy == MutationStrategy.ADAPTIVE:
                mutation_data = self._generate_adaptive_mutation(task.parameters)
            else:
                mutation_data = self._generate_exhaustive_mutation(task.parameters)
            
            generation_time = time.time() - start_time
            
            return MutationResult(
                task_id=f"{task.primitive_name}_{int(start_time*1000)}",
                mutation_data=mutation_data,
                generation_time=generation_time,
                metadata={
                    'strategy': task.strategy.value,
                    'primitive': task.primitive_name,
                    'parameters': task.parameters
                }
            )
            
        except Exception as e:
            return MutationResult(
                task_id=f"failed_{int(start_time*1000)}",
                mutation_data=b"",
                generation_time=time.time() - start_time,
                metadata={'error': str(e)}
            )

    def _generate_random_mutation(self, params: Dict) -> bytes:
        """Generate random mutation data."""
        import random
        length = params.get('length', random.randint(1, 1000))
        return bytes(random.randint(0, 255) for _ in range(length))

    def _generate_targeted_mutation(self, params: Dict) -> bytes:
        """Generate targeted mutation based on known patterns."""
        patterns = params.get('patterns', [b"AAAA", b"\x00\x00", b"\xff\xff"])
        import random
        return random.choice(patterns)

    def _generate_coverage_guided_mutation(self, params: Dict) -> bytes:
        """Generate mutation to improve coverage."""
        # Simplified coverage-guided generation
        base_data = params.get('base_data', b"test")
        import random
        
        # Mutate random bytes
        data = bytearray(base_data)
        for _ in range(random.randint(1, 5)):
            if data:
                pos = random.randint(0, len(data) - 1)
                data[pos] = random.randint(0, 255)
        
        return bytes(data)

    def _generate_adaptive_mutation(self, params: Dict) -> bytes:
        """Generate mutation based on learned patterns."""
        if self.successful_patterns:
            import random
            pattern = random.choice(self.successful_patterns)
            return pattern.encode() if isinstance(pattern, str) else pattern
        else:
            return self._generate_random_mutation(params)

    def _generate_exhaustive_mutation(self, params: Dict) -> bytes:
        """Generate systematic exhaustive mutations."""
        # Simplified exhaustive generation
        base = params.get('base', 0)
        length = params.get('length', 4)
        return (base).to_bytes(length, 'little')

    def _record_task_completion(self, task: MutationTask, result: MutationResult):
        """Record the completion of a task."""
        with self._lock:
            self.completed_tasks.append((task, result))
            self.performance_stats['completed_tasks'] += 1
            
            # Update performance metrics
            if 'error' not in result.metadata:
                self.performance_stats['strategy_performance'][task.strategy].append(
                    result.generation_time
                )
                
                # Update average generation time
                total_time = sum(
                    sum(times) for times in self.performance_stats['strategy_performance'].values()
                )
                total_count = sum(
                    len(times) for times in self.performance_stats['strategy_performance'].values()
                )
                if total_count > 0:
                    self.performance_stats['average_generation_time'] = total_time / total_count

    def submit_task(self, strategy: MutationStrategy, primitive_name: str, 
                   parameters: Dict[str, Any], priority: int = 5) -> bool:
        """
        Submit a mutation generation task.
        
        Args:
            strategy: Mutation strategy to use
            primitive_name: Name of the primitive being mutated
            parameters: Parameters for the mutation
            priority: Task priority (lower numbers = higher priority)
            
        Returns:
            True if task was queued, False if queue is full
        """
        with self._lock:
            if len(self.task_queue) >= self.max_queue_size:
                return False
            
            task = MutationTask(
                priority=priority,
                strategy=strategy,
                primitive_name=primitive_name,
                parameters=parameters,
                created_at=time.time()
            )
            
            heapq.heappush(self.task_queue, task)
            self.performance_stats['total_tasks'] += 1
            return True

    def get_mutations(self, count: int = 10, timeout: float = 5.0) -> List[MutationResult]:
        """
        Get generated mutations.
        
        Args:
            count: Number of mutations to retrieve
            timeout: Maximum time to wait for mutations
            
        Returns:
            List of mutation results
        """
        results = []
        start_time = time.time()
        
        while len(results) < count and (time.time() - start_time) < timeout:
            with self._lock:
                if self.completed_tasks:
                    task, result = self.completed_tasks.popleft()
                    if 'error' not in result.metadata:
                        results.append(result)
            
            if len(results) < count:
                time.sleep(0.01)  # Brief sleep
        
        return results

    def record_feedback(self, mutation_id: str, effectiveness: float, 
                       coverage_increase: bool = False):
        """
        Record feedback about mutation effectiveness.
        
        Args:
            mutation_id: ID of the mutation
            effectiveness: Effectiveness score (0.0 to 10.0)
            coverage_increase: Whether this mutation increased coverage
        """
        with self._lock:
            # Find the corresponding task
            for task, result in self.completed_tasks:
                if result.task_id == mutation_id:
                    strategy = task.strategy
                    self.effectiveness_scores[strategy].append(effectiveness)
                    
                    # Track successful patterns
                    if effectiveness >= 7.0:
                        self.successful_patterns.append(result.mutation_data)
                        
                        # Limit successful patterns
                        if len(self.successful_patterns) > 1000:
                            self.successful_patterns = self.successful_patterns[-500:]
                    
                    break

    def get_performance_stats(self) -> Dict[str, Any]:
        """Get current performance statistics."""
        with self._lock:
            stats = self.performance_stats.copy()
            
            # Calculate mutations per second
            if stats['completed_tasks'] > 0 and stats['average_generation_time'] > 0:
                stats['mutations_per_second'] = 1.0 / stats['average_generation_time']
            
            # Add strategy effectiveness
            strategy_effectiveness = {}
            for strategy, scores in self.effectiveness_scores.items():
                if scores:
                    strategy_effectiveness[strategy.value] = {
                        'average_score': sum(scores) / len(scores),
                        'sample_count': len(scores)
                    }
            stats['strategy_effectiveness'] = strategy_effectiveness
            
            return stats

    def optimize_strategies(self):
        """Optimize mutation strategies based on feedback."""
        with self._lock:
            # Analyze strategy performance
            best_strategy = None
            best_score = 0.0
            
            for strategy, scores in self.effectiveness_scores.items():
                if scores:
                    avg_score = sum(scores) / len(scores)
                    if avg_score > best_score:
                        best_score = avg_score
                        best_strategy = strategy
            
            # Adjust priorities based on performance
            if best_strategy:
                print(f"Best performing strategy: {best_strategy.value} (score: {best_score:.2f})")

    def shutdown(self):
        """Shutdown the mutation manager."""
        self._shutdown = True
        for worker in self._worker_threads:
            worker.join(timeout=1.0)
