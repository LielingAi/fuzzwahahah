"""
Parallel FUZZ data generation system for high-performance fuzzing.

This module provides multi-process and multi-threaded generation capabilities
to fully utilize modern multi-core systems.
"""

import multiprocessing
import threading
import queue
import time
import itertools
from typing import Iterator, List, Callable, Any, Optional, Dict
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from dataclasses import dataclass


@dataclass
class GenerationTask:
    """Represents a generation task for parallel execution."""
    generator_type: str
    parameters: Dict[str, Any]
    count: int
    priority: int = 5


class ParallelStringGenerator:
    """
    High-performance parallel string generator.
    
    Features:
    - Multi-process generation for CPU-intensive tasks
    - Thread pool for I/O-bound operations
    - Work stealing for load balancing
    - Adaptive batch sizing
    """
    
    def __init__(self, num_processes: Optional[int] = None, num_threads: Optional[int] = None):
        """
        Initialize parallel generator.
        
        Args:
            num_processes: Number of worker processes (default: CPU count)
            num_threads: Number of worker threads (default: CPU count * 2)
        """
        self.num_processes = num_processes or multiprocessing.cpu_count()
        self.num_threads = num_threads or multiprocessing.cpu_count() * 2
        
        # Executors
        self.process_executor = None
        self.thread_executor = None
        
        # Performance tracking
        self.stats = {
            'tasks_submitted': 0,
            'tasks_completed': 0,
            'total_mutations_generated': 0,
            'total_generation_time': 0.0,
            'average_task_time': 0.0
        }
        
        # Work queue for dynamic load balancing
        self.work_queue = queue.Queue()
        self.result_queue = queue.Queue()
    
    def __enter__(self):
        """Context manager entry."""
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.shutdown()
    
    def start(self):
        """Start the parallel generation system."""
        self.process_executor = ProcessPoolExecutor(max_workers=self.num_processes)
        self.thread_executor = ThreadPoolExecutor(max_workers=self.num_threads)
    
    def shutdown(self):
        """Shutdown the parallel generation system."""
        if self.process_executor:
            self.process_executor.shutdown(wait=True)
        if self.thread_executor:
            self.thread_executor.shutdown(wait=True)
    
    @staticmethod
    def _generate_string_batch(sequence: str, sizes: List[int]) -> List[str]:
        """Generate a batch of strings in a worker process."""
        results = []
        for size in sizes:
            if size <= 0:
                results.append("")
            elif len(sequence) == 0:
                results.append("")
            else:
                repeat_count = size // len(sequence)
                remainder = size % len(sequence)
                result = sequence * repeat_count + sequence[:remainder]
                results.append(result)
        return results
    
    @staticmethod
    def _generate_random_batch(min_length: int, max_length: int, count: int, seed: int) -> List[bytes]:
        """Generate a batch of random data in a worker process."""
        import random
        local_random = random.Random(seed)
        results = []
        
        for i in range(count):
            length = local_random.randint(min_length, max_length)
            if length <= 100:
                # Small data: byte by byte
                data = bytes(local_random.randint(0, 255) for _ in range(length))
            else:
                # Large data: batch generation
                random_ints = [local_random.randint(0, 255) for _ in range(length)]
                data = bytes(random_ints)
            results.append(data)
        
        return results
    
    def generate_strings_parallel(self, sequence: str, sizes: List[int], 
                                batch_size: int = 100) -> Iterator[str]:
        """
        Generate strings in parallel using multiple processes.
        
        Args:
            sequence: Base sequence to repeat
            sizes: List of target sizes
            batch_size: Number of strings per batch
            
        Yields:
            Generated strings
        """
        if not self.process_executor:
            raise RuntimeError("Parallel generator not started. Use with statement or call start().")
        
        start_time = time.time()
        
        # Split sizes into batches
        size_batches = [sizes[i:i + batch_size] for i in range(0, len(sizes), batch_size)]
        
        # Submit tasks to process pool
        futures = []
        for batch in size_batches:
            future = self.process_executor.submit(self._generate_string_batch, sequence, batch)
            futures.append(future)
            self.stats['tasks_submitted'] += 1
        
        # Collect results as they complete
        total_generated = 0
        for future in as_completed(futures):
            try:
                batch_results = future.result()
                for result in batch_results:
                    yield result
                    total_generated += 1
                
                self.stats['tasks_completed'] += 1
                
            except Exception as e:
                print(f"Error in parallel string generation: {e}")
        
        # Update statistics
        generation_time = time.time() - start_time
        self.stats['total_mutations_generated'] += total_generated
        self.stats['total_generation_time'] += generation_time
        if self.stats['tasks_completed'] > 0:
            self.stats['average_task_time'] = (
                self.stats['total_generation_time'] / self.stats['tasks_completed']
            )
    
    def generate_random_parallel(self, min_length: int, max_length: int, 
                                total_count: int, batch_size: int = 50) -> Iterator[bytes]:
        """
        Generate random data in parallel using multiple processes.
        
        Args:
            min_length: Minimum data length
            max_length: Maximum data length
            total_count: Total number of items to generate
            batch_size: Number of items per batch
            
        Yields:
            Generated random data
        """
        if not self.process_executor:
            raise RuntimeError("Parallel generator not started. Use with statement or call start().")
        
        start_time = time.time()
        
        # Calculate batches
        num_batches = (total_count + batch_size - 1) // batch_size
        
        # Submit tasks with different seeds for randomness
        futures = []
        for i in range(num_batches):
            count = min(batch_size, total_count - i * batch_size)
            seed = hash((min_length, max_length, i)) % (2**32)
            
            future = self.process_executor.submit(
                self._generate_random_batch, min_length, max_length, count, seed
            )
            futures.append(future)
            self.stats['tasks_submitted'] += 1
        
        # Collect results
        total_generated = 0
        for future in as_completed(futures):
            try:
                batch_results = future.result()
                for result in batch_results:
                    yield result
                    total_generated += 1
                
                self.stats['tasks_completed'] += 1
                
            except Exception as e:
                print(f"Error in parallel random generation: {e}")
        
        # Update statistics
        generation_time = time.time() - start_time
        self.stats['total_mutations_generated'] += total_generated
        self.stats['total_generation_time'] += generation_time
        if self.stats['tasks_completed'] > 0:
            self.stats['average_task_time'] = (
                self.stats['total_generation_time'] / self.stats['tasks_completed']
            )
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get performance statistics."""
        stats = self.stats.copy()
        
        if stats['total_generation_time'] > 0:
            stats['mutations_per_second'] = (
                stats['total_mutations_generated'] / stats['total_generation_time']
            )
        else:
            stats['mutations_per_second'] = 0
        
        stats['task_completion_rate'] = (
            stats['tasks_completed'] / stats['tasks_submitted'] * 100
            if stats['tasks_submitted'] > 0 else 0
        )
        
        return stats


class AsyncGenerator:
    """
    Asynchronous generator for overlapping I/O and computation.
    
    Features:
    - Producer-consumer pattern
    - Configurable buffer sizes
    - Backpressure handling
    - Graceful shutdown
    """
    
    def __init__(self, buffer_size: int = 1000):
        """
        Initialize async generator.
        
        Args:
            buffer_size: Size of internal buffer
        """
        self.buffer_size = buffer_size
        self.buffer = queue.Queue(maxsize=buffer_size)
        self.producers = []
        self.shutdown_event = threading.Event()
        
        # Statistics
        self.stats = {
            'items_produced': 0,
            'items_consumed': 0,
            'buffer_overflows': 0,
            'producer_threads': 0
        }
    
    def start_producer(self, generator_func: Callable, *args, **kwargs):
        """
        Start a producer thread.
        
        Args:
            generator_func: Function that generates items
            *args, **kwargs: Arguments for generator function
        """
        def producer_worker():
            try:
                for item in generator_func(*args, **kwargs):
                    if self.shutdown_event.is_set():
                        break
                    
                    try:
                        self.buffer.put(item, timeout=1.0)
                        self.stats['items_produced'] += 1
                    except queue.Full:
                        self.stats['buffer_overflows'] += 1
                        # Drop item or implement backpressure
                        
            except Exception as e:
                print(f"Producer error: {e}")
            finally:
                # Signal end of production
                try:
                    self.buffer.put(None, timeout=1.0)
                except queue.Full:
                    pass
        
        thread = threading.Thread(target=producer_worker, daemon=True)
        thread.start()
        self.producers.append(thread)
        self.stats['producer_threads'] += 1
    
    def consume(self, timeout: float = 1.0) -> Iterator[Any]:
        """
        Consume items from the buffer.
        
        Args:
            timeout: Timeout for getting items
            
        Yields:
            Generated items
        """
        active_producers = len(self.producers)
        
        while active_producers > 0 and not self.shutdown_event.is_set():
            try:
                item = self.buffer.get(timeout=timeout)
                
                if item is None:
                    # Producer finished
                    active_producers -= 1
                    continue
                
                yield item
                self.stats['items_consumed'] += 1
                
            except queue.Empty:
                # Check if we should continue waiting
                if all(not t.is_alive() for t in self.producers):
                    break
    
    def shutdown(self):
        """Shutdown the async generator."""
        self.shutdown_event.set()
        
        # Wait for producers to finish
        for producer in self.producers:
            producer.join(timeout=2.0)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get async generator statistics."""
        return {
            **self.stats,
            'buffer_utilization': self.buffer.qsize() / self.buffer_size * 100,
            'active_producers': sum(1 for t in self.producers if t.is_alive())
        }
