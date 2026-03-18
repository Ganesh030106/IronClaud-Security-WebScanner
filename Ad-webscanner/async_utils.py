"""
Async utilities for Streamlit + asyncio integration
Manages async operations in Streamlit's synchronous context
"""

import asyncio
import nest_asyncio
import streamlit as st
from typing import Callable, Any, List, Coroutine, Optional
import logging
from functools import wraps

# Apply nest_asyncio to allow re-entrant event loops
nest_asyncio.apply()

logger = logging.getLogger(__name__)

class AsyncExecutor:
    """Safely execute async code in Streamlit's synchronous context"""
    
    @staticmethod
    def run_async(async_func: Callable, *args, **kwargs) -> Any:
        """
        Execute an async function in Streamlit's synchronous context.
        
        Usage:
            result = AsyncExecutor.run_async(my_async_function, arg1, arg2)
        
        Args:
            async_func: Async function to execute
            *args: Positional arguments for async function
            **kwargs: Keyword arguments for async function
            
        Returns:
            Result from async function or None if error
        """
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(async_func(*args, **kwargs))
            return result
        except Exception as e:
            logger.error(f"❌ Async execution failed: {e}")
            st.error(f"⚠️ Scan error: {str(e)[:100]}")
            return None
        finally:
            try:
                loop.close()
            except:
                pass
    
    @staticmethod
    async def gather_with_timeout(
        *tasks: Coroutine, 
        timeout: int = 30,
        description: str = "Processing"
    ) -> List[Any]:
        """
        Run multiple coroutines with timeout protection.
        
        Args:
            *tasks: Coroutines to run
            timeout: Timeout in seconds
            description: Description for logging
            
        Returns:
            List of results (None for failed tasks)
        """
        try:
            async with asyncio.timeout(timeout):
                results = await asyncio.gather(*tasks, return_exceptions=True)
                return results
        except asyncio.TimeoutError:
            logger.warn(f"⏱️ {description} timed out after {timeout}s")
            return [None] * len(tasks)
        except Exception as e:
            logger.error(f"❌ {description} failed: {e}")
            return [None] * len(tasks)

class RetryPolicy:
    """Configurable retry logic with exponential backoff"""
    
    def __init__(
        self, 
        max_retries: int = 3, 
        base_delay: float = 0.5,
        backoff_multiplier: float = 2.0,
        jitter: bool = True
    ):
        """
        Initialize retry policy.
        
        Args:
            max_retries: Maximum number of attempts
            base_delay: Initial delay in seconds
            backoff_multiplier: Factor to multiply delay by each retry
            jitter: Add randomness to avoid thundering herd
        """
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.backoff_multiplier = backoff_multiplier
        self.jitter = jitter
    
    async def execute(
        self, 
        async_func: Callable, 
        *args,
        description: str = "Operation",
        **kwargs
    ) -> Optional[Any]:
        """
        Execute with automatic retry on failure.
        
        Args:
            async_func: Async function to execute
            *args: Positional arguments
            description: Description for logging
            **kwargs: Keyword arguments
            
        Returns:
            Result or None if all retries failed
        """
        for attempt in range(self.max_retries):
            try:
                result = await async_func(*args, **kwargs)
                if attempt > 0:
                    logger.info(f"✅ {description} succeeded on retry {attempt + 1}")
                return result
                
            except asyncio.TimeoutError:
                if attempt == self.max_retries - 1:
                    logger.error(f"❌ {description} timed out after {self.max_retries} attempts")
                    return None
                
                delay = self.base_delay * (self.backoff_multiplier ** attempt)
                if self.jitter:
                    import random
                    delay *= (0.5 + random.random())  # Jitter: 0.5-1.5x
                
                logger.warn(f"⏱️ {description} attempt {attempt + 1} timed out, retrying in {delay:.1f}s...")
                await asyncio.sleep(delay)
                
            except Exception as e:
                if attempt == self.max_retries - 1:
                    logger.error(f"❌ {description} failed after {self.max_retries} attempts: {e}")
                    return None
                
                delay = self.base_delay * (self.backoff_multiplier ** attempt)
                if self.jitter:
                    import random
                    delay *= (0.5 + random.random())
                
                logger.warn(f"⚠️ {description} attempt {attempt + 1} failed ({str(e)[:50]}), retrying...")
                await asyncio.sleep(delay)
        
        return None

class AsyncProgressTracker:
    """Track and display async task progress in Streamlit"""
    
    def __init__(self, total_steps: int, container=None):
        """
        Initialize progress tracker.
        
        Args:
            total_steps: Total number of steps
            container: Streamlit container for progress display
        """
        self.total_steps = total_steps
        self.current_step = 0
        self.container = container or st.container()
        
        with self.container:
            self.progress_bar = st.progress(0)
            self.status_text = st.empty()
    
    def update(self, step_num: int, message: str = ""):
        """Update progress display"""
        self.current_step = step_num
        progress = min(step_num / self.total_steps, 1.0)
        
        with self.container:
            self.progress_bar.progress(progress)
            if message:
                self.status_text.text(f"📊 [{step_num}/{self.total_steps}] {message}")
    
    def complete(self, message: str = "Scan complete!"):
        """Mark as complete"""
        with self.container:
            self.progress_bar.progress(1.0)
            self.status_text.text(f"✅ {message}")

def async_timer(func: Callable) -> Callable:
    """Decorator to measure async function execution time"""
    @wraps(func)
    async def wrapper(*args, **kwargs):
        import time
        start = time.time()
        try:
            result = await func(*args, **kwargs)
            duration = time.time() - start
            logger.info(f"⏱️ {func.__name__} completed in {duration:.2f}s")
            return result
        except Exception as e:
            duration = time.time() - start
            logger.error(f"❌ {func.__name__} failed after {duration:.2f}s: {e}")
            raise
    return wrapper

class AsyncHTTPSession:
    """Wrapper around httpx.AsyncClient with sensible defaults for scanning"""
    
    def __init__(
        self,
        timeout: float = 10.0,
        connect_timeout: float = 5.0,
        http2: bool = True,
        verify_ssl: bool = False,
        follow_redirects: bool = True,
        max_redirects: int = 5
    ):
        """Initialize HTTP session"""
        import httpx
        
        timeout_config = httpx.Timeout(timeout, connect=connect_timeout)
        self.client = None
        self.config = {
            'timeout': timeout_config,
            'http2': http2,
            'verify': verify_ssl,
            'follow_redirects': follow_redirects,
            'limits': httpx.Limits(max_redirects=max_redirects)
        }
    
    async def __aenter__(self):
        """Async context manager entry"""
        import httpx
        self.client = httpx.AsyncClient(**self.config)
        return self.client
    
    async def __aexit__(self, *args):
        """Async context manager exit"""
        if self.client:
            await self.client.aclose()

# Convenience function for batch async operations
async def batch_execute(
    tasks: List[Coroutine],
    batch_size: int = 10,
    delay_between_batches: float = 0.5
) -> List[Any]:
    """
    Execute coroutines in batches with delay between batches.
    Useful for rate limiting.
    
    Args:
        tasks: List of coroutines
        batch_size: Number of concurrent tasks per batch
        delay_between_batches: Delay between batches in seconds
        
    Returns:
        List of results
    """
    results = []
    
    for i in range(0, len(tasks), batch_size):
        batch = tasks[i:i+batch_size]
        batch_results = await asyncio.gather(*batch, return_exceptions=True)
        results.extend(batch_results)
        
        if i + batch_size < len(tasks):
            await asyncio.sleep(delay_between_batches)
    
    return results
