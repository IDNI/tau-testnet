"""Token buckets for the RPC limiter and for limits on each key."""
import threading
import time
from collections import OrderedDict


class TokenBucket:
    """Token bucket over an injected clock.

    The clock is a parameter because the two transports measure time
    differently: the WebSocket loop runs under trio and must use
    `trio.current_time()`, while the TCP handler is a plain thread using
    `time.monotonic()`.

    Not thread-safe: the caller holds a lock or owns the instance alone.
    """

    __slots__ = ("capacity", "refill_per_second", "_tokens", "_last")

    def __init__(self, capacity: float, refill_per_second: float, now: float):
        self.capacity = capacity
        self.refill_per_second = refill_per_second
        self._tokens = capacity
        self._last = now

    def _refill(self, now: float) -> None:
        elapsed = max(0.0, now - self._last)
        self._last = now
        self._tokens = min(self.capacity, self._tokens + elapsed * self.refill_per_second)

    def take(self, now: float) -> bool:
        """Consume one token. False when the caller is over budget."""
        self._refill(now)
        if self._tokens < 1.0:
            return False
        self._tokens -= 1.0
        return True

    def has_credit(self, now: float) -> bool:
        self._refill(now)
        return self._tokens > 0.0

    def charge(self, amount: float, now: float) -> None:
        """Deduct `amount`. The balance can go below zero."""
        self._refill(now)
        self._tokens -= amount


class KeyedBuckets:
    """One TokenBucket for each key, behind one lock.

    At most `max_keys` buckets stay. The key used least recently goes first.
    """

    def __init__(self, capacity: float, refill_per_second: float, max_keys: int,
                 clock=time.monotonic):
        self.capacity = capacity
        self.refill_per_second = refill_per_second
        self.max_keys = max_keys
        self.clock = clock
        self._buckets: "OrderedDict[str, TokenBucket]" = OrderedDict()
        self._lock = threading.Lock()

    def _bucket(self, key: str, now: float) -> TokenBucket:
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = TokenBucket(self.capacity, self.refill_per_second, now)
            self._buckets[key] = bucket
            while len(self._buckets) > self.max_keys:
                self._buckets.popitem(last=False)
        else:
            self._buckets.move_to_end(key)
        return bucket

    def admit(self, key: str) -> bool:
        """True when the bucket of `key` is above zero. Takes nothing."""
        with self._lock:
            now = self.clock()
            return self._bucket(key, now).has_credit(now)

    def charge(self, key: str, amount: float) -> None:
        with self._lock:
            now = self.clock()
            self._bucket(key, now).charge(amount, now)

    def clear(self) -> None:
        with self._lock:
            self._buckets.clear()

    def __contains__(self, key: str) -> bool:
        with self._lock:
            return key in self._buckets

    def __len__(self) -> int:
        with self._lock:
            return len(self._buckets)
