import time
import threading
from collections import defaultdict


class RateLimiter:
    def __init__(self, max_requests=100, window_seconds=60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(list)
        self.blocked = {}
        self.block_duration = 300
        self.lock = threading.Lock()

    def check(self, ip):
        now = time.time()
        with self.lock:
            if ip in self.blocked:
                if now < self.blocked[ip]:
                    return False, int(self.blocked[ip] - now)
                del self.blocked[ip]

            window = self.requests.get(ip, [])
            window = [t for t in window if now - t < self.window_seconds]
            self.requests[ip] = window

            if len(window) >= self.max_requests:
                self.blocked[ip] = now + self.block_duration
                return False, self.block_duration

            self.requests[ip].append(now)
            return True, 0

    def get_stats(self, ip):
        now = time.time()
        window = [t for t in self.requests.get(ip, []) if now - t < self.window_seconds]
        return {
            "ip": ip,
            "current_count": len(window),
            "max_allowed": self.max_requests,
            "blocked": ip in self.blocked and now < self.blocked[ip],
            "blocked_until": int(self.blocked.get(ip, 0))
        }


rate_limiter = RateLimiter()
