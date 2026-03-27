import threading
import time

from dnslib import DNSRecord


class DNSCache:
    """Thread-safe DNS response cache with per-record expiry timestamps."""

    def __init__(self):
        self._cache = {}
        self._lock = threading.Lock()

    def get(self, domain):
        """Return a cached response if valid; remove and miss on expiry."""
        now = time.time()
        with self._lock:
            item = self._cache.get(domain)
            if not item:
                return None

            response, expiry = item
            if now < expiry:
                return response

            del self._cache[domain]
            return None

    def set(self, domain, response, ttl):
        """Store a packed DNS response using ttl seconds from now."""
        ttl = max(1, int(ttl))
        with self._lock:
            self._cache[domain] = (response, time.time() + ttl)


def extract_ttl(response_data, fallback_ttl=60):
    """Extract a positive TTL from DNS answers, or return the fallback."""
    try:
        parsed = DNSRecord.parse(response_data)
        ttls = [rr.ttl for rr in parsed.rr if rr.ttl > 0]
        if ttls:
            return min(ttls)
    except Exception:
        pass

    return fallback_ttl
