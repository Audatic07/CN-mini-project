import socket
import threading

from dnslib import DNSRecord


class DNSForwarder:
    """Round-robin upstream DNS forwarder with response validation."""

    def __init__(self, upstream_servers, timeout_sec=2, buffer_size=4096):
        if not upstream_servers:
            raise ValueError("upstream_servers must not be empty")

        self._upstream_servers = list(upstream_servers)
        self._timeout_sec = timeout_sec
        self._buffer_size = buffer_size
        self._index = 0
        self._lock = threading.Lock()

    def _next_server(self):
        with self._lock:
            server = self._upstream_servers[self._index]
            self._index = (self._index + 1) % len(self._upstream_servers)
            return server

    def forward(self, query_data, request_id):
        """Try each upstream server until one valid DNS reply is returned."""
        for _ in range(len(self._upstream_servers)):
            server = self._next_server()
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream_sock:
                    upstream_sock.settimeout(self._timeout_sec)
                    upstream_sock.sendto(query_data, server)
                    response, _ = upstream_sock.recvfrom(self._buffer_size)

                try:
                    upstream_record = DNSRecord.parse(response)
                except Exception:
                    continue

                if upstream_record.header.id != request_id:
                    continue

                return response
            except (socket.timeout, OSError):
                continue

        return None
