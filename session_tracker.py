"""Thread-safe, reference-counted session state for local diagnostics."""

import threading


class SessionTrackerRegistry:
    def __init__(self, factory):
        self._factory = factory
        self._lock = threading.RLock()
        self._entries = {}

    def acquire(self, session):
        with self._lock:
            entry = self._entries.get(session)
            tracker, references = entry if entry is not None else (self._factory(), 0)
            self._entries[session] = (tracker, references + 1)
            return tracker

    def release(self, session):
        with self._lock:
            entry = self._entries.get(session)
            if entry is None:
                return
            tracker, references = entry
            if references <= 1:
                self._entries.pop(session, None)
            else:
                self._entries[session] = (tracker, references - 1)
