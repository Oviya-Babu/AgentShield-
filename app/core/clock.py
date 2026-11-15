"""Injectable clock – makes time deterministic in tests."""

from __future__ import annotations

from datetime import datetime, timezone


class Clock:
    """Default wall-clock implementation."""

    def now(self) -> datetime:
        """Return the current UTC time."""
        return datetime.now(timezone.utc)


# Module-level instance ---------------------------------------------------
_clock: Clock = Clock()


def get_clock() -> Clock:
    """Return the active clock instance."""
    return _clock


def set_clock(clock: Clock) -> None:
    """Replace the active clock (useful for deterministic testing)."""
    global _clock
    _clock = clock
