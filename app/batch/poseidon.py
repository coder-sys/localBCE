"""Shared Stark field modulus for current authority and boundary modules.

The retired synthetic Poseidon execution lane and its Rust helper lived here
previously.  Current direct-state and public-input boundaries need only the
field modulus; proof/hash execution belongs to a separately qualified profile.
"""

from __future__ import annotations


FIELD_MODULUS = 2**251 + 17 * 2**192 + 1


__all__ = ("FIELD_MODULUS",)
