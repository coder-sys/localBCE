"""Small helpers for delivering public Mirror errors without raw context."""

from __future__ import annotations

from typing import NoReturn, TypeVar


_ErrorT = TypeVar("_ErrorT", bound=BaseException)


def raise_redacted(error_type: type[_ErrorT], message: str) -> NoReturn:
    """Raise one public error with no retained inner exception object."""

    try:
        raise error_type(message)
    except error_type as public_error:
        public_error.__cause__ = None
        public_error.__context__ = None
        public_error.__suppress_context__ = True
        raise
