"""One bound for every timing test: the timed call runs in a daemon thread and the test fails if it is still running after ten times
its expected time (at least 30 seconds), so a slow change fails in minutes and never hangs the run."""

import threading
import time


def timed(call, expected: float = 3.0):
    """(seconds, result) of ``call()``; AssertionError if it is still running after max(30, 10 * expected) seconds (its thread is left to die with the process)."""
    box: dict = {}

    def go():
        t0 = time.perf_counter()
        try:
            box["result"] = call()
        except BaseException as error:  # noqa: BLE001 - handed to the test thread
            box["error"] = error
        box["seconds"] = time.perf_counter() - t0

    limit = max(30.0, 10 * expected)
    thread = threading.Thread(target=go, daemon=True)
    thread.start()
    thread.join(limit)
    if thread.is_alive():
        raise AssertionError(f"still running after {limit:.0f}s, ten times its expected time: too slow")
    if "error" in box:
        raise box["error"]
    return box["seconds"], box["result"]
