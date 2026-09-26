import os

os.environ.setdefault("RIGHTRAIL_CHECK_ROW_CACHE", "1")  # the Owner recounts every history table after each write and compares its cache
