import os


os.environ.setdefault("BL_PROVIDER_ALIAS_KEY", "BL_TEST_PROVIDER_ALIAS_KEY")
os.environ.setdefault("BL_DEV", "1")
os.environ.setdefault("BL_ALLOW_LOCAL_TEST_ORACLE_KEYS", "1")
os.environ.setdefault("BL_ALLOW_LOCAL_RULES_ENGINE_FALLBACK", "1")
os.environ.setdefault("BL_FORCE_PYTHON_RULES_ENGINE", "1")
