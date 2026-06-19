from __future__ import annotations

import hashlib
import hmac
import os

from app.canonical_encoding import canonical_record


PROVIDER_ALIAS_KEY_ENV = "BL_PROVIDER_ALIAS_KEY"


def provider_payment_alias(provider_npi: str, provider_name: str) -> str:
    key = os.environ.get(PROVIDER_ALIAS_KEY_ENV)
    if not key:
        raise RuntimeError(f"missing required provider alias key: {PROVIDER_ALIAS_KEY_ENV}")
    payload = canonical_record("provider_payment_alias", [provider_npi, provider_name])
    digest = hmac.new(key.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return f"provider_payment_key:{digest}"
