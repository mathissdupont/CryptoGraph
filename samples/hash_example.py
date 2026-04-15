import hashlib
import hmac


def digest_payload(payload, key):
    legacy = hashlib.md5(payload).hexdigest()
    modern = hashlib.sha256(payload).hexdigest()
    tag = hmac.new(key, payload, "sha256").digest()
    return legacy, modern, tag

