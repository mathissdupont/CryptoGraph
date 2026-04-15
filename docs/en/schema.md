# CBOM Schema

CryptoGraph emits `cryptograph-custom-v2` with `spec_version` `1.0`.

## Top Level

```json
{
  "cbom_format": "cryptograph-custom-v2",
  "spec_version": "1.0",
  "metadata": {},
  "analysis": {},
  "cryptographic_assets": [],
  "supporting_artifacts": [],
  "summary": {}
}
```

## Primary Assets

`cryptographic_assets` contains first-class cryptographic operations:
- encryption and decryption
- key generation
- key derivation
- hashing
- HMAC/message authentication
- random material generation
- signing and verification
- certificate management

## Supporting Artifacts

`supporting_artifacts` contains crypto-adjacent objects that are useful evidence but should not inflate the primary CBOM:
- `x509.Name`
- `x509.NameAttribute`
- certificate extensions
- cipher mode objects such as `modes.CBC`
- serialization/backend helpers

## Asset Shape

```json
{
  "asset_id": "crypto-...",
  "asset_class": "primary_asset",
  "crypto_metadata": {
    "algorithm": "AES",
    "primitive": "symmetric_encryption",
    "mode": "CBC",
    "padding": "unknown",
    "provider": "cryptography",
    "key_size": 256
  },
  "usage": {
    "operation": "encryption",
    "intent": "encrypt_data"
  },
  "context": {
    "file": "basic_symmetric.py",
    "function": "basic_symmetric.encrypt_simple_data",
    "line": 21,
    "call_chain": ["basic_symmetric.encrypt_simple_data"]
  },
  "flow": {
    "key_source": "function_parameter",
    "data_source": "external_input",
    "iv_source": "unknown",
    "salt_source": null,
    "randomness_source": null,
    "sink": {"type": "crypto_sink", "id": "crypto_operation"}
  },
  "control": {},
  "graph_context": {},
  "risk": {},
  "rules": [],
  "inference": {},
  "evidence": {"summary": {}, "debug": {}}
}
```

## Unknown vs Null

Use `unknown` when a field applies but the analysis cannot resolve it.

Use `null` when the field is not applicable. Example: `salt_source` is null for normal AES encryption, but unknown for a KDF when the salt cannot be resolved.
