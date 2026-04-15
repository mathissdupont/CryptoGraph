# CBOM Semasi

CryptoGraph `cryptograph-custom-v2` ve `spec_version` `1.0` uretir.

## Ust Seviye

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

`cryptographic_assets` gercek kriptografik operasyonlari tutar:
- encryption/decryption
- key generation
- key derivation
- hashing
- HMAC/message authentication
- random material generation
- signing/verification
- certificate management

## Supporting Artifacts

`supporting_artifacts`, kanit icin faydali ama ana CBOM'u sisirmemesi gereken yapilari tutar:
- `x509.Name`
- `x509.NameAttribute`
- certificate extension objeleri
- `modes.CBC` gibi cipher mode objeleri
- serialization/backend yardimcilari

## Asset Yapisi

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

## Unknown ve Null Ayrimi

`unknown`, alan bu operasyon icin anlamli ama analiz cozemedi demektir.

`null`, alan bu operasyon icin uygulanamaz demektir. Ornek: normal AES encryption icin `salt_source` null olur; KDF icin salt varsa ama kaynagi bulunamiyorsa unknown olur.
