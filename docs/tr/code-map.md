# Kod Haritasi

## Ana Calisma Akisi

- `main.py`: scan, graph export ve report komutlarini yonetir.
- `cpg_loader.py`: Fraunhofer/AST-lite backend secimini ve graph yuklemeyi yapar.
- `models.py`: graph node, edge, normalized graph ve finding modellerini tanimlar.
- `utils.py`: path, JSON ve run klasoru yardimcilari.

## Graph Uretimi

- `ast_lite.py`: Python AST tabanli fallback graph builder.
- `tools/fraunhofer-exporter/.../Main.kt`: Docker icinde calisan Fraunhofer CPG exporter.
- `cpg_visualizer.py`: graph JSON, DOT ve HTML viewer uretir.

## Tespit ve Context

- `crypto_matcher_v2.py`: call node'larini crypto API mapping ile eslestirir.
- `context_extractor.py`: call chain, argument role, literal tracking, source/sink label ve data-flow kaniti ekler.

## CBOM Semantigi

- `algorithm_normalizer.py`: `Cipher(...)` gibi wrapper'lari AES, ChaCha20, mode, padding ve key size alanlarina cozer.
- `asset_classifier.py`: bulguyu `primary_asset`, `supporting_artifact` veya `ignore` olarak siniflandirir.
- `flow_analyzer.py`: key/data/iv/salt/randomness source alanlarini stabil sekilde uretir.
- `risk_engine.py`: risk level, confidence, tag ve derivation summary hesaplar.
- `rule_engine.py`: `config/rules_v2.json` kurallarini kosullu uygular.
- `inference_explainer.py`: usage context, intent, data flow ve derivation path kararlarini aciklar.
- `cbom_builder_v2.py`: final JSON'u toplar.

## Rapor ve Tekrar Uretilebilirlik

- `report_builder.py`: CBOM JSON'dan standalone HTML rapor uretir.
- `manifest.py`: run metadata ve config hash'lerini yazar.
