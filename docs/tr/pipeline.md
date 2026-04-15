# CryptoGraph Islem Hatti

CryptoGraph, Python kaynak kodunu grafik destekli ozel CBOM ciktisina donusturur. Akis alti ana adimdan olusur.

## 1. CLI Girisi

Dosya: `src/cryptograph/main.py`

`scan` komutu run klasorunu belirler, graph backend'ini calistirir, kripto API cagrilarini bulur, context'i zenginlestirir, CBOM'u uretir, HTML raporu ve manifest dosyasini yazar.

## 2. Graph Yukleme

Dosyalar:
- `src/cryptograph/cpg_loader.py`
- `tools/fraunhofer-exporter/src/main/kotlin/io/cryptograph/exporter/Main.kt`
- `src/cryptograph/ast_lite.py`

Ana hedef Fraunhofer CPG'dir. Fraunhofer; function, call, callee, argument, data-flow ve call edge bilgilerini normalize edilmis grafa cevirir. `ast-lite`, hizli lokal gelistirme icin Python AST tabanli yedek backend'dir.

## 3. Crypto API Esleme

Dosya: `src/cryptograph/crypto_matcher_v2.py`

Matcher, graph icindeki call node'larini `config/api_mappings.json` ile eslestirir ve `CryptoFinding` objeleri uretir. Bu asamada bulgu hala wrapper seklinde olabilir: mesela `Cipher` bulunur ama gercek algoritma `AES` olabilir.

## 4. Context Zenginlestirme

Dosya: `src/cryptograph/context_extractor.py`

Bu katman sunlari ekler:
- `CALLS` edge'lerinden call chain
- key, data, iv, salt, randomness gibi argument rolleri
- gercek literal ile identifier/call ayrimi
- local assignment ve function parameter origin bilgisi
- `DFG`, `DATA_FLOW`, `REACHES` edge'leriyle graph destekli data-flow
- `config/source_sinks.json` ile source/sink etiketleri

## 5. Semantik CBOM Katmanlari

Dosyalar:
- `src/cryptograph/algorithm_normalizer.py`
- `src/cryptograph/asset_classifier.py`
- `src/cryptograph/flow_analyzer.py`
- `src/cryptograph/risk_engine.py`
- `src/cryptograph/rule_engine.py`
- `src/cryptograph/inference_explainer.py`
- `src/cryptograph/cbom_builder_v2.py`

Bu katmanlar ham bulguyu daha anlamli hale getirir:
- wrapper API'ler gercek algoritma ve moda cozulur
- primary crypto asset ile supporting artifact ayrilir
- flow alanlari `unknown` ve `null` ayrimina gore net tutulur
- risk; algoritma, mod, key size, kaynak kalitesi ve parametrelere gore hesaplanir
- inference alanlari kararlarin nedenini aciklar

## 6. Cikti

Her scan ayri bir run klasorune yazilir:

```text
output/run-YYYYMMDDTHHMMSSZ-xxxxxxxx/
  result.json
  report.html
  manifest.json
```

Ana cikti JSON dosyasidir. HTML rapor okuma kolayligi saglar. Manifest ise tekrar uretilebilirlik icin config hash'lerini ve graph ozetini tutar.
