# Uygulama Notları

## Fraunhofer CPG Python Ön Ucu

- Python ön ucu, JVM tarafı kurulumu ve `jep` kitaplığını gerektirir (Docker'da sarılır).
- Docker, tutarlı Java/Python uyumluluğu için **tercih edilen yürütme yoludur**.
- Python paketi, Fraunhofer JVM sınıflarına doğrudan bağımlı değildir; iletişim alt işlem JSON alışverişi aracılığıyla gerçekleşir.

## CPG İhraçcı Davranışı

Mevcut uygulama, gerçek Fraunhofer `TranslationManager` geçişini ilk olarak dener:

1. Alt işlem `java -jar exporter.jar --input ... --output ...` başlatır
2. İhraçcı normalize edilmiş JSON'u çıktı dosyasına yazar
3. Python yükleyicisi JSON'u `NormalizedGraph` olarak okur ve doğrular

Mevcut Docker görüntülerinde, Java/Python sınırı JEP başlatma hatalarına neden olabilir. Python CLI bunu bir alt işlemde izole eder ve `--backend fraunhofer` kullanıldığında (sıkı mod olmadan) otomatik olarak `ast-lite`'ye geri döner.

## Veri Akışı Çıkarma Stratejisi

Fraunhofer CPG'nin Python ön ucu, gerçek kodda karşılaşılan her kaynak-lavabo deseninin tam işlemler arası veri akışını garantilemez. Bu nedenle:

1. **Grafik kenarları önce**: İhraçcı tarafından yayıldığında DFG, DATA_FLOW, REACHES kenarlarını izleyin.
2. **Yerel analiz geri dönüş**: Kaynak işlevin AST denetletimesi aracılığıyla atama kökenlerini ve işlev parametresi kökenlerini çıkarın.
3. **Birleştirilmiş kanıt**: Hem grafik tabanlı hem de yerel analiz kaynaklarını `sources_reaching_sink` içinde bildirin.

Bu hibrit yaklaşım, Fraunhofer'ın işlemler arası analizi eksik olduğunda bile veri akışı kanıtını yakaladığımızı sağlar.

## CBOM Uyumluluğu

Kriptografik bileşen kütü oluşturmada (CBOM) standartlarının tam uyumluluğu, tespit modeli stabilize olana kadar kasıtlı olarak ertelenir. Mevcut sürüm, CBOM ilkeleriyle uyumlu **CryptoGraph özel şeması** kullanır:

- Her bulgu için kararlı `asset_id`
- Üst düzey bölümler: `crypto_metadata`, `usage`, `context`, `flow`, `control`, `risk`, `evidence`
- `primitive` (AES, RSA, MD5, vb.) ve `operation` (şifrele, özet, imzala, vb.)
- Birden çok işaretten türetilen risk güveni (API eşleştirme, kaynak bağlamı, veri akışı, kural eşleştirmeleri)

## Grafik Normalizasyon İşlem Hattı

```
Fraunhofer CPG → İhraçcı JSON → NormalizedGraph
AST → ast-lite oluşturucu → NormalizedGraph
```

Her iki yol da aynı JSON yapısını üretir; bu, aşağı akış kodunun backend'den bağımsız olmasını sağlar. `backend` alanı düğüm seviyesinde kökenini izler.

## Hata Ayıklama

Backend seçimini ve ihraçcı durumunu görmek için ayrıntılı çıktıyı etkinleştirin:

```bash
export CRYPTOGRAPH_DEBUG=1
cryptograph scan --input samples --output result.json
```

Geri dönüş iletileri için `stderr` çıktısını kontrol edin. CPG verilerine tam erişim için:

```bash
cryptograph graph --input samples --output cpg.json --html cpg.html
```

## Performans Göz Önünde Bulundurması

- **Grafik oluşturma**: Fraunhofer ihraçcı zamanı Java başlatması (~1–2 saniye) ve kaynak ayrıştırması (kodtaban boyutuyla ölçeklenir) tarafından baskın.
- **Eşleştirme**: Kripto eşleştirici, düğüm ve kural sayısında O(n)'dir; küçük ila orta kodtabanlar için tipik olarak < 100 ms.
- **Veri akışı**: BFS, MAX_DATAFLOW_DEPTH=24 sınırı ile üstel artışı önler.
- **Bellek**: Tam grafik bellekte tutulur; çok büyük kodtabanlar için, grafik bölüntülü ayrıştırmayı uygulamayı düşünün (scale-notes.md bölümüne bakın).

## Test Etme

Yerel testler, hızlı yineleme için `--backend ast-lite` kullanır:

```bash
pytest tests/test_pipeline.py -v
```

Fraunhofer ile tam işlem hattı testleri Docker ve Java kurulumu gerektirir:

```bash
docker compose run --rm cryptograph pytest
```
