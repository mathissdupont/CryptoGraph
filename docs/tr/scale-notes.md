# CryptoGraph'ı Büyük Depolara Ölçeklendirme

CryptoGraph, çok satırlı depoları birkaç milyona ölçeklemekten oyuncak örneklerine kadar ölçeklemek için mimarisi sağlanmıştır. MVP, büyük yeniden yapılandırmalar olmadan büyümeyi etkinleştiren ölçeklenebilirlik ilk tasarım kararlarını içerir.

## MVP Ölçekleme Stratejisi

### Dosya Dosya Taraması

- Giriş dizinlerini tek bir tek yapı belleğinde grafik oluşturmak yerine **dosya dosyasına göre** işleyin.
- Her dosya, normalize edilmiş grafiğin bir parçasını oluşturur.
- Parçalar bağımsız olarak işlenebilir ve önbelleğe alınabilir.

### Normalize Edilmiş Grafik Sınırı

- CPG oluşturma (Fraunhofer veya AST-lite) bir `load_graph()` arabirimi arkasında izole edilir.
- Tüm aşağı akış analizi (eşleştirme, veri akışı, CBOM oluşturma) normalize edilmiş JSON üzerinde çalışır.
- Bu sınır **backend değişimini** ve **paralelleştirmesini** analiz kodunu değiştirmeden sağlar.

### Çalıştırma Başına Yapı Gruplaması

Bir taramanın tüm çıktıları bir zaman damgalı çalıştırma dizini altında gruplandırılır:

```
output/run-YYYYMMDDTHHMMSSZ-xxxxxxxx/
  ├── cpg.json (veya bölünmüş: cpg-shard-*.json)
  ├── result.json
  ├── report.html
  └── manifest.json
```

Faydaları:
- Büyük taramalar gözden geçirilebilir (ilgisiz çalıştırmalar karışık değil).
- Yeniden deneme dostu: başarısız parçalar tam girdi yeniden işlemesi olmadan yeniden çalıştırılabilir.
- Aşamalı çıktı: bulgular parçalar arasında toplanabilir.

### Tek Yapılı Grafik Nesnelerinden Kaçınma

- Eşleştirme mantığı, tek bir bellek içi JVM grafik nesnesine **bağlı değildir**.
- Tüm grafik sorguları JSON'dan düğüm/kenar aramaları kullanır (Java nesne işaretçileri yok).
- Bu, backend değişimini ve bağımsız parça işlemesini sağlar.

## Sonraki Ölçekleme Adımları

### 1. Büyük Depoları için Shard Bildirileri

Büyük depoları boyut sınırasına uydurulmuş parçalara bölün:

```
manifest.json
├── shards: [
│   { "id": "shard-0", "file_count": 500, "node_count": 12000, ... },
│   { "id": "shard-1", "file_count": 500, "node_count": 11500, ... },
│   ...
│  ]
├── aggregated_findings: { "HIGH": 42, "MEDIUM": 156, ... }
```

### 2. Shard Başına Bulgu Dışa Aktarması

Toplanmadan önce, shard başına bulgu dosyalarını yayın:

```
output/run-xxx/findings-shard-0.json
output/run-xxx/findings-shard-1.json
output/run-xxx/findings-aggregated.json
```

Şunları sağlar:
- Paralel bulgu çoğaltma kaldırılması
- Aşamalı CBOM oluşturma
- Başarısız parçalar için daha kolay yeniden deneme mantığı

### 3. Aşamalı Taramalar için Dosya Karması

Dosya SHA-256'yi bildirimde izleyin:

```json
{
  "run_timestamp": "...",
  "files": [
    { "path": "src/auth.py", "sha256": "abc123...", "change_type": "modified|added|unchanged" }
  ]
}
```

Aşamalı taramaları etkinleştirin:
- Değiştirilmemiş dosyaları atla
- Yalnızca değiştirilen dosyaları yeniden işleyin
- Eski ve yeni bulguları birleştir

### 4. CPG Dışa Aktarması için İşçi Kuyrukları

CPG oluşturmayı işçiler arasında dağıtın:

```python
# Sözde Kod
queue = FileQueue(input_directory)
workers = [ExporterWorker(queue) for _ in range(cpu_count())]
for worker in workers:
    worker.start()

# Her işçi:
# - Kuyruktan bir dosya çıkarır
# - Fraunhofer veya ast-lite çalıştırır
# - Normalize edilmiş grafik parçası yazar
# - Toplanmış bulgular için kuyruk
```

Göz Önünde Bulundurması:
- Fraunhofer JVM başlatma ek yükü (~1–2 saniye işlem başına); işçi başına dosyaları toplu işlem yaparak amortize.
- Kilitsiz grafik parça birliği (her işçi bağımsızdır).

### 5. Grafik/Bulgu Yapılar için Dayanıklı Depolama

Ara yapıları kalıcı depolamada saklayın:

```
s3://cryptograph-artifacts/run-xxx/
├── cpg-shard-0.json
├── cpg-shard-1.json
├── findings-shard-0.json
├── findings-shard-1.json
└── manifest.json
```

Faydaları:
- Yeniden denenebilir taramalar: tam yeniden dışa aktarma olmadan başarısız analiz aşamalarını yeniden çalıştırın.
- Denetim izi: uyum için tarihsel grafik verilerini saklayın.
- Dağıtılmış işleme: işçiler yapılar bulut depolamadan alabilir/itebilir.

### 6. Meta Verilerle Bildiri Çalıştırması

`manifest.json` aşağıdakileri içerecek şekilde genişletin:

```json
{
  "tool_version": "0.2.0",
  "backend": "fraunhofer",
  "source_hash": "depo SHA-256",
  "shard_count": 12,
  "generation_seconds": 142,
  "matching_seconds": 18,
  "aggregate_findings_by_risk": { "HIGH": 52, "MEDIUM": 201, ... },
  "config_hashes": {
    "api_mappings.json": "...",
    "rules.json": "...",
    "source_sinks.json": "..."
  }
}
```

Bu şunları sağlar:
- Sürüm izleme ve yeniden üretilebilirlik
- Performans atribüsyonu (hangi aşama en uzun sürüp aldı?)
- Config değişim tespiti (config değiştiyse yeniden çalıştır)

## Performans Hedefleri

| İşlem | Hedef | Cari |
|-----------|--------|---------|
| CPG oluşturma (1k LOC) | < 500 ms | ~1–2 s (JVM başlatma) |
| Eşleştirme (1k düğüm) | < 100 ms | ~ 50 ms |
| Veri akışı BFS bulgu başına | < 50 ms | ~ 10 ms |
| Tam işlem hattı (10k LOC) | < 30 s | ~ 15 s (ast-lite) |

JVM başlatması Fraunhofer zamanını baskın; işçi toplu işlemesi ve aşamalı işleme büyük kodtabanlar için kritiktir.

## Dağıtım Kontrol Listesi

- [ ] Çalıştırma başına dizin yapısı uygulaması
- [ ] Düğüm/kenar/bulgu sayılarıyla bildiri oluşturma ekleyin
- [ ] Shard bölme mantığı uygulayın
- [ ] Shard başına CPG dışa aktarması ve bulgu çıktısı uygulayın
- [ ] Aşamalı taramalar için dosya karması uygulaması
- [ ] İşçi kuyruğu altyapısı kurun
- [ ] Bulut depolama entegrasyonu ekleyin (isteğe bağlı)
- [ ] Bildiri sürümlendirilmesi ve meta veri izlemesi uygulayın
- [ ] Performans enstrümantasyonu ekleyin (aşama başına zamanlamalar)
- [ ] Çok shard tarama işlemleri için runbook belgelendiri
