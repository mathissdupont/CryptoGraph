# Mimari

CryptoGraph, grafik oluşturmayı kriptografik analizden ayırarak, CPG oluşturmaya adanmış izole backend bileşenleriyle katmanlı bir işlem hattı kullanır.

## Temel Tasarım İlkeleri

- **Backend izolasyonu**: Fraunhofer AISEC CPG Java dahili işlevleri bir yükleyici arabirimi arkasına sarılır; eşleştirme motoru asla JVM sınıflarına doğrudan bağımlı değildir.
- **Normalize edilmiş grafik sınırı**: Tüm kripto analizi, backend'ten (Fraunhofer veya AST-lite) bağımsız bir tekdüze JSON grafik temsili üzerinde çalışır.
- **Grafik destekli değişken izleme**: Veri akışı, uygun olduğunda normalize edilmiş grafik kenarlarını (DFG, DATA_FLOW, REACHES) izler; mevcut olmadığında yerel atama/fonksiyon-parametre orijini çıkarmaya geri döner.
- **Yeniden üretilebilirlik**: Docker kapsülleme, ortamlar arasında tutarlı Java/Python uyumluluğu sağlar.

## Backend'ler

### Fraunhofer AISEC CPG

Tercih edilen üretim backend'i. Java 11+ JVM ve Fraunhofer CPG ihraçcı JAR'ı gerektirir. Python ön uç, alt işlem yürütmesi aracılığıyla iletişim kurar ve doğrudan JVM bağlaşmasını önler.

- **Geri dönüş davranışı**: İhraçcı mevcut değilse veya çökerse, CLI `--backend fraunhofer-strict` belirtilmediği sürece `ast-lite`'ye otomatik geri dönüş denemesi yapar.
- **Sıkı mod**: `fraunhofer-strict` herhangi bir CPG oluşturma hatasında hemen başarısız olur; doğrulama ve CI/CD işlem hatlarında uygun.

### AST-lite Geri Dönüş

Normalize edilmiş grafik şeklini koruyan hafif bir Python AST tabanlı geri dönüş. Şu durumlarda kullanılır:
- Fraunhofer ihraçcı mevcut değil
- JVM başlatma başarısız olur
- Geliştirme, Fraunhofer kurulumu olmadan hızlı yineleme gerektirir

Python AST geçişi nedeniyle daha düşük kaliteli veri akışı bilgisi üretir.

### Sabit Backend Etiketleri

- `fraunhofer`: Yalnızca CPG verisi.
- `fraunhofer-fallback:ast-lite`: İhraçcı mevcut değil; ast-lite kullanıldı.
- `fraunhofer-failed:ast-lite`: İhraçcı çöktü; kullanılabilirliğe rağmen geri dönüş uygulandı.

## Normalize Edilmiş Grafik Modeli

Normalize edilmiş grafik JSON, Fraunhofer ve AST-lite çıktılarını tekdüze bir şemaya normalleştirir.

### Düğümler

Semantik kod öğelerini temsil eder:
- `id`: Kararlı benzersiz tanımlayıcı (node_ref formatı).
- `kind`: Düğüm türü (çağrı, çağrılan, işlev, bağımsız değişken, değişken, atama, dönüş, hazır değer).
- `name`: Kısa isim (API adı, işlev adı veya değişken adı).
- `properties`:
  - `file`, `line`, `column`: Kaynak konumu.
  - `function`: İçeren işlev adı.
  - `resolved_name`: Tam nitelikli ad (genellikle Fraunhofer'dan).
  - `callee`: Bir çağrının hedefi (çağrı düğümü özelliği).
  - `arguments`, `keywords`: Çağrı sitesi bağımsız değişken listesi ve anahtar sözcük bağımsız değişkenleri.
  - `literal_arguments`: Hazır değer bağımsız değişkenlerinden dize değerleri.
  - `backend`: Köken (fraunhofer veya ast-lite).

### Kenarlar

Düğümler arasında yönetilen ilişkiler:

**AST/CFG kenarları:**
- `CALLS`: İşlev çağrısı ilişkisi.
- `AST`: Soyut sözdizimi ağacı ebeveyn-çocuk.
- `ARGUMENT`: Bir çağrıda bağımsız değişken konumu.
- `RETURN`: Dönüş değeri akışı.

**Veri akışı kenarları (grafik destekli):**
- `DFG`: Fraunhofer'dan veri akışı grafik kenarı.
- `DATA_FLOW`: Alternatif veri akışı kenar etiketi.
- `REACHES`: Tanımı ulaşan kenar.

**Kontrol akışı:**
- `EOG`: Değerlendirilen sıra grafik (Fraunhofer tarafından yayıldığında).

### Backend Özelliği

Her düğüm ve kenarın kökenini izler:
- `"fraunhofer"`: Gerçek Fraunhofer CPG verisi.
- `"ast-lite"`: Python AST geri dönüşünden sentezlenir.

## Değişken Seviyesi Veri Akışı (VDF)

### Zorluk

Fraunhofer CPG'nin Python ön ucu, gerçek kodda karşılaşılan her kaynak-lavabo deseninin zengin işlemler arası veri akışını garantilemez. `request["token"] → token → encrypt(token)` gibi karmaşık desenler için, grafik eksiksiz DFG/DATA_FLOW kenarlarından yoksun olabilir.

### Çözüm: Grafik Destekli + Yerel Analiz

Değişken seviyesi veri akışı üç stratejiyi birleştirir:

1. **Normalize edilmiş grafik kenarları**: DFG, DATA_FLOW ve REACHES kenarları mevcut olduğunda bunları izleyin.
2. **Yerel atama izlemesi**: Bir değişken ataması, lavaboyı içeren işlevde meydana geldiğinde (ör. `token = request["token"]`), bunu `assignment_origin` olarak kaydedin.
3. **İşlev parametresi orijini**: Bir bağımsız değişken bir işlev parametresinden geldiğinde, parametre adı ve dizinini kaydedin.

### Uygulama

`context_extractor.py` içinde:

- `_extract_argument_signals()` bağımsız değişken değerlerini ve kaynaklarını çıkarır.
- `_assignment_origin()` bir değişkenin nerede tanımlandığını bulmak için işlevin yerel atamalarında yürür.
- `_dataflow_analysis()` grafik kenarlarını ve yerel kökenlerini birleştirilmiş bir `sources_reaching_sink` listesine birleştirir.
- `_reaching_dataflow_sources()` DFG kenarları üzerinde BFS gerçekleştirir, `MAX_DATAFLOW_DEPTH=24` atlamalarına kadar ziyaret eder.

Örnek çıktı:
```json
{
  "sources_reaching_sink": [
    {
      "argument_index": 0,
      "argument": "token",
      "via": "assignment_origin",
      "source": "request[\"token\"]",
      "reaches_sink": true
    },
    {
      "argument_index": 0,
      "argument": "token",
      "via": "graph_edge:DFG",
      "source": "...",
      "reaches_sink": true
    }
  ]
}
```

### Eksik Veri Akışı

DFG kenarları veya atama kökenlerinin bulunmadığında, sonuç şunları içerir:
```json
{
  "available": false,
  "unresolved_reason": "no_dataflow_edges_or_assignment_origin"
}
```

## Analiz Katmanları

### 1. Kripto Eşleştirici (`crypto_matcher.py`)

Kriptografik API çağrılarını `config/api_mappings.json` içindeki yapılandırılmış API/ilkel eşlemelerine karşı eşleştirerek tanımlar. Aşağıdakileri içeren `CryptoFinding` nesnelerini çıkarır:
- API adı ve çözülen çağrılan
- Kaynak dosyası, satırı, işlevi
- Kriptografik ilkel ve işlem kategorisi
- Risk güveni (0.0–1.0)

### 2. Bağlam Çıkarıcısı (`context_extractor.py`)

Her bulguyu bağlamsal işaretlerle zenginleştirir:
- **Çağrı zinciri**: Ters çağrı grafiğinden arayan soyoluşu.
- **Bağımsız değişken işaretleri**: Hazır değerler, modlar (CBC, GCM, vb.), doldurma şemaları, anahtar boyutları.
- **Kaynak/lavabo sınıflandırması**: Bağımsız değişken seviyesi kaynak kategorisi (user_input, key_material, generated_random, vb.) ve kripto lavabo türü.
- **Veri akışı analizi**: Kaynakların kripto lavaboya değişken seviyesi erişilebilirliği.
- **Grafik bağlamı**: Gelen/giden kenarlar, kenar türleri, yakın çağrı/çağrılan/bağımsız değişken düğümleri.

### 3. CBOM İnşaatçı (`cbom_builder.py`)

Zenginleştirilmiş bulguları CryptoGraph CBOM JSON şemasına dönüştürür; API eşlemesinden, kaynak konumundan, grafik bağlamından, veri akışı kanıtından ve risk kural eşleştirmelerinden türetilen kararlı varlık kimliklerine ve risk puanlarına sahiptir.

## Çağrı Grafik Oluşturması

### Yerel Çağrı Kenarları

Fraunhofer AISEC CPG, gerçek işlemler arası çağrıları temsil eden `invokes` ilişkilerini dışa aktarır.

### Sentez Yerel Kenarları

Fraunhofer veri akışı mevcut olmadığında (ör. modül arası veya modül seviyesi çağrılar), ihraçcı AST analizi tarafından bulunan aynı modül işlev tanımları için sentetik `CALLS` kenarları ekler. Bu, CBOM varlıklarının her zaman anlamlı bir çağrı zinciri içermesini sağlar.

## CPG Denetimi

`cryptograph graph` komutu deneme için normalize edilmiş grafiği dışa aktarır:

```bash
cryptograph graph --input samples --backend fraunhofer-strict --output cpg.json --dot cpg.dot --html cpg.html
```

Çıktılar:
- **cpg.json**: Tam normalize edilmiş grafik (düğümler ve kenarlar).
- **cpg.dot**: Grafik gösterimi için Graphviz DOT formatı.
- **cpg.html**: Etkileşimli HTML grafik görüntüleyicisi (bağımsız, sunucu gerekli değil).

## Çalıştırma Yapıları

Tüm oluşturulan yapılar bir zaman damgalı çalıştırma dizini altında gruplandırılır:

```
output/run-YYYYMMDDTHHMMSSZ-xxxxxxxx/
  ├── cpg.json
  ├── cpg.dot
  ├── cpg.html
  ├── result.json
  ├── report.html
  └── manifest.json
```

`manifest.json` şunları içerir:
- Grafik düğüm ve kenar sayıları
- Risk seviyesi, algoritma ve ilkel tarafından bulgu sayıları
- Yeniden üretilebilirlik için yapılandırma dosyası SHA-256 karmaları
- Araç sürümü ve backend etiketi

## Genişletilebilirlik

### Yeni bir Backend Ekleme

Grafik yükleyici arabirimini uygulayın:

```python
def load_graph(input_path: Path, backend: str) -> NormalizedGraph:
    # NormalizedGraph örneğini döndürün
    pass
```

Backend, normalize edilmiş şemaya uyan geçerli düğümler ve kenarlar yaymalıdır.

### Risk Kuralları Ekleme

`config/rules.json` alanına özgü risk puanlama kurallarıyla genişletin. Kurallar CBOM oluşturucuda bağlam desenlerine dayalı olarak güven puanları ayarlamak için uygulanır.
