# Kaynak incelemesine başlama

İlk hedefimiz analiz aracını geliştirmek için kullanılabilecek insan notlarını
toplamak. Bu bir dergi hakemliği değil: Python kaynak kodunda anahtarın hangi
atamalardan geldiğini okuyup gerekçesiyle kaydetme işi.

## Senin ilk yapacağın iş

1. `output/research-author-start/review.html` dosyasını tarayıcıda aç. İlk paket
   yalnızca dört küçük geliştirme örneği içeriyor; gerçek proje paketinden önce
   terimleri ve formu birlikte kontrol edeceğiz.
2. Adını veya sabit bir takma adını yaz. Her örnekte sarıyla gösterilen çağrıyı,
   anahtar argümanını ve öncesindeki atamaları oku. Kodları çalıştırman gerekmiyor.
3. API adayının uygunluğunu, anahtarın yakın kaynağını, destekleyebildiğin nihai
   kaynak kategorilerini ve belirsizliği seç. Gerekçeye ilgili satırları yaz.
   Emin değilsen belirsiz bırak; boşlukları tahminle doldurma.
4. Kaydı kontrol ettikten sonra incelemeyi tamamladığın kutusunu işaretle ve
   **Taslak incelemeyi JSON olarak indir** düğmesine bas. İndirdiğin
   `project_author-review.json` dosyasını sakla. Formu kapatmadan indir; formda
   otomatik kaydetme yok. Dosyanın yerini bu konuşmada belirtmen sonraki kontrol
   için yeterli. Kısmi taslağı aynı formdan tekrar yükleyebilirsin.

Formda araç tahminleri ve önerilen cevaplar yok. Çıktı dosyası yazar incelemesi
olarak kaydedilir; mevcut bağımsız inceleme alanları beklemede kalır. İlk dört
örnek geliştirme/eğitim verisidir, yayın doğruluğu ölçümü için kullanılmaz.

## Terimler

| Formdaki alan | Sorduğu şey |
| --- | --- |
| API adayı uygun mu? | Çağrı gerçekten belirtilen kriptografik API mi; anahtar rolü doğru mu? Aynı isimli başka bir fonksiyon olabilir. |
| Yakın kaynak | Çağrıya doğrudan sabit mi, değişken mi, parametre mi, fonksiyon dönüşü mü veriliyor? |
| `literal` | İzlediğin kaynak sabit bir değere dayanıyor mu? |
| `csprng_api` | Anahtar doğrudan tanınan rastgelelik API'sinin sonucundan mı geliyor? Bu tek başına güvenli kullanım demek değil. |
| `external_configuration` | Kaynak ortam değişkeninden mi geliyor? |
| Kaynakların tamamı | Olası yolların tamamını bu sözleşmede açıklayabildin mi? Bir yol bilinmiyorsa tamamlandı deme. |
| Gerekçe | Hangi satırlar sonucu destekliyor; hangi kısım belirsiz veya sözleşmenin dışında? |

Bir fonksiyon parametresi, çağıranın ne verdiği bilinmeden nihai kökeni açıklamaz.
Bir anahtarın KDF ile türetildiğini görürsen bunu gerekçeye yaz. Sözleşmemizin üç
kategorisine uymayan bir türetmeyi rastgele veya sabit diye etiketleme. Rastgele
salt bağımlılığı, doğrudan rastgele anahtar kaynağıyla aynı şey değildir.

## Sonraki adımlar

- İlk dört kaydın alanlarını ve gerekçelerini birlikte kontrol ettikten sonra
  `output/expanded-author-review/review.html` içindeki 19 gerçek geliştirme
  adayını inceleyebiliriz. Bu notlar analiz kapsamındaki eksikleri geliştirmek
  içindir; bağımsız doğruluk sonucu olarak sunulmaz.
- Kaynak kod okuyabilecek ikinci bir kişiyle bağımsız kontrol gerekir. Lisans
  öğrencisi, araştırma arkadaşı veya uygun bir danışman olabilir. Deneyimini ve
  önceki analiz sonuçlarını görüp görmediğini kaydedelim. Bu kişinin paketi
  `output/expanded-independent-review/` altında, 33 ayrılmış adayla hazırdır.
  Paket hiçbir kişiye gönderilmedi. Kendi doldurduğun dosyayı bağımsız inceleme
  olarak yeniden adlandırmak uygun değildir.
- Bağımsız kayıtlar gelince API uygunluğu, kaynak kategorileri ve anlaşmazlıkları
  kontrol edeceğiz. Belirsiz/uygun olmayan adaylar gerekçeleriyle korunacak.
  Eksik referansları model tahminleriyle tamamlamayacağız.
- Gerçek geliştirme kodunda anlamlı kapsam elde edilmeden ve etiketler kontrol
  edilmeden ayrılmış veri üzerinde makale sonucu hesaplamayacağız. Mevcut 33 adayın
  sayısı, tek başına yeterli istatistiksel güç veya temsil kabiliyeti sağlamaz.

Bu arada tekrar çalıştırma, testler, sürüm/parmak izi kayıtları ve değerlendirme
araçlarının teknik bakımını araştırma deposunda sürdürebiliriz.
