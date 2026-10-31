"""Prepare source/contract-only review materials, withholding tool outputs/proposals."""
import argparse
import hashlib
import shutil
from pathlib import Path

from cryptograph.research_corpus import materialize_corpus
from cryptograph.key_origin import MODEL
from cryptograph.research_review import require_blank_review_population
from cryptograph.utils import load_json, write_json

ROOT = Path(__file__).resolve().parents[1]
INSTRUCTIONS = """# Kaynak kodu inceleme paketi

Bu paket araç sonuçlarını ve önerilen etiketleri içermez. Kaynak dosyalar
değiştirilmeden, lisansları ve sabit sürüm bilgileriyle verilmiştir. Kaynak kodu
çalıştırmayın; yalnız okuyun. Her aday çağrının gerçekten belirtilen kriptografik
API'ye bağlandığını ve doğru anahtar argümanını gösterdiğini önce kontrol edin.

`annotations.json` içindeki her kayıt için kaynak konumunu inceleyin. Anahtarın
bilinen kaynak kategorilerini, olası alternatifleri, kapsam sınırını ve belirsiz
kalan noktaları `CONTRACT.md` tanımlarına göre belirleyin. Bir parametre, anahtarın
nihai kökenini tek başına açıklamaz. Rastgele bir salt'a bağımlılık da anahtarın
doğrudan rastgele üretilmiş olduğunu kanıtlamaz. Desteklenmeyen türetme veya
modüller arası ilişki için kesin kaynak uydurmayın; belirsizliği ve nedeni kaydedin.

Kimliğiniz için sabit bir takma ad kullanabilirsiniz. İncelemeyi gerçekten
tamamladıktan sonra uygun kayıtları doldurun. Reddedilen API adaylarını ve
anlaşmazlıkları silmeyin; nedenleriyle ayrı kaydedin. Bu ilk kayıtların ardından
diğer etiketlerle karşılaştırma ve gerekirse uzlaştırma yapılabilir.

Proje yazarı olarak kendi kontrolünüzü yaparsanız bunu yazar incelemesi olarak
kaydedin; bağımsız ikinci kişi kontrolü diye adlandırmayın. Araç çıktısına bakarak
etiket oluşturmak bağımsız kaynak incelemesi değildir. İnceleme tamamlanmadan
`approved` yazmayın. Bu paket herhangi bir kişiye otomatik olarak gönderilmez.

İkinci kişi kontrolünü kaydederken `independent_review` içine `candidate_verified`
alanını yalnız API kimliği ve anahtar konumu doğrulandıysa `true` olarak ekleyin.
`reviewer_role: "independent"` yalnız gerçekten bağımsız inceleme için uygundur.
Kimlik/doğruluk/bağımsızlık iddiaları yazılım tarafından kanıtlanmaz.
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path)
    parser.add_argument('--designed', action='store_true', help='Package selected designed development files, not downloaded project sources.')
    parser.add_argument('--case-id', action='append', default=[], help='Explicit development training subset; never an origin-evaluation split.')
    parser.add_argument('--annotations', type=Path, required=True)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--out-dir', type=Path, required=True)
    args = parser.parse_args()
    if args.out_dir.exists():
        parser.error('Use a fresh review directory.')
    if not args.manifest and not args.designed:
        parser.error('--manifest is required for project sources')
    annotations = load_json(args.annotations)
    if annotations.get('analysis_model')!=MODEL:
        parser.error('Use the matching historical tool/contract for an earlier analysis model; no review is migrated automatically.')
    try:
        require_blank_review_population(annotations)
    except ValueError as exc:
        parser.error(str(exc))
    if args.case_id:
        if any(entry['split']!='development' for entry in annotations['cases']):
            parser.error('Training subsets must not silently select reserved evaluation cases')
        annotations=dict(annotations,cases=[entry for entry in annotations['cases'] if entry['case_id'] in args.case_id])
        if {entry['case_id'] for entry in annotations['cases']}!=set(args.case_id):
            parser.error('Unknown training case identifier')
    if args.designed:
        manifest={'scope':'Designed development training subset, not held-out evidence.'}
        record={'resources':[]}
        for entry in annotations['cases']:
            path=(args.source_root/entry['source']).resolve()
            if not path.is_relative_to(args.source_root.resolve()) or hashlib.sha256(path.read_bytes()).hexdigest()!=entry['source_sha256']:
                parser.error('Designed source identity mismatch')
            record['resources'].append({'path':entry['source']})
    else:
        manifest=load_json(args.manifest)
        record = materialize_corpus(manifest, args.source_root)
    args.out_dir.mkdir(parents=True)
    for resource in record['resources']:
        destination = args.out_dir / 'sources' / resource['path']
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(args.source_root / resource['path'], destination)
    write_json(args.out_dir / 'annotations.json', annotations)
    write_json(args.out_dir / 'provenance.json', manifest)
    shutil.copyfile(ROOT / 'research/python-key-origin/CONTRACT.md', args.out_dir/'CONTRACT.md')
    shutil.copyfile(ROOT / 'research/python-key-origin/claim.schema.json', args.out_dir/'claim.schema.json')
    (args.out_dir/'README.md').write_text(INSTRUCTIONS, encoding='utf-8')
    print(f'Prepared source-only review materials in {args.out_dir}; no messages were sent.')


if __name__ == '__main__':
    main()
