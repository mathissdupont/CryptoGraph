"""Create a local source-only review form; no predictions, network or scoring."""
import argparse
import hashlib
import html
import json
from pathlib import Path

from cryptograph.utils import load_json
from cryptograph.research_review import require_blank_review_population


PAGE = r'''<!doctype html><html lang="tr"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CryptoGraph kaynak incelemesi</title><style>
body{font:16px/1.5 system-ui,sans-serif;max-width:1100px;margin:30px auto;padding:0 20px;background:#f7f9fc;color:#17243c}h1{font-size:26px}details{background:white;border:1px solid #ccd5e3;border-radius:8px;margin:16px 0;padding:16px}summary{cursor:pointer;font-weight:650;overflow-wrap:anywhere}pre{font:13px/1.6 Consolas,monospace;max-height:480px;overflow:auto;background:#102038;color:#f1f5ff;padding:16px;white-space:pre}pre span{display:block}pre .target{background:#64511a}label{display:block;margin:10px 0}input,select,textarea,button{font:inherit}textarea{width:96%;min-height:100px}select,input[type=text]{max-width:100%;padding:6px}button{background:#164b94;color:white;border:0;padding:10px 18px;border-radius:5px;cursor:pointer}.note{background:#e6eefb;padding:12px;border-radius:6px}.status{font-weight:600}small{color:#43516b}
</style><h1>CryptoGraph — kaynak kodundan inceleme</h1>
<p class="note">Bu formda analiz tahminleri yoktur. Kod çalıştırılmaz; hiçbir veri gönderilmez. Rol: <strong>__ROLE__</strong>.
Yazar incelemesi bağımsız inceleme sayılmaz. Emin değilsen belirsiz bırak. Başka bir fonksiyona gelen parametre, nihai kaynağı tek başına göstermez.</p>
<p>Önce çağrının gerçekten belirtilen API olduğunu ve anahtar argümanını kontrol et. Sonra anahtarın önceki atamalarını ve varsa çağrılan fonksiyonları izle.
<code>literal</code>: sabit kaynak; <code>csprng_api</code>: tanınan rastgelelik API'sinin doğrudan sonucu; <code>external_configuration</code>: ortam değişkeni.
Bir KDF'ye rastgele salt verilmesi doğrudan rastgele anahtar demek değildir. Sözleşme dışındaki kökenleri veya izleyemediğin kısmı gerekçeye yaz.</p>
<p><a href="CONTRACT.md">Tam sözleşme</a> · <a href="provenance.json">Kaynak/sürüm bilgileri</a> · Kaynakların tamamı ve lisansları <code>sources/</code> altında.</p>
<label>İnceleyen adı veya sabit takma ad <input id="reviewer" type="text" autocomplete="off"></label>
<p><button id="save">Taslak incelemeyi JSON olarak indir</button> <label>Önceki taslağı yükle <input id="restore" type="file" accept="application/json"></label></p>
<p id="status" class="status"></p>__CASES__
<script type="application/json" id="packet">__PACKET__</script><script>
const packet=JSON.parse(document.getElementById('packet').textContent),role='__ROLE_KEY__';
const boxes=[...document.querySelectorAll('details[data-case]')];
function value(box,name){return box.querySelector('[name="'+name+'"]').value}
function getReview(box){
 const origins=[...box.querySelectorAll('[name="origin"]:checked')].map(x=>x.value).sort();
 const decision=value(box,'decision'),complete=value(box,'complete')==='yes',boundary=value(box,'boundary'),rationale=value(box,'rationale').trim();
 const confirmed=box.querySelector('[name="confirmed"]').checked,reviewer=document.getElementById('reviewer').value.trim();
 const valid=!!reviewer&&!!rationale&&['eligible','ineligible'].includes(decision)&&(decision==='ineligible'||(boundary&&value(box,'complete')&&(!complete||origins.length)));
 const reference=decision==='eligible'&&boundary?{status:origins.length?(complete?'resolved':'partial'):'abstained',origins,origin_set_complete:origins.length?complete:false,modality:origins.length?(complete&&origins.length===1?'must':'may'):'unknown',immediate_boundary:boundary}:null;
 return {status:confirmed&&valid?'approved':'pending',reviewer:reviewer||null,reviewer_role:role,candidate_decision:decision,candidate_verified:decision==='eligible'&&confirmed&&valid,candidate_rationale:rationale||null,reviewed_reference:reference,notes:rationale||null};
}
document.getElementById('save').onclick=()=>{
 const result=JSON.parse(JSON.stringify(packet));let done=0;
 boxes.forEach(box=>{const entry=result.cases.find(x=>x.case_id===box.dataset.case),review=getReview(box);entry[role==='project_author'?'author_review':'independent_review']=review;if(review.status==='approved')done++;});
 result.review_form_role=role;result.review_form_note='Human-entered source review; no software verification of semantic truth or reviewer independence.';
 const link=document.createElement('a'),url=URL.createObjectURL(new Blob([JSON.stringify(result,null,2)+'\n'],{type:'application/json'}));link.href=url;link.download=role+'-review.json';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
 document.getElementById('status').textContent=done+'/'+boxes.length+' kayıt için inceleme tamamlandı olarak işaretlendi. Dosya indirildi; özgün paket değiştirilmedi.';
};
document.getElementById('restore').onchange=async event=>{
 try{const data=JSON.parse(await event.target.files[0].text());
 if(data.analysis_model!==packet.analysis_model||data.review_form_role!==role||data.cases.length!==packet.cases.length||new Set(data.cases.map(x=>x.case_id)).size!==packet.cases.length)throw Error('İnceleme rolü veya aday kümesi uyuşmuyor');
 const restored=boxes.map(box=>{const original=packet.cases.find(x=>x.case_id===box.dataset.case),entry=data.cases.find(x=>x.case_id===box.dataset.case);
 if(!entry||entry.source!==original.source||entry.source_sha256!==original.source_sha256||entry.target_api!==original.target_api||entry.split!==original.split||['file','line','column','end_line','end_column'].some(key=>entry.target[key]!==original.target[key]))throw Error('Kaynak/sürüm/API uyuşmuyor');
 const review=entry[role==='project_author'?'author_review':'independent_review'];if(!review||review.reviewer_role!==role)throw Error('Kayıt rolü uyuşmuyor');
 if(!['pending','approved'].includes(review.status)||!['pending','uncertain','eligible','ineligible'].includes(review.candidate_decision)||[review.reviewer,review.candidate_rationale,review.notes].some(x=>x!=null&&typeof x!=='string'))throw Error('Taslak kayıt biçimi geçersiz');
 const ref=review.reviewed_reference;
 if(ref!=null){if(typeof ref!=='object'||!Array.isArray(ref.origins)||ref.origins.some(x=>!['literal','csprng_api','external_configuration'].includes(x))||new Set(ref.origins).size!==ref.origins.length||typeof ref.origin_set_complete!=='boolean'||!['literal','local_assignment','parameter','return_value','object_field','expression'].includes(ref.immediate_boundary))throw Error('Taslak etiket sözleşmesi geçersiz');
 const expected=ref.origins.length?(ref.origin_set_complete?'resolved':'partial'):'abstained',modality=ref.origins.length?(ref.origin_set_complete&&ref.origins.length===1?'must':'may'):'unknown';
 if(ref.status!==expected||ref.modality!==modality||(!ref.origins.length&&ref.origin_set_complete))throw Error('Taslak etiket alanları tutarsız');}
 if(review.status==='approved'&&(!review.reviewer?.trim()||!(review.candidate_rationale||review.notes)?.trim()||!['eligible','ineligible'].includes(review.candidate_decision)||(review.candidate_decision==='eligible'&&(!ref||review.candidate_verified!==true))||(review.candidate_decision==='ineligible'&&(ref||review.candidate_verified===true))))throw Error('Tamamlanmış inceleme kaydı eksik');
 return {box,review};});
 if(new Set(restored.map(x=>x.review.reviewer).filter(Boolean)).size>1)throw Error('Bu form tek inceleyici içindir; farklı kişilerin kayıtlarını birleştirmeyin');
 restored.forEach(({box,review})=>{
 document.getElementById('reviewer').value=review.reviewer||'';box.querySelector('[name="decision"]').value=review.candidate_decision||'pending';box.querySelector('[name="rationale"]').value=review.candidate_rationale||review.notes||'';
 box.querySelector('[name="confirmed"]').checked=review.status==='approved';const ref=review.reviewed_reference;
 box.querySelector('[name="boundary"]').value=ref?ref.immediate_boundary:'';box.querySelector('[name="complete"]').value=ref?(ref.origin_set_complete?'yes':'no'):'';box.querySelectorAll('[name="origin"]').forEach(x=>x.checked=!!ref&&ref.origins.includes(x.value));});
 document.getElementById('status').textContent='Taslak yüklendi.';
 }catch(error){document.getElementById('status').textContent='Taslak yüklenemedi: '+error.message;}
};
</script></html>'''


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle',type=Path,required=True)
    parser.add_argument('--role',choices=['project_author','independent'],required=True)
    args=parser.parse_args()
    output=args.bundle/'review.html'
    if output.exists():
        parser.error('Use a fresh source-only bundle')
    packet=load_json(args.bundle/'annotations.json')
    try:
        require_blank_review_population(packet)
    except ValueError as exc:
        parser.error(str(exc))
    sections=[]
    for index,entry in enumerate(packet['cases']):
        path=(args.bundle/'sources'/entry['source']).resolve()
        if not path.is_relative_to((args.bundle/'sources').resolve()):
            parser.error('Source escaped the review bundle')
        raw=path.read_bytes()
        if hashlib.sha256(raw).hexdigest()!=entry['source_sha256']:
            parser.error('Review source identity changed')
        lines=[]
        for number,line in enumerate(raw.decode('utf-8-sig').splitlines(),1):
            css=' class="target"' if entry['target']['line']<=number<=entry['target']['end_line'] else ''
            lines.append(f'<span{css}>{number:4}  {html.escape(line)}</span>')
        options=''.join(f'<option value="{name}">{label}</option>' for name,label in [('', 'Seç'),('literal','Doğrudan sabit'),('local_assignment','Yerel atama'),('parameter','Fonksiyon parametresi'),('return_value','Fonksiyon dönüşü'),('object_field','Nesne alanı'),('expression','Diğer ifade / belirsiz')])
        sections.append(f'''<details data-case="{html.escape(entry['case_id'],quote=True)}" {'open' if index==0 else ''}><summary>{html.escape(entry['case_id'])}</summary>
<p>Nominal API: <code>{html.escape(entry['target_api'])}</code>. Kaynak: <code>{html.escape(entry['source'])}</code>, satır {entry['target']['line']}.</p>
<pre>{''.join(lines)}</pre>
<label>API kimliği ve anahtar argümanı uygun mu? <select name="decision"><option value="pending">Henüz bakmadım</option><option value="eligible">Uygun aday</option><option value="ineligible">Uygun değil</option><option value="uncertain">Belirleyemedim</option></select></label>
<label>Çağrıya verilen anahtarın yakın kaynağı <select name="boundary">{options}</select></label>
<p>Kaynak kodla destekleyebildiğin nihai kategoriler:</p>
<label><input type="checkbox" name="origin" value="literal"> literal</label><label><input type="checkbox" name="origin" value="csprng_api"> csprng_api</label><label><input type="checkbox" name="origin" value="external_configuration"> external_configuration</label>
<label>Olası kaynakların tamamını bu sözleşme içinde belirleyebildin mi? <select name="complete"><option value="">Seç</option><option value="yes">Evet</option><option value="no">Hayır / belirsiz</option></select></label>
<label>Gerekçe: ilgili satırları, fonksiyonları ve belirsiz kalan kısmı yaz<textarea name="rationale"></textarea></label>
<label><input type="checkbox" name="confirmed"> Bu kaydın kaynak incelemesini tamamladım.</label></details>''')
    text=PAGE.replace('__ROLE__','Proje yazarı' if args.role=='project_author' else 'Bağımsız inceleyen').replace('__ROLE_KEY__',args.role)
    text=text.replace('__CASES__',''.join(sections)).replace('__PACKET__',json.dumps(packet,ensure_ascii=True).replace('<','\\u003c'))
    output.write_text(text,encoding='utf-8')
    print(f'Source-only {args.role} form: {output}; no labels were filled or approved.')


if __name__=='__main__':
    main()
