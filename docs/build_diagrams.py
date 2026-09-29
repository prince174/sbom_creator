"""Generate design artifacts only; not the SBOM service."""
from pathlib import Path
import json
import html
import xml.etree.ElementTree as ET

OUT = Path(__file__).parent
nodes = [
 ('input','Вход задания','Bitbucket URL · commit · image',440,30,'Три входа: HTTPS clone URL, полный SHA и ссылка на готовый образ. Секреты настраиваются отдельно. Готовый SBOM не требуется.'),
 ('validate','Python API / worker','Проверка входов → job ID',440,155,'Проверка URL, allowlist, SHA, лимитов и авторизации. Изолированная рабочая папка. queued → running → succeeded / failed.'),
 ('git','Git clone + checkout','Точный commit · проверка HEAD',160,290,'Клонирование Bitbucket и checkout --detach. HEAD обязан совпасть с полным commit. Сборка и установка пакетов не запускаются; неполные submodules/LFS отражаются в coverage.'),
 ('pull','Получение образа','Digest · platform · image ID',720,290,'Pull из registry. Тег разрешается один раз, фиксируются digest и платформа. Архив создаётся по immutable image ID. Связь commit ↔ image отмечается unverified; проверка build attestation остаётся внешней задачей.'),
 ('source','Syft: исходники','source.syft.json',160,425,'Directory scan закреплённой версией Syft. Manifests, lockfiles и имеющиеся артефакты. Это доступные декларации, а не гарантированный состав сборки.'),
 ('image','Syft: образ','image.syft.json · squashed',720,425,'Та же версия Syft, catalogers для образа. Анализ конечной файловой системы, а не всех удалённых слоёв. Приложение не запускается. Наличие не означает runtime execution.'),
 ('match','Сопоставление Syft JSON','Объединение кандидатов + evidence',440,565,'Сначала schema validation. Ключ — нормализованный PURL + exact version + значимые qualifiers. Fallback: ecosystem/namespace/name/version. Локальные Syft IDs не сравниваются между документами. Версии не склеиваются.'),
 ('assess','Проверка свидетельств','Точная идентичность → правила',440,710,'Основной режим без LLM. Пакетная, архивная или бинарная metadata образа подтверждает идентичность. Декларации не заменяют установленный пакет; оценки вероятности не назначаются.'),
 ('gate','Решение по политике','INCLUDE / UNKNOWN',440,855,'Правила v2: INCLUDE при подтверждённой идентичности; иначе UNKNOWN с причиной. Подтверждение пакета не переносит в итог одноимённые записи lockfile. Отсутствие наблюдения не доказывает отсутствие пакета.'),
 ('selected','Положительное решение','selected.syft.json',160,1000,'INCLUDE: отобранные записи образа, сохранённые metadata и известные связи. Удаляются висячие ссылки, сохраняются разные реально поставленные версии. Source metadata дополняет evidence, а не подменяет факты образа.'),
 ('report','Отчёт решений','decisions.json + review.json',720,1000,'decisions.json содержит объяснение и evidence IDs для каждого кандидата. review.json содержит компактный список UNKNOWN и следующие шаги проверки. UNKNOWN не попадает в final и помечает результат как частичную подтверждённую инвентаризацию.'),
 ('cdx','CycloneDX JSON','Syft convert + provenance + validation',160,1135,'Преобразование selected.syft.json, закреплённая CycloneDX schema, уникальные bom-ref и целостные dependency refs. Неизвестные dependency edges не выдумываются. Ошибка блокирует публикацию.'),
 ('output','Выход системы','final.cdx.json + отчёты + raw SBOM',440,1275,'Атомарная публикация после проверок. Помимо final: source/image Syft JSON, decisions, coverage, provenance с commit, digest, версиями Syft/policy и hashes входных файлов.'),
 ('dtrack','Пользователь','Ручная загрузка в Dependency-Track',440,1410,'Сервис заканчивает работу на выдаче файлов. Загрузку в Dependency-Track выполняет пользователь.'),
]
edges=[('input','validate'),('validate','git'),('validate','pull'),('git','source'),('pull','image'),('source','match'),('image','match'),('match','assess'),('assess','gate'),('gate','selected'),('gate','report'),('selected','cdx'),('cdx','output'),('report','output'),('output','dtrack')]
mx=ET.Element('mxfile',host='app.diagrams.net',type='device')
def page(name, ns, es):
 d=ET.SubElement(mx,'diagram',id=name.split()[0],name=name)
 m=ET.SubElement(d,'mxGraphModel',dx='1400',dy='1700',grid='1',gridSize='10',page='1',pageWidth='1200',pageHeight='1600')
 r=ET.SubElement(m,'root');ET.SubElement(r,'mxCell',id='0');ET.SubElement(r,'mxCell',id='1',parent='0')
 for id,title,sub,x,y,detail in ns:
  color='#d9f0eb' if id in ('selected','cdx','output') else '#e8eff8'
  c=ET.SubElement(r,'mxCell',id=id,value=f'<b>{html.escape(title)}</b><br>{html.escape(sub)}',style=f'rounded=1;whiteSpace=wrap;html=1;fillColor={color};strokeColor=#64829a;fontColor=#152e43;fontSize=16;spacing=10;',vertex='1',parent='1')
  ET.SubElement(c,'mxGeometry',x=str(x),y=str(y),width='320',height='90',attrib={'as':'geometry'})
 for i,(a,b) in enumerate(es):
  c=ET.SubElement(r,'mxCell',id=f'e{i}',source=a,target=b,edge='1',parent='1',style='edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;endArrow=block;strokeColor=#64829a;strokeWidth=2;')
  ET.SubElement(c,'mxGeometry',relative='1',attrib={'as':'geometry'})
page('01 Поток системы',nodes,edges)
decision_nodes=[
 ('facts','Кандидат + evidence','Идентичность, версия, location, foundBy',440,40,''),
 ('valid','Валидатор свидетельств','Все кандидаты и evidence IDs корректны?',440,190,''),
 ('failed','Ошибка контракта','FAILED · final SBOM не выдаётся',840,350,''),
 ('present','Подтверждение в образе','Конкретная идентичность подтверждена?',240,350,''),
 ('unknown','Недостаточно доказательств','UNKNOWN → отчёт · неполнота',660,530,''),
 ('yes','INCLUDE','Добавить подтверждённую запись',40,730,''),
 ('note','Граница интерпретации','Наличие ≠ выполнение ≠ применимость CVE',240,930,''),
]
page('02 Решение по зависимости',decision_nodes,[('facts','valid'),('valid','failed'),('valid','present'),('present','unknown'),('present','yes')])
# Explicit branch labels on second page.
for cell,label in zip(mx.findall('./diagram')[1].findall('.//mxCell[@edge="1"]'),['','ошибка','валидно','нет / спорно','да']): cell.set('value',label)
ET.indent(mx); ET.ElementTree(mx).write(OUT/'system-workflow.drawio',encoding='utf-8',xml_declaration=True)

cards=''.join(f'<button class="node" id="{n[0]}" data-id="{n[0]}" aria-pressed="false"><span>{i+1:02}</span><strong>{n[1]}</strong><small>{n[2]}</small></button>' for i,n in enumerate(nodes))
template='''<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SBOM Creator — схема системы</title>
<style>
:root{color-scheme:light;--ink:#17344a;--muted:#506575;--line:#cad7df;--accent:#086a64;--surface:#fff;--bg:#eef3f5}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.5 system-ui,sans-serif}main{max-width:1380px;margin:auto;padding:32px}header{margin-bottom:24px}h1{font-size:36px;line-height:1.15;margin:8px 0}h2{font-size:23px;margin:0 0 14px}p{margin:8px 0 16px}.eyebrow{color:var(--accent);font-weight:700;letter-spacing:2px;font-size:12px}.muted,small{color:var(--muted)}.layout{display:grid;grid-template-columns:minmax(0,1.5fr) minmax(280px,1fr);gap:24px}.flow{display:grid;grid-template-columns:1fr 1fr;gap:30px 24px}.node{position:relative;text-align:left;background:var(--surface);color:var(--ink);border:1px solid var(--line);border-radius:12px;padding:17px;min-height:100px;cursor:pointer;font:inherit}.node strong,.node small{display:block}.node span{float:right;color:var(--muted);font-size:12px}.node[aria-pressed=true]{outline:3px solid var(--accent);background:#e6f4ef}.node:after{content:'↓';position:absolute;bottom:-28px;left:50%;color:var(--muted)}#input,#validate,#match,#assess,#gate,#output,#dtrack{grid-column:1/-1}#dtrack:after{display:none}#report{grid-row:8 / span 2;grid-column:2;align-self:stretch}#cdx{grid-column:1}.panel{background:var(--surface);padding:24px;border-radius:14px;border:1px solid var(--line);margin-bottom:20px}.detail{position:sticky;top:20px;align-self:start}.tag{display:inline-block;background:#e6f4ef;color:var(--accent);padding:4px 10px;border-radius:20px;font-size:13px}.controls{display:flex;gap:10px;flex-wrap:wrap;margin-top:20px}button.action,select{font:inherit;padding:10px 13px;border:1px solid var(--line);border-radius:7px;background:white;color:var(--ink);max-width:100%}button.action{cursor:pointer}label{display:block;margin:12px 0 6px}#result{border-left:4px solid var(--accent);padding:12px;margin-top:18px;background:#f2f7f7}a{color:var(--accent)}table{border-collapse:collapse;width:100%;font-size:14px}th,td{text-align:left;padding:9px;border-bottom:1px solid var(--line)}footer{margin-top:28px}code{overflow-wrap:anywhere}details{margin-top:16px}summary{cursor:pointer;font-weight:600}@media(max-width:850px){main{padding:18px}.layout{grid-template-columns:1fr}.detail{position:static}h1{font-size:29px}}@media(max-width:420px){.flow{gap:28px 10px}.node{padding:11px;font-size:14px}.node small{font-size:12px}.panel{padding:16px}}@media print{.layout{display:block}.detail{position:static}.controls{display:none}}
</style><main><header><div class="eyebrow">TRACE / SBOM CREATOR</div><h1>От исходников и образа к чистому SBOM</h1><p class="muted">Режим без LLM · правила v2 · 30 сентября 2026</p><span class="tag">Bitbucket + commit + image → Syft JSON ×2 → CycloneDX</span></header>
<div class="layout"><section aria-label="Схема потока"><p class="muted">Нажми на этап — справа появятся его входы, правила и ограничения. Две ветви сходятся на сопоставлении; INCLUDE идёт в сборку, все решения — в отчёт.</p><div class="flow">__CARDS__</div></section>
<aside class="detail"><section class="panel" aria-live="polite"><span class="eyebrow" id="step"></span><h2 id="title"></h2><p id="description"></p><div class="controls"><button class="action" id="prev">← Назад</button><button class="action" id="next">Далее →</button></div></section>
<section class="panel"><h2>Как принимается решение</h2><p class="muted">Учебные сценарии, не результаты испытаний. Правила не назначают вероятности.</p><label for="scenario">Сценарий зависимости</label><select id="scenario"><option value="match">Совпадает в коде и образе</option><option value="image">Только в образе / пакет ОС</option><option value="source">Только в исходниках</option><option value="version">Разные версии</option><option value="ambiguous">Неоднозначная идентичность</option><option value="lock">Скопированный lockfile</option><option value="error">Невалидный SBOM</option></select><div id="result" aria-live="polite"></div></section>
<section class="panel"><h2>Что означает «чистый»</h2><p>В итог попадают только положительно оценённые компоненты с подтверждением в образе. UNKNOWN остаётся в отчёте и делает инвентаризацию частичной.</p><p><strong>Наличие ≠ выполнение кода.</strong> Syft не доказывает runtime usage или применимость CVE.</p><details><summary>Воспроизводимость и ошибки</summary><p>Фиксируются commit, digest, platform, версия Syft, catalogers, policy и SHA-256 артефактов. Связь сборки с commit — unverified; проверка build attestation остаётся внешней задачей.</p><p>Ошибка Git, pull, scan, конвертации или schema → failed. Финальный SBOM не выдаётся; диагностика сохраняется.</p></details></section>
<section class="panel"><h2>Матрица испытаний: 60 репозиториев</h2><table><thead><tr><th>Язык</th><th>Количество</th></tr></thead><tbody><tr><td>Java</td><td>10</td></tr><tr><td>JavaScript</td><td>10</td></tr><tr><td>Python</td><td>10</td></tr><tr><td>Rust</td><td>10</td></tr><tr><td>Go</td><td>10</td></tr><tr><td>Ruby</td><td>10</td></tr></tbody></table><p class="muted">По 10 на каждый язык. Сводка: 60 строк и итоги по языкам; commit/digest, source/image/final counts, решения, FP/FN на независимой разметке, coverage, время и CycloneDX validation.</p></section></aside></div>
<footer><a href="system-workflow.drawio" download>Редактируемая схема draw.io</a> · <a href="architecture.md">Подробная архитектура</a> · <a href="https://github.com/anchore/syft">Документация Syft</a><p class="muted">Основа: локальный SCA_accuracy_improvement. Разговор «Варианты сбора SBOM» прочитан через историю чатов. HTML работает без внешних библиотек и сети.</p></footer></main>
<script>
const nodes=__DATA__;let selected=0;
function show(i){selected=Math.max(0,Math.min(nodes.length-1,i));const n=nodes[selected];document.querySelectorAll('.node').forEach(b=>b.setAttribute('aria-pressed',String(b.dataset.id===n[0])));document.getElementById('step').textContent=`ЭТАП ${selected+1} / ${nodes.length}`;document.getElementById('title').textContent=n[1];document.getElementById('description').textContent=n[5];document.getElementById('prev').disabled=selected===0;document.getElementById('next').disabled=selected===nodes.length-1;}
document.querySelectorAll('.node').forEach(b=>b.addEventListener('click',()=>show(nodes.findIndex(n=>n[0]===b.dataset.id))));document.getElementById('prev').onclick=()=>show(selected-1);document.getElementById('next').onclick=()=>show(selected+1);
const scenarios={match:['INCLUDE','Точная идентичность и версия подтверждены metadata образа. Подтверждённая запись включается.'],image:['INCLUDE','Metadata установленного пакета с точной версией. Отсутствие в исходниках не мешает включить пакет образа.'],source:['UNKNOWN','Есть только декларация в исходниках. Нет подтверждения в образе: в final не включаем, отсутствие не утверждаем.'],version:['РАЗДЕЛЬНАЯ ОЦЕНКА','В коде A@1, в образе A@2. A@1 → UNKNOWN; подтверждённая A@2 → INCLUDE. Если в образе обе версии — оцениваем и сохраняем обе.'],ambiguous:['UNKNOWN','Имя совпало, но версия или идентичность не установлена. Fuzzy match не заменяет evidence.'],lock:['UNKNOWN','Скопированный lockfile — декларация. Без установленной metadata пакет не включается; причина и следующий шаг проверки остаются в review.json.'],error:['FAILED','Нарушена schema или целостность ссылок SBOM. Всё задание завершено ошибкой; final.cdx.json не публикуется.']};
function scenario(){const r=scenarios[document.getElementById('scenario').value];const box=document.getElementById('result');box.replaceChildren();const title=document.createElement('strong');title.textContent=r[0];const p=document.createElement('p');p.textContent=r[1];box.append(title,p);}document.getElementById('scenario').onchange=scenario;show(0);scenario();
</script></html>'''
(OUT/'system-workflow.html').write_text(template.replace('__CARDS__',cards).replace('__DATA__',json.dumps(nodes,ensure_ascii=False)),encoding='utf-8')
for diagram in mx.findall('diagram'):
 cells=diagram.findall('.//mxCell'); ids=[c.get('id') for c in cells]
 assert len(ids)==len(set(ids))
 for c in cells:
  if c.get('edge'): assert c.get('source') in ids and c.get('target') in ids
print('Validated: 2 draw.io pages, unique IDs, all edge endpoints. Generated standalone HTML.')
