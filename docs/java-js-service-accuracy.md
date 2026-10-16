# Java / JavaScript: image-first MVP — R112, 2026-10-16

**Новая публичная Java DB проверена на всех шести прежних Java-образах.**
Current runtime `88de091`, release default archive-components v7. Новая DB SHA256
`491fe2ddb9cfd09bfb1e216d49541e9b64628621ce3538c23ecee5864bfefd59`
экспортирована из сохранённой R111 native volume в отдельный cache без сети.
Прежняя DB `c26ec91d…` и все immutable пары сохранены. Исправлены два adapter bugs:
относительный cache path теперь одинаков для validator/Trivy, ancestors проверяются
до создания child или tool invocation; unsafe path даёт `CACHE_INVALID`.

| Язык / область | TP / FP / FN | Precision | Recall / exact-version coverage | F1 | Count delta |
|---|---:|---:|---:|---:|---:|
| Java R112,6 repositories/59 known owner sets |3862/20/18|99.4848%|99.5361%|99.5104%|+2|
| JS R109,12 fresh no-lock attempts/8 positive roots |307/9/0|97.1519%|100%|98.5554%|+9|

Java:3882 predicted versus3880 known owner/GAV-version instances; repository macro
P98.8317/R99.0954/F198.9626%; conditional matched-identity versions99.9482%.
Все шесть repositories и59 известных owner sets >90% по P/R/exact-version coverage
в этой разметке. Это известные поставленные зависимости, **не global recall
для opaque/shaded code**. Исторические31 scope-UNKNOWN сохранены отдельной view;
все59 global component scopes partial,67 packaging observations UNKNOWN.
Archive-complete47/56 reactor owners из прежней проверки не означает полный shaded inventory.

| Java, тот же delivered scope | TP / FP / FN | P / R / F1 | Fresh Trivy + physical + publisher |
|---|---:|---:|---:|
| Microservices,8 owners |1341/12/8|99.113/99.407/99.260%|118.953s|
| Boot,1 owner |90/3/2|96.774/97.826/97.297%|19.031s|
| Javalin,14 owners |184/0/1|100/99.459/99.729%|13.954s|
| Dropwizard,34 owners |2140/2/5|99.907/99.767/99.837%|86.797s|
| REST,1 owner |104/3/2|97.196/98.113/97.653%|20.781s|
| DBCP,1 owner |3/0/0|100/100/100%|7.094s|

R112 — cached ORIGINAL Syft1.51.1 и cached empty-source catalog, **свежие** offline
Trivy0.75.0, physical reads, identity/archive gates и actual service publisher.
Все18 final/os/full и96 outputs sealed до отдельного POST evaluator. Frozen48
source/schema, tools,6archives, inventories, DB/metadata не менялись. Никаких source
projects, reference caches, registry acquisition, builds или downloads. Сумма266.610s
исключает Syft scans/acquisition/download/freeze; peak RSS не измерялся.
Это regression на шести раскрытых проектах, не fresh blind acceptance.

Все шесть raw Trivy component/property/path/layer/config multisets **точно равны**
прежним результатам со старой DB; added/removed0. Все18 final/os/full coordinate
multisets и6 selected-artifact-ID sets также равны. Результат подтверждён новым
POST scoring тех же packaged labels, а не перенесён из одного равенства counts.
[Полный POST report](../benchmarks/results/mvp-r112-evaluation-v1/evaluation.json),
[prediction seal](../benchmarks/results/mvp-r112-java-v1/predictions-complete.json).

JS в R112 заново не сканировался: приведены последние12 fresh R109 no-lock runs;
macro8positive P93.4808/R100%, conditional versions100%,4empty roots не успехи.
Axios per-project precision всё ещё <90%;9 консервативных fixture FP сохранены.
Image-only direct638 Java/103 JS UNKNOWN/FN — отдельная optional graph axis,
не component-MVP gate. Public DB и Trivy коррелированы, SHA1 association не доказывает
publisher authenticity/global GAV uniqueness. Metadata-only201 proofs остаются
disclosed R108, независимая новая metadata-only acceptance не заявляется.

Runtime guard проверен722 full-service tests passed/10skips и188 benchmark
regressions; native Linux actual peer symlink guard PASS/0skips. Windows новый
native-link skip покрыт этой отдельной проверкой, прежние9 skips сохранены.
Первый native harness обнаружил raw diagnostic вместо fixed code; сохранён v1,
после wrapper `CACHE_INVALID` — v2 PASS. Guard/relative path менялись до freeze;
reader/identity algorithms не менялись и под oracle не настраивались.

Installed RC `sbom-creator:mvp-r112`, configID
`sha256:46911efe835d118cae7f5decde254c988f6d32504482405bf8273a8c646280b8`:
собственная сборка29.906s, один actual warm DBCP pipeline9.839s/container13.563s.
Все48 installed hashes равны freeze; defaultv7 без feature overrides. Network-none
job/non-root/read-only/3GiB2CPU без socket/source/reference/secrets; public cache reuse,
download0, DB/metadata до/после равны. Все3schemas/16exports/4-0-4coordinates и
selected IDs равны текущему host DBCP. Readonly file-program SHA и actual Cmd/Args
проверены. Build использовал pip downloads; только runtime job был offline.
Это installed-service smoke одного существующего образа, не новая accuracy выборка.
[Installed report](../benchmarks/results/mvp-r112-container-v1/report.json).

Итоговые проверки:959 unique passing pytest nodes/10skips:722 full-service,
188 benchmark regressions,37 evaluator tests+5 targeted (один повтор),8 container
contract tests. Ruff/schema/hash/seal проверки PASS. В первом container unit v1
ошиблась строковая проверка вложенного assert; сохранена, v2 PASS, единственный
реальный build/runtime job прошёл сразу. Git binding45exact/3CRLF-LF-only;
frozen/installed bytes не нормализовались. Deployments не менялись.

R112 lossless pack:172 JSON/502,626,212 original bytes →38,666,627 tracked
JSON+gzip bytes,48 large JSON/45 unique gzip. Manifest SHA256
`16fa49694e51a85974aaeeaceb98a7438c7a8e45b830a5758277f9cc20791ad1`;
`python benchmarks/package_mvp_r112.py restore/verify`. Originals и R105–R111
manifests сохранены. Следующий практический разбор — сохранённый Chalk publication
PermissionError и generic identity/installed-owner ambiguities; без unchanged
Java-reader/DB replay, новых чужих recipes или удаления доставленных fixture units.

## Historical R111 — cold bootstrap and offline reuse

**Проверен первый запуск с пустой Java DB cache и последующий offline reuse.**
Новый atomic cache защищает от partial-download poisoning; component policyv7,
Java defaulttrue и JS type-surface policyv4 сохраняются. Это reliability improvement,
не новый precision/recall gain.

| Installed actual DBCP pipeline | Time | Public download | Cache status | Final / OS / Full |
|---|---:|---:|---|---:|
| Cold,новаяvolume/networkbridge |110.125s|100.489s|published atomic no-replace|4/0/4|
| Warm,та жеDB/network-none |9.171s|0s|reused readonly|4/0/4|

Все3coordinate multisets равны R110 DBCP; известный3/0/0 dependency control сохранился.
Это не новый blind control или проверка metadata-only axis. Source/oracle/secret/socket
не монтировались.48installed source/schema bytes равны freeze; image configID
`sha256:4b31c639de2cb444b115dd5ced5bf1fbc9ce98cf3657b6fd2f0923a867f13698`.
Native Linux6symlink guards,empty/nonempty no-replace иtoy cold/warm прошли без skips.
889tests passed/9skips:701service+188selectedbench;6Windows symlink skips покрыты
отдельным Linux preflight,3прежних skips сохранены. Ruff/schema/freeze checks PASS.

**Новая publicDB отличается от измеренного R110 snapshot.** ColdSHA256
`491fe2ddb9cfd09bfb1e216d49541e9b64628621ce3538c23ecee5864bfefd59`,1,554,915,328B,
UpdatedAt2026-10-16. Она проверена пока только на DBCP. Полный Java aggregate ниже
относится к старой DB`c26ec91d...` и не переносится автоматически на новый snapshot.
JS R109307/9/0 не менялся/не переизмерялся. Warm peer regression на старой DB:
REST252/DBCP4 raw identities/properties/paths/layers/config равны R110; no oracle/
Syft/physical/publisher. v1 был frozen до финального parent-before-mkdir guard;
итоговый cold/warm проверяет уже current48files. Old cache и29pairs сохранены.

Staging2GiB/10kentries, metadata16KiB, supported SQLite layout/schema/index/fullSHA,
read-only stale reuse, fixed error codes. Existing invalid cache/foreignlocks
сохраняются, partial cold stages очищаются, hidden retry/overwrite отсутствуют.
Schema VM100ksteps/2s; full quick_check не используется и full integrity/authenticity/
hostile-writer/power-loss durability не заявляются. Docker host discovery v1failure
не дошёл до build/network, v2 сделал одну реальную public download попытку.
[Cache/recovery guide](java-db-cache-r111.md),
[actual stage report](../benchmarks/results/mvp-r111-summary-v1/report.json).

Runtime commit `782cae1` pushed. Git binding45byte-exact/3CRLF-LF-only;48actual
installed bytes совпадают с executed source. Исходные CRLF program snapshots сохранены;
точные LF program bytes восстановлены из frozen harness AST и совпали с freeze SHA.
Это не независимый capture container argv: reduced inspect не сохранял Cmd/Args.

R111 lossless evidence:85JSON/3,431,636raw bytes →2,101,338JSON+gzip bytes,
4largeJSON/2uniquegzip. Manifest SHA256
`dfd8685e0872267314c2f6b661f462acba0143b79352b0363f3d154dd9a398a3`;
`python benchmarks/package_mvp_r111.py restore/verify`. Original bytes сохранены;
R105–R110 manifests не менялись. Новая1.55GBDB остаётся в отдельной named volume,
не публикуется в Git.

Следующая необходимая проверка перед заявлением метрик на новой DB — совместимость
её classifier inputs с прежним корпусом, затем только изменившиеся final predictions.
Новых foreign build recipes/40пар/direct graph как MVP gate не добавляется.

## Historical measured release R110, 2026-10-16

**Java v7 принят как default самого сервиса.** `Settings.java_archive_components=True`,
`.env.example` true; Docker image не подставляет скрытый включающий flag. Обратный
переход явный: archive=false/nested=false →v4, archive=false/nested=true →v6.
Существующий пользовательский `.env=false` остаётся override; deployments не менялись.
Image-only — полноценный API/CLI вход; исходники/cdxgen остаются необязательными.

| Язык / измеренная область | TP / FP / FN | Precision | Recall / exact-version coverage | F1 | Delta |
|---|---:|---:|---:|---:|---:|
| Java,6 repositories/59 known owner sets |3862/20/18|99.4848%|99.5361%|99.5104%|+2|
| JS,12 image-only no-lock cases/8 positive roots |307/9/0|97.1519%|100%|98.5554%|+9|

Java aggregate объединяет **новые R110 controls** и прежние четыре R108 predictions
с R109 independently packaged scoring; это не6 новых scans. Java repository macro
P98.8317/R99.0954/F198.9626, conditional versions99.9482%. JS macro восьми positive
roots P93.4808/R100/F196.1372, conditional versions100%;4 пустых корня не успехи.
JS accuracy —12 fresh R109 scans, R110 даёт только cached publisher regression.
[Sealed combined report](../benchmarks/results/mvp-r110-summary-v1/report.json).

## Новые Java controls на release defaults

| Existing immutable image | TP / FP / FN | P / R / F1 | Exact versions / conditional | Fresh pipeline |
|---|---:|---:|---:|---:|
| Petclinic REST |104/3/2|97.196/98.113/97.653%|98.113/99.048%|26.938s|
| Commons DBCP |3/0/0|100/100/100%|100/100%|7.516s|

Это serial fresh Syft1.51.1+Trivy0.75.0+physical reader+actual publisher, без source,
reference/build cache или пересборки. Code/inputs/tools/DB frozen до prediction;
все6 final/os/full sealed до post-only evaluator. Контроли ранее раскрыты, но не
использовались для последних reader/identity настроек; это **не fresh blind samples**.
Новые controls не содержат metadata-only archive proofs. Этот axis по-прежнему
подкреплён disclosed R108 Micro/Drop201proofs и security tests, не независимой
новой metadata-only выборкой. Reader/identity алгоритмы R108 не менялись при adoption.
[Controls and reference bindings](../benchmarks/results/mvp-r110-held-controls-v1/README.md).

REST: known packaged106, raw build reference121. Raw build recall85.95% сохранён
рядом;15 отсутствующих build artifacts не объявляются ошибками image inventory.
Hibernate wrong namespace/models-version и packaging-added jarmode UNKNOWN не
исключены ради процента. DBCP own-primary exclusion подтверждён отдельно реальными
SHA/effective/native/CDX/canonical properties/immutable copy recipe.

## Проверка сборки, отказов и регрессий

Installed `sbom-creator:mvp-r110`, config ID
`sha256:e7ad622093c917aecc4d8c7e3094286e54c485c91566a5462b6d7c95d9be423f`:
actual default REST pipeline120.445s/container122.469s/build32.078s.47 installed
hashes совпали с executed freeze, оба reader ENV overrides отсутствовали;
archive=true/nested=false/policyv7 получены из самого приложения. UID10001,
read-only/network-none/no socket/source/reference/secrets,3GiB/2CPU,16 exports verified.
Все3 coordinate multisets равны Windows109/143/252,109non-OS IDs/payload равны.
Parity остаётся PARTIAL:143OS IDs различаются, raw inventory258Windows/253Linux и
UNKNOWN6/1. Причина дополнительных5 binary-classifier observations не установлена;
ничего не фильтровалось/пересканировалось ради равенства. R109 systemd OS delta
также сохранён. [Installed report](../benchmarks/results/mvp-r110-container-v1/README.md).

Повреждённая SQLite Java DB раньше могла выбросить DatabaseError мимо graceful
boundary. Теперь original inventory/nonJava факты сохраняются, Java UNKNOWN,
три валидных SBOM публикуются без подстановки неподтверждённых raw packages.
Новые selector/fault tests проверяют настоящий reader/gate/converter, explicit
rollback и pure Node без Java tool/DB вызовов. Compose example3g, Kubernetes example
3Gi/32Giworkspace/40Gi ephemeral storage; это configuration examples, не cluster
capacity certification или применение к deployment. Cold download/recovery,
hard quota и parallel-job acceptance остаются отдельными ограничениями.

R110 JS cached12 publisher/converter regressions80.797s: все36views/12IDsets/
payload/type facts равны R109. Никаких scanner/source/acquisition/oracle calls;
исторический Chalk FAILED не переименован в исправленный locking bug.
[JS regression](../benchmarks/results/mvp-r110-js-publish-v1/README.md).

Original R110 control freeze включил22 generated PYC рядом с47source/schema files;
preflight отказ сохранён. Все69 hashes проверены, инертные PYC bytes сохранены
losslessly отдельно; portable verification не исполняет их,47source обязательны.
Future runner замораживает source до imports. Frozen attempts не перезаписывались.

803 tests passed,3 skipped; Ruff/schema/freeze/negative checks прошли. Runtime
commit `30902eb` pushed. Git binding44byte-exact/3CRLF-LF-only к executed snapshot;
все47installed bytes совпадают с frozen source. Frozen originals не нормализованы.
Первый fullsuite/focused tests отказал из-за тестового location/mock conversion;
негативные XML сохранены, финальный полный suite прошёл.

R110 evidence:250JSON/248,951,489raw bytes, losslessJSON+gzip25,955,415bytes/86uniquegzip.
Manifest SHA256`2b2221eefc2dedfce13185c55c2f9fba8e2a36e962e0952e0586d1e7ea56a03a`.
`python benchmarks/package_mvp_r110.py restore/verify`; originals локально сохранены,
старые R105–R109 manifests не изменены.

## Практическая граница MVP

Режим с высокой измеренной точностью теперь включён в release configuration,
а не спрятан за opt-in. Метрики относятся к **известным поставленным компонентам**:
archive scope завершён47/56 reactor owners, opaque/shaded completeness остаётся
UNKNOWN. Не заявляется универсальный recall или подлинность издателя. Axios/Pino/
Fastify реальные fixture units остаются conservative FP по dependency reference;
Axios project precision по-прежнему ниже90. Image-only direct638Java/103JS UNKNOWN/FN
не смешивается с component accuracy и не блокирует этот component MVP. Неизвестный
TeamCity recipe не мешает выдаче image SBOM.

## Historical R109, 2026-10-16

Два разных результата: **новое runtime-исправление JS**, проверенное свежими scans,
и **новая post-only packaged-SHA оценка Java** на неизменённых frozen R108 finals.
Они не смешиваются с новыми Java prediction или слепой независимой приёмкой.
Java v7 по-прежнему включается явно через `SBOM_JAVA_ARCHIVE_COMPONENTS=true`;
default false остаётся v4 reader. Базовый non-Java rules policy теперь
`image-evidence-and-payload-v4`.

## Java: actual R108 final, новая область подтверждённых поставленных JAR

| Корпус / все shipped owners | TP / FP / FN | Precision | Recall по известным delivered GAV | F1 | Delta |
|---|---:|---:|---:|---:|---:|
| Microservices,8 |1341/12/8|99.11%|99.41%|99.26%|+4|
| Javalin,14 |184/0/1|100%|99.46%|99.73%|-1|
| Dropwizard,34 |2140/2/5|99.91%|99.77%|99.84%|-3|
| Три reactors,56 |3665/14/14|99.62%|99.62%|99.62%|0|

Это расширяет оценку на31 прежний UNKNOWN owner set, не меняя исторические scopes
или final. Actual build/runtime TAR/image config/DiffID bindings перепроверены;
truth составлен независимо от predictions по полному SHA256 физических standalone
и nested JAR → unique controlled-build CDX GAV.1259 nested labels Micro подтверждены
own-module SHA. Все прогнозные GAV под фиксированным owner prefix сохранены в score;
packaging-added UNKNOWN консервативно считается FP, а не фильтруется по эталону.

Archive-only scope завершён для **47/56 owners**. Остаются8 Micro packaging extras
и один Drop primary с ZIP_DIRECTORY_SINGLE guard; глобальная полнота component
inventory для opaque/shaded кода не доказана ни для одного owner. Поэтому recall
в таблице — по известным delivered archives, не гарантированный global recall.
Conditional version accuracy reactors100%, exact-version coverage99.619%.
Module macro: Micro P99.066/R99.453/F199.258; Javalin100/99.351/99.660;
Drop99.952/99.824/99.887. Repository macro99.673/99.544/99.609.
[Current packaged evaluation](../benchmarks/results/reactor-packaged-evaluation-r109-v3/evaluation.json).

14 Javalin roots первоначально conservatively FP: initial packaged view3665/28/14,
Javalin module macroP82.806%. Новый независимый proof связывает literal immutable
Docker copy recipe, effective/native/CDX GAV, canonical embedded properties,
отсутствие dependency overwrite collision и full actual SHA/config/path. Только
после этого root исключается как собственное приложение. Старые v1/v2 views
сохранены; GAV truth sets и прогнозы не изменились. Enum v1 failed на directory
budget, v2 overly strict Unix directory mode, v3/v4 исправляют только POST-only
reference enumeration; ни один production guard не ослаблен.
[Actual nested labels/proofs](../benchmarks/results/reactor-packaged-nested-r109-v4/README.md).

Для справки, добавление прежнего Boot90/3/2 даёт four-repository known-delivered
**3755/17/16**, P99.5493%, R/exact-version coverage99.5757%, F199.5625%, delta+1.
Это не заменяет прежние R1081264/4/3 на меньшей области. Image-only direct Java614
и JS103 UNKNOWN/FN остаются отдельной осью, не gate component MVP.

Новый исходный JS-код дополнительно проверен4 Java cached publisher regressions:
12schemas/три coordinate multisets/selected IDs и Java policyv7 равны R108,
106.203s. Это publisher/converter-only, без scanner/physical/source/oracle calls.
[Java regression](../benchmarks/results/mvp-r109-java-publish-v1/report.json).

## JavaScript: свежие image-only no-lock прогнозы самого сервиса

12/12 scans+publish прошли, включая Chalk. **307/9/0**, P97.1519%, R/exact-version
coverage100%, F198.5554%; macro восьми positive roots P93.4808%, R100%, F196.1372%.
Conditional versions100%,316predicted/307reference, delta+9;4 empty roots не успехи.
Nest107/0/0 вместо106/0/1: @tokenizer/token0.3.0 имеет явное types:index.d.ts и
реальный непустой declaration file, но не исполняемый JS. Новое свидетельство
`declared_type_surface` требует совпадения manifest name/version с PURL, safe relative
path, final regular file и собственного owner; фиксирует manifest SHA256. `.d.ts`
contents не читаются/хешируются production-путём; наличие файла подтверждается
pinned Syft final-filesystem metadata. Нет execution/type-validity/integrity claim.

47 executing source/schema hashes и12 input archives frozen до prediction;36views
опубликованы до oracle.190.048s исключают local image acquisition. Единственное
добавление — Nest, ранее выбранные компоненты не потеряны. Все9 conservative FP
сохранены: отдельный physical audit нашёл у этих embedded package-like units реальные
поставленные JS/TS bytes; build-reference dependency scope их не содержит. Они не
удаляются из full inventory ради процента. Axios остаётся слабым project precision.
[Fresh JS evaluation](../benchmarks/results/mvp-js-types-r109-v1/evaluation.json),
[physical owner audit](../benchmarks/results/js-installed-owner-audit-r109-v1/README.md).

Первый evaluator import без src bootstrap FAILED до oracle; helper исправлен,
прогнозы не повторялись. Исторический R106 Chalk PermissionError сохранён; успех
R109 не доказывает механизм исправления Windows locking.

Installed Linux RC `sbom-creator:mvp-r109`, config ID
`sha256:ad9e174893775b55c9c64742a8d243e8bf47125c51b2e592378370e895fdb61f`:
actual Nest pipeline55.292s/container57.610s/build30.281s,47installed hashes равны
freeze,13exports/hash/schema checks прошли. Non-root10001/read-only/network-none,
без socket/source/reference/secrets,3GiB2CPU. Все308 non-OS coordinates/selected IDs
и declared-type fact равны Windows. **Полная parity PARTIAL:** Linux final/os/full
308/88/396 против Windows308/89/397. Windows дополнительно выдаёт OS systemd
252.39-1~deb12u2 из ELF cataloger; причина и OS accuracy не установлены. OS IDs тоже
различаются. Все исходные OS/full views и strict parity failure сохранены, ничто
не отфильтровано ради равенства. Java DB mounted по общему harness, но не требовалась
этому Node analysis; cold download/peakRSS/concurrency здесь не проверялись.
[Installed scoped parity](../benchmarks/results/mvp-r109-container-v1/README.md).

750tests passed,3skips, Ruff/schema/freeze/API proof-rejection checks.76new type
cases,40post-only enumeration/primary-proof tests,30packaged evaluator tests.
Развёрнутые сервисы/immutable пары не менялись, чужие recipes не расширялись.
Следующий release этап — held-from-recent-tuning существующие REST/DBCP controls и
явное принятие лучшего Java v7 режима по умолчанию при сохранённом partial coverage,
без ещё одного неизменённого reader replay. Универсальный blind acceptance не заявлен.

R109 runtime commit `9010f31` опубликован. Exact snapshot binding:46 файлов побайтно
равны Git, один прежний image_java/__init__.py отличается только CRLF/LF.
317 JSON/705,873,680 raw bytes сохранены локально; lossless gzip+small JSON
63,228,323 bytes,117 unique gzip objects. Manifest SHA256
`5d7576fdf6be0301a2090bdc4b5742f72c014ec58d1ed1779581cfb80ce6c507`.
Восстановление и проверка: `python benchmarks/package_mvp_r109.py restore/verify`.
Original frozen sources, failed attempts и старые manifests не изменены.

## Historical R108, 2026-10-16

Измеряется **final.cdx.json самого сервиса**; совпадают точное имя и версия.
Image-only не использует repository/reference/build cache. Все final/os/full,
original inventories, observed payload и identity/presence audits сохранены.
Референсы открыты отдельным evaluator после завершения всех4 прогнозов.

**R108 поднимает Microservices выше90% на прежнем согласованном scope:**139/1/1
вместо124/1/16; Dropwizard907/0/0 вместо893/0/14.29новых TP, без новых FP и потерь
прежних подтверждённых координат/physical witnesses. Новый режим реализован в
runtime, но остаётся **явным opt-in** `SBOM_JAVA_ARCHIVE_COMPONENTS=true`, policy
`image-delivered-archive-v7`. Default false сохраняет R105/v4; один nested-флаг —
R107/v6. Метрики v7 нельзя выдавать за поведение default-конфигурации.

| Java / прежний scope | TP / FP / FN | Precision | Recall / exact-version coverage | F1 | Count delta | Время |
|---|---:|---:|---:|---:|---:|---:|
| Microservices,1 owner +7 UNKNOWN |139/1/1|99.29%|99.29%|99.29%|0|63.468s|
| Petclinic,92 SHA-labelled packaged components |90/3/2|96.77%|97.83%|97.30%|+1|9.875s|
| Javalin,8 owners +6 UNKNOWN |128/0/0|100%|100%|100%|0|6.641s|
| Dropwizard,16 owners +18 UNKNOWN |907/0/0|100%|100%|100%|0|49.797s|

Java micro **1264/4/3**, P99.6845%, R/exact-version coverage99.7632%, F199.7239%;
1268predicted/1267reference owner/component instances, delta+1. Repository macro
P99.0150%, R99.2780%, F199.1458%. Conditional versions1264/1265=99.9209%
(Boot98.90%, остальные100%).26scored owner instances — не26 независимых проектов.
**31 UNKNOWN scope сохранён** с raw deltas, не считается прошедшим >90.
Это4 раскрытых tuning repositories, не fresh independent acceptance.
[Post-only evaluation](../benchmarks/results/mvp-r108-v1/evaluation.json).

Syft1.51.1/Trivy0.75.0 inventories кешированы; physical reads и реальная conversion/
publication12SBOM выполнены заново.129.781s суммарно исключают scanner/acquisition.
47source/schema files, input/DB hashes frozen до прогнозов; evaluator проверяет
4-case marker/freeze/12schemas до oracle. Whole final Micro2628 не является TP count.

Новая ось **verified archive component presence** не подменяет payload.201archive
proofs(170Micro+31Drop) имеют complete SHA256/SHA1 и CRC файлов ZIP;37nested
instances также повторно проверяют STORED-member CRC/range. Все201 сохраняют
`observed_payload=unconfirmed`, весь payload mapping равен R107.105proofs используют
канонический `pom.properties`,96 — exact full-SHA1 public Java DB association и тот
же unique Trivy GAV/path/layer. Gradle-published Boot starters содержат только
manifest/LICENSE/NOTICE, без `pom.properties`; filename/manifest не являются GAV proof.
[Fresh physical inspection](../benchmarks/results/archive-metadata-inspection-r108-v1/verification.json),
[public hash research](../benchmarks/results/public-java-hash-research-r108-v1/report.json).

Public DB и Trivy коррелированы. SHA1→GAV index с first-writer семантикой не является
publisher authentication или доказательством глобальной уникальности GAV. Полный
SHA256 запечатывается отдельно; conflicting metadata/DB/peer или несколько GAV для
одинакового SHA256 внутри образа остаются UNKNOWN. Proof — внутренний output, API
его не принимает. Нет утверждения о class/resource bytes, execution или directness.

Оставшиеся FN: Micro netty-common4.2.9.Final с ambiguous identity; Boot Hibernate
group/models-version mismatch. Packaging-added jarmode/jarmode-tools остаются
conservative FP/UNKNOWN. Ничего не исключено по эталону ради процента.
614Java/103JS image-only direct edges UNKNOWN/FN, optional source model отдельно;
полнота direct graph и40пар не условие первого component MVP.

Micro ресурсы: normalization1,303,884,800B once, verification1,953,449,473B,
payload windows96,514,144B; complete member-CRC3,950,660B оплачены прежним128MiB
ordinary-read cap; index9,814,345B/91,330chargedentries,256resident107evictions363charges.
Бюджеты не повышены:8GiBnormalization/отдельно8GiBverification,32MiB/read128MiBpayload,
outer128MiB/nested32MiB, ZIP2MiBsingle/16MiBcumulative/100kchargedentries,
4096views/180s cooperative witness. Drop сохраняет137 ZIP_DIRECTORY_SINGLE guard
observations вне согласованных score instances. Hardquota/peakRSS/concurrency/coldDB
acceptance не доказаны.

JS accuracy не пересчитана по новым scans: последние fresh image-only no-lock R106
дали306/9/1, P97.14%, R/exact-version coverage99.67%, F198.39%; macro8positive roots
P93.48%, R99.88%, conditionalversions100%.4emptyroots не успехи. Axios/Fastify/Pino
fixture FP и Nest @tokenizer/token FN остаются. R10812cachedpublisher regressions
сохраняют36views и selectedIDs R107,89.578s, JSv3; не новые scans/accuracy. Оригинальный
Chalk PermissionError сохранён, locking fix не заявляется.
[JS regression](../benchmarks/results/mvp-r108-js-publish-v1/report.json).

604service/selectedbenchmark tests passed,3skips;103new archive/hash tests,
Ruff/schema/freeze checks прошли. Freshphysical/actualpublisher defaultBootv4 и
nestedJavalinv6 сохраняют3coordinate multisets/selectedIDs; v6 exactcatalog/payload/
audit. [Default preservation](../benchmarks/results/mvp-r108-default-parity-v1/report.json).

Actual installed Linux RC `sbom-creator:mvp-r108`, image/config ID
`sha256:aeae62a80a41d2ac2c8dae93a38f96233b7ee822ef74ead045a38211486047da`,
прошёл полный Micro pipeline со **свежими Syft/Trivy scans**:547.699s, build31.109s;
local archive acquisition исключён. final/os/full2628/0/2628,5UNKNOWN groups;
все3 coordinate multisets,2628selectedIDs и170complete archiveproofs точно равны
Windows, payload facts тоже равны.47installed source/schema hashes равны freeze,
16export/hash/schema checks прошли; source/publicDB не изменились. Nonroot10001,
read-only/network-none/no socket/source/reference/secrets,3GiB/2CPU. Linux actual
payload_read_bytes95,338,413, Windows96,514,144; counters не выдаются за одинаковые.
Cgroup memory.peak856.0MiB включает cache/probes, не process RSS и не2GiB acceptance.
Это installed pipeline parity, не fresh independent accuracy.
[Installed verification](../benchmarks/results/mvp-r108-container-v1/verification.json),
[Windows/three-view/proof parity](../benchmarks/results/mvp-r108-container-v1/windows-coordinate-comparison.json),
[resources/timing](../benchmarks/results/mvp-r108-container-v1/resource-summary.json).
Runtime commit `379469a`:46Git blobs побайтно равны executed snapshot, один прежний
`image_java/__init__.py` отличается только CRLF/LF. Эта неудачная проверка exactGit
bytes сохранена отдельно; все47 installed hashes совпадают с реальными executed
bytes, исходный CRLF snapshot и исторический HEAD build receipt не переписаны.
[Commit/content binding](../benchmarks/results/mvp-r108-v1/committed-source-binding.json).

Отдельный POST-only scope этап заново проверил actual build/runtime TAR trees и
точный image layer по OCI platform/config/DiffID для всех3 reactors. Уникальные
own-module CDX SHA256 дали standalone labels:185/199Javalin,2145/2179Drop,
1361/1369Micro.34Drop/8Micro primary outputs вынесены отдельно с effective-output
SHA proof;14Javalin unmatched сохраняют UNKNOWN. Предсказания не использовались
для выбора truth. **Это ещё не закрывает31UNKNOWN**: nested/shaded содержимое
primary JAR и packaging extras требуют независимой разметки. Новая scoring view
не выдумана, исторические scopes/scores не изменены.
[Packaged tree binding/labels](../benchmarks/results/reactor-packaged-scope-r108-v1/report.json).

Перед default adoption: независимая nested packaged-SHA разметка, held-from-tuning
controls и слабые JS roots. Раскрытые результаты не дают универсального acceptance.
Развёрнутые сервисы не менялись, чужие пары не пересобирались. Долгосрочный corpus/
direct research остаётся отдельным.

R108 evidence:340JSON,738,403,545 исходных байт сохранены локально. JSON lossless
pack (120unique gzip +smallJSON) занимает59,310,431B; контейнерные export.gz тоже
сохраняются отдельно с SHA. `python benchmarks/package_mvp_r108.py restore` восстанавливает
крупные JSON для ссылок/повтора, `verify` проверяет точные original/stored hashes.
[Manifest R108](../benchmarks/results/mvp-r108-evidence-manifest.json), SHA256
`5a7b17a87e9541221b995bcb29e94aed01ff16f0727b1a1a390d82242d73762d`. Старые R105/R106/R107 manifests не изменились.

## Historical R107 opt-in experiment, 2026-10-16

Измеряется **final.cdx.json самого сервиса** после фактического запуска сканеров,
reader, identity gate и publisher. Референс открывает только evaluator после
завершения прогнозов. Точное имя **и версия** должны совпасть. Repo/commit не
передаются image-only анализу; граф исходников — отдельное обогащение.
Все три SBOM и полный scanner inventory сохраняются.

**Стабильный default остаётся на reader R105, policy v4.** Nested-window вариант
сохраняется отдельным opt-in экспериментом: `SBOM_JAVA_NESTED_WINDOWS=true`
(Python `Settings(java_nested_windows=True)`); текущий R107 использует policy v6,
исторический R106 — v5. Числа относятся к зафиксированным experimental snapshots,
не к принятию reader по умолчанию. Microservices пока не достиг90% recall.

**Java пока не проходит >90% на всех сложных проектах.** R107 повышает Microservices
с99/1/41 до124/1/16, но recall88.57% всё ещё ниже цели. Java aggregate уже выше90%,
однако он не заменяет слабый проект и31 владельца с UNKNOWN scope. JS проходит
компонентный порог на измеренной раскрытой положительной выборке; отдельный Windows
publication failure сохранён. Универсальной гарантии для любых образов нет.

## R107 opt-in v6: прежние scope, свежие physical reads и публикация

| Java / согласованный scope | TP / FP / FN | Precision | Recall / exact-version coverage | Версии среди совпавших имён | Время |
|---|---:|---:|---:|---:|---:|
| Microservices,1 owner; ещё7 scope UNKNOWN |124 /1 /16|99.20%|88.57%|100%|58.453s|
| Petclinic,92 packaged dependencies |90 /3 /2|96.77%|97.83%|98.90%|8.171s|
| Javalin,8 owners; ещё6 scope UNKNOWN |128 /0 /0|100%|100%|100%|4.406s|
| Dropwizard,16 owners; ещё18 scope UNKNOWN |893 /0 /14|100%|98.46%|100%|40.969s|

Сканерные inventories кешированы; физическое чтение образов, подтверждение и
Syft publication всех12 final/os/full выполнены заново.112.0s суммарно — **не**
полный scanner/acquisition timing. Код/inputs frozen до4 прогнозов; reference
evaluator стартует только после их завершения. Java micro1235/4/32:
P99.677%, R/exact-version coverage97.474%, F198.563%; repository macro
P98.994%, R96.213%, F197.526%.26 scored owner instances/31 UNKNOWN остаются
отдельно. [Полный R107 post-only отчёт](../benchmarks/results/mvp-r107-v1/evaluation.json).

Причина R106 BudgetExceeded доказана отдельной no-oracle диагностикой:
742 отказа fingerprint-cap256 при7,689,813bytes/72,282entries; payload128MiB,
ZIP16MiB/100k cumulative limits в тот момент ещё не достигнуты. R107 использует
LRU на те же256 fingerprint credits; вытесненный directory при повторном чтении
снова полностью оплачивает существующие cumulative bytes/entries. Лимиты не
увеличены. Micro:9,813,237 charged directory bytes/91,317entries,256 live credits,
106 evictions/362 charges, budget guards empty,95,536,087 payload-window bytes.
Бюджеты проверяются до выделения ZIP index. [Guard proof](../benchmarks/results/mvp-r107-directory-diagnostic-v1/report.json).

25 дополнительных TP,0 удалённых ранее включённых координат,0 новых FP против
R106; остальные3 проекта сохраняют состав. Прежние12 "unmatched" FN оказались
ошибкой диагностического join: оригинальный Syft PURL имел namespace=artifactname,
а Trivy уже содержал правильный GAV в том же exact path/layer. Все21 observation
тех12 библиотек тоже имели BudgetExceeded; новый alias/Boot-path rule не добавлялся.
[Диагностика исходных PURL](../benchmarks/results/micro-missing-diagnosis-r107-v1/report.json).
Оставшиеся16 FN Micro —15 metadata-only starter artifacts без class/resource
witness и netty-common с physical bytes, но UNKNOWN identity. Packaging-added
jarmode-tools остаётся conservative FP. Они не исключаются ради порога.

JS R107 — только cached publisher regression:12 публикаций/36 валидных views
и selected IDs совпадают с R106(Chalk сравнивается с отдельным сохранённым
diagnostic replay),84.657s. Новых scanner/physical проходов JS и новой accuracy
оценки нет; ранее измеренные306/9/1,P97.14/R99.67 сохраняют свою область.
R106 Chalk failure остаётся FAILED, исправление Windows locking не заявляется.
[JS regression](../benchmarks/results/mvp-r107-js-publish-v1/report.json).

501 тест прошёл,3 skips,20.03s;12 дополнительных security cases проверяют
LRU eviction/recharge, cumulative budgets, отказ до parser allocation и identity
UNKNOWN. Default policy v4 не включил эксперимент.

Actual installed Linux RC `sbom-creator:mvp-r107`, config ID
`sha256:9030298f955b585040e1059c659e2767471555199fc4f66cb03aaa78780c0fd0`,
прошёл полный image-only pipeline со **свежими Syft/Trivy scans** и explicit v6:
523.962s pipeline/527.344s harness. Готовый local image archive исключает registry
acquisition; исходников/reference/socket/секретов нет, nonroot/read-only/network-none.
Установленные44 source/schema файла равны freeze, source/Java DB не изменились;
16 экспортированных артефактов/hash/schema checks прошли. final/os/full2458/0/2458,
36 UNKNOWN groups; все3 coordinate multisets и2458 selected IDs точно равны
Windows R107. Это установленный full-pipeline parity, **не** новая независимая
accuracy и не основание включить эксперимент по умолчанию: Micro88.57% ниже цели.
Linux ledger9,813,237bytes/91,317entries,256 live credits/106evictions/362charges,
2649hits; budget guards/rejections0. Raw inventories сохранены; их байтовое равенство
между платформами не заявляется.
[Installed verification](../benchmarks/results/mvp-r107-container-v1/verification.json),
[Windows output parity](../benchmarks/results/mvp-r107-container-v1/windows-coordinate-comparison.json),
[actual harness timing](../benchmarks/results/mvp-r107-container-v1/microservices/run.json).

Доступен путь отдельно закрыть scope, не пересобирая проекты: immutable
application-tree.json уже содержит SHA256 standalone dependency files, а все
module CycloneDX components — SHA256/GAV; коллизий hash→multiple GAV не найдено.
Audit: Javalin185 из199 standalone files имеют own-module hash match, Drop2145
из2179, Micro1361 из1369; остаток включает primary outputs. Это availability
proof для будущих packaged labels, **не** изменение ground truth/score сейчас.
Нужны отдельная проверка build/final TAR trees+config и nested packaging extras;
все31 UNKNOWN scopes здесь сохраняются. [Scope-data audit](../benchmarks/results/reactor-scope-audit-r107-v1/report.json).

R107 evidence:286 JSON,679,029,559 исходных байт сохранены локально;
lossless gzip и небольшие JSON занимают56,524,528bytes в Git.
Восстановление: `python benchmarks/package_mvp_r107.py restore`, проверка:
`python benchmarks/package_mvp_r107.py verify`.
[SHA256 manifest R107](../benchmarks/results/mvp-r107-evidence-manifest.json).

## R106 historical opt-in: actual image-only service, прежние области оценки

| Java / согласованный scope | TP / FP / FN | Precision | Recall / exact-version coverage | Версии среди совпавших имён | Время |
|---|---:|---:|---:|---:|---:|
| Microservices,1 owner; ещё7 scope UNKNOWN |99 /1 /41|99.00%|70.71%|100%|158.953s|
| Petclinic,92 SHA256-labelled packaged dependencies |90 /3 /2|96.77%|97.83%|98.90%|95.859s|
| Javalin,8 owners; ещё6 scope UNKNOWN |128 /0 /0|100%|100%|100%|22.765s|
| Dropwizard,16 owners; ещё18 scope UNKNOWN |893 /0 /14|100%|98.46%|100%|125.610s|

Java micro1210/4/57: P99.67%, R/exact-version coverage95.50%, F197.54%.
Repository macro P98.94%, R91.75%, F194.75%. Это26 размеченных owner instances
в4 раскрытых репозиториях, не26 независимых проектов;31 других owner scopes
UNKNOWN с полными raw build-reference deltas. Количество отдельно:1214 predictions
против1267 reference occurrences, delta−53. Все3 SBOM каждого Java case сохранены.
Image-only direct остаётся0/0/614, UNKNOWN; source-model результаты не смешиваются
с этими компонентными метриками. [Полный post-only отчёт](../benchmarks/results/mvp-r106-v1/java/evaluation.json).

Экспериментальный reader связывает STORED nested JAR с точным физическим диапазоном родительского
образа. Local header/central directory/filename/overlap проверяются стандартным
ZIP parser; SHA256 и CRC всего nested body заново проверяются в уже существующем
8GiB verification budget. Полный body не копируется в128MiB payload-window budget.
Exact-range cache остаётся16MiB/4096 entries, теперь сохраняется между witnesses
только в рамках одного reader/job; parsed ZipFile объекты между witnesses не делятся.
Identity/path/layer/config guards и метаданные UNKNOWN не ослаблены.

Microservices: payload windows91,016,461bytes вместо134,217,721, normalization
1,303,884,800bytes ровно один раз, verification1,952,538,302bytes, copied0;
1267 stored nested windows с CRC verification. Whole final1878 artifact records
вместо188 — это **не** число TP. На размеченном owner91 дополнительный TP и1 новый
conservative FP(jarmode-tools);41 FN остаются. Post-only audit разделяет27 FN с
BudgetExceeded(какой именно guard — UNKNOWN),1 confirmed physical/netty identity
UNKNOWN,1 без physical witness и12 без совпавшей записи existing Syft bridge.
Это диагностика, не новые исключения из score. [Детали](../benchmarks/results/mvp-r106-v1/microservices-diagnosis.json).

Состав Petclinic/Javalin/Dropwizard в согласованных project scopes не ухудшился.
Метрики не объявляются независимой приёмкой: эти проекты раскрыты для настройки,
Microservices остаётся ниже90%, metadata-only Dropwizard FN не удалены.
Время403.187s — сумма4 actual Java pipelines, включая свежие Syft/Trivy scans,
DB hashing, physical reads и публикацию; registry acquisition готового local archive
не входит. Peak RSS/hard filesystem quota/безопасная параллельность не доказаны.

JS R106:12 fresh image-only no-lock **попыток**,11 опубликованных результатов.
На8 положительных roots компоненты306/9/1, P97.14%, R/exact-version coverage99.67%,
F198.39%; macro P93.48%, R99.88%, matched-identity versions100%.
Все3 coordinate multisets11 опубликованных результатов равны R105; прежние
Axios/Fastify/Pino FP и Nest FN остаются. Сумма pipeline timings201.500s.
Image-only direct0/0/103, UNKNOWN. [JS отчёт](../benchmarks/results/mvp-r106-v1/javascript/evaluation.json).

Chalk завершился publication PermissionError(reconcile_convert_validate), final
не опубликован. Его project reference пуст; он не становится успешным precision/
recall примером и исключён из positive macro вместе с другими пустыми roots.
Отдельный **однократный publisher-only diagnostic replay** тех же сохранённых
каталогов и frozen code, без нового scanner/oracle, завершился за6.000s; все3
coordinate multisets равны R105. Первая ошибка сохранена, точная операция/cause
не установлены; это не доказанное исправление Windows locking.
[Отрицательная попытка](../benchmarks/results/mvp-r106-v1/javascript/paired-chalk-v1/run.json),
[отдельная диагностика](../benchmarks/results/chalk-publish-diagnostic-v1/run.json).

Код и все16 image inputs frozen до анализа; evaluator открыл эталоны только после
завершения всех16 попыток. [Общий протокол и operational status](../benchmarks/results/mvp-r106-v1/evaluation.json).
После opt-in selector489 service/selected benchmark tests прошли,3 skips
(492 total,20.31s); Ruff прошёл. Corpus остаётся29
immutable пар, сторонние рецепты не расширялись, развёрнутые сервисы не менялись.
Первая Linux RC попытка отдельно провалилась до Java evidence из-за заполненного
512MiB `/tmp` в Syft scratch; она не является компонентной метрикой и не заменяет
Windows protocol выше. Отдельный запуск ТОГО ЖЕ experimental snapshot с
`TMPDIR/TMP/TEMP=/workspace/process-temp` проходит:517.271s pipeline/524.484s
container, final/os/full1878/0/1878. Coordinate multisets всех3 views равны Windows;
это parity, не новая независимая точность. [Linux scratch protocol](../benchmarks/results/mvp-r106-container-scratch-v1/run.json).
Workspace scratch configuration исправлена отдельно для shipping default,
а nested-window classifier по умолчанию не включается.

Финальный RC `sbom-creator:mvp-r106-final`, config ID
`sha256:ce5737b1915804d33f6c335a3b13f01e6a61da319ff64beba0b70b57dbc55613`:
установленные43 source/schema файла совпадают с freeze; read-only/nonroot/no-socket/
network-none configuration smoke прошёл за1.282s. Default selector=false,
explicit=true и отказ на invalid flag проверены. TMPDIR/TMP/TEMP=/workspace
доступны для записи, `/tmp` остаётся512MiB tmpfs. Experimental reader SHA256
`26aca377bc5905da73b258bbacebc9a5b7c4de0726860bd82a16a2278078c00f`
совпадает с ранее измеренным алгоритмом. Это selector/config proof, **не** повтор
полного scanner/acquisition Micro pipeline после разделения default/opt-in.
[RC configuration proof](../benchmarks/results/mvp-r106-container-selector-v1/config-smoke.json).

Отдельный post-selector parity v2 прошёл на cached scanner catalogs со свежими
physical reads и настоящим Syft publisher: experimental Micro50.766s, default
Boot7.890s. У opt-in Micro adapted catalog, physical facts и serialized audit
точно равны R106; все3 coordinate multisets и selected artifact IDs совпадают.
У default=false Boot policy v4 и все3 views/IDs точно равны R105 stable.
Это проверка сохранения режима/результатов, не новая independent accuracy.
В первой попытке v1 post-publication harness ошибочно сравнил tuples в памяти
с JSON lists: сами predictions/3views/IDs и сериализованные факты уже совпадали.
Отрицательный harness report сохранён; это не ошибка сервиса.
[Selector parity v2](../benchmarks/results/mvp-r106-selector-parity-v2/report.json),
[сохранённый harness false assertion v1](../benchmarks/results/mvp-r106-selector-parity-v1/harness-failure.json),
[финальный unit report](../benchmarks/results/mvp-r106-selector-unit.xml).

Полные исходные артефакты сохранены локально:379 JSON,1,237,293,325bytes.
В Git крупные JSON представлены lossless gzip с SHA256; вместе с небольшими
JSON это58,700,664bytes. После checkout восстановление:
`python benchmarks/package_mvp_r106.py restore`; проверка:
`python benchmarks/package_mvp_r106.py verify`.
[Manifest исходных и сжатых файлов](../benchmarks/results/mvp-r106-evidence-manifest.json).

## R105 baseline: реальные итоговые SBOM

| Запуск / область оценки | TP / FP / FN | Precision | Recall / exact-version coverage | Время |
|---|---:|---:|---:|---:|
| Linux installed RC, Petclinic:92 известных packaged dependencies |90 /3 /2|96.77%|97.83%|84.563s|
| Финальный Linux RC после safety catch, тот же Petclinic |90 /3 /2|96.77%|97.83%|75.062s|
| Windows serial, тот же Petclinic |90 /3 /2|96.77%|97.83%|24.234s|
| Windows v2, Javalin:8 native/CDX-agreeing owners |128 /0 /0|100%|100%|22.485s|
| Windows v2, Dropwizard:16 agreeing owners |893 /0 /14|100%|98.46%|171.031s|
| Windows v2, Microservices:1 agreeing owner |8 /0 /132|100%|5.71%|139.234s|

Это actual pipeline timings: fresh scans, DB hashing, physical reads и publication;
готовый local archive исключает время registry acquisition. Linux также включает
container startup. Windows v2 Petclinic сначала завершился partial с
java_image_status=UNKNOWN, RuntimeError:0/0/92, recall0. Тот же код при отдельном
serial-запуске и в установленном Linux image получает90/3/2. Отрицательный запуск
сохранён; точная причина Windows helper failure не установлена.

Финальный локальный image `sbom-creator:mvp-r105-final`, config ID
`sha256:318289b205c2bd0597dfbb1cf6a20169f39cefe598758f5ca91d261cd7850a8d`:
73.262s pipeline /75.062s с контейнером. Все42 установленных файла совпадают со
снимком; единственная разница с предыдущим успешным RC — catch schema failure
дополнительного peer-сканера. Все три coordinate multisets и выбранные artifact IDs
совпали. [Финальная проверка](../benchmarks/results/mvp-container-r105-v1/final-fallback-verification.json).
457 service/selected benchmark tests прошли,3 skips; Ruff и schema checks прошли.
Это проверенный runtime candidate с сохранённым Microservices failure, не приёмка
универсального Java >90% и не развёртывание сервиса.

[Linux RC evaluation](../benchmarks/results/mvp-container-r105-v1/final-smoke/evaluation.json),
[Windows serial Boot](../benchmarks/results/mvp-image-r105-serial-boot/evaluation.json),
[полный фиксированный v2 протокол](../benchmarks/results/mvp-image-r105-v2/evaluation.json).
В полном v2 протоколе, включая failed-helper Boot и слабый Microservices,
Java micro1029/0/238: P100%, R81.22%, F189.63%; repository macro recall51.04%.
Удачный serial Boot показан отдельно, а не незаметно подставлен в агрегат.

Javalin имеет ещё6 владельцев со scope UNKNOWN, Dropwizard18, Microservices7:
для каждого сохранены raw build-reference delta, missing/extra и owner path.
Они не объявлены успешными. Это модули четырёх раскрытых репозиториев, а не десятки
независимых проектов. Фиксированные /application/<module> пути относятся к fixture
recipes; полный image inventory не фильтруется по эталону. GAV comparison не
доказывает classifier/type accuracy.

Linux final содержит95 non-OS записей:93 project coordinates под /application/
совпадают с прежним benchmark,2 записи вне этой области остаются в результате.
Petclinic conditional version accuracy98.90%; известны неправильные namespace
org.hibernate/hibernate-core и версия hibernate-models1.1.0 вместо1.1.1.
Packaging-added jarmode UNKNOWN консервативно считается FP. Aliases не угадывались.

Все14 Dropwizard FN — metadata-only listenablefuture9999.0-empty-to-avoid-conflict-with-guava
у14 владельцев. JAR присутствует,2199bytes, только manifest/POM/properties, без
class/resource proof. Он **остаётся FN**, не исключён из score ради100%.

Microservices:1,303,884,800 normalized bytes,1,302,810,004 SHA256 verification bytes
и134,217,721 из134,217,728 payload-window bytes;188 подтверждённых artifact instances.
На единственном owner с native/CDX agreement найдено8/140 точных компонентов;
ещё7 owner scopes UNKNOWN с raw recall5–10%. Это реальный предел покрытия текущей
ресурсной политики. Сложный проект не удаляется из проверки ради метрик.

## R105 baseline JavaScript:12 свежих image-only запусков без project lockfiles

| Метрика компонентов | Результат |
|---|---:|
| TP / FP / FN, exact name + version |306 /9 /1|
| Precision / Recall / F1 micro |97.14% /99.67% /98.39%|
| Macro по8 положительным проектам, P / R |93.48% /99.88%|
| Версии среди совпавших имён / exact-version coverage |100% /99.67%|
| Изменённые component sets против сохранённого baseline |0 из12|
| Суммарное время12 actual pipeline scans |272.091s|

Все36 final/os/full валидны. Четыре пустых project roots не засчитаны как идеальные
примеры. Node/npm platform и ОС не смешиваются с fixture /app/ scope, но остаются
в inventory. Ни исходников, ни source/image project lockfiles analyzer не получает.
Это fresh scans, а не только повторная проверка старых JSON.
[Прогнозы, snapshot исполнявшегося src, каждый проект и регрессия](../benchmarks/results/mvp-js-r105-v1/evaluation.json).

Слабые места сохранены: Axios8/5/0, P61.54% (вложенные test fixtures);
Fastify47/3/0; Pino12/1/0 (transport fixture); Nest106/0/1
(пропущен @tokenizer/token0.3.0). Высокая micro-метрика не скрывает Axios.

## R105 baseline: граф и оставшиеся шаги до выпуска

Image presence подтверждает компонент поставки, но не прямоту. В image-only
запусках все известные direct edges UNKNOWN/FN: JS103, Java16/55/443/100
для Boot/Javalin/Dropwizard/Microservices. Полный original-CI граф не заявляется.
По текущему запросу пользователя это отдельное обогащение, не условие выдачи
SBOM готового образа.

R104 source comparison на Microservices: passive Trivy76/0/24; native cdxgen
на8 shipped owners100/0/0, raw all-owner100/8/0 из-за module containment.
[Отчёт и границы](java-microservices-reference-r104.md).
Default SBOM_JAVA_BACKEND=disabled; cdxgen разрешается явно в изолированном job.
Модель доступной Maven environment не выдаётся за неизвестный TeamCity recipe.

До заявления высокой точности всего Java MVP нужны: устранить недостаток физического
покрытия Microservices с измеренными ресурсами, сохранить identity/path/layer guards,
все три SBOM и регрессию; проверить стабильность Windows helper/DB cache, получить
независимые сложные image controls. Для JS — разобраться с bundled fixtures и
пропуском Nest без reference-based filtering. Расширение сторонних build recipes
отложено ради первого выпуска; сборка самого сервиса, тесты и reference checks
продолжаются. Развёрнутые сервисы не изменялись.

Ресурсная политика Java:8GiB disk normalization, отдельно8GiB SHA256 verification
reads;32MiB/read и128MiB суммарных payload windows; outer JAR128MiB/nested32MiB;
16MiB unique ZIP directory ledger,100k entries,256 fingerprints,4096 views/180s
cooperative witness deadline. Hard filesystem quota, peak RSS и безопасная
параллельность больших образов отдельно не доказаны. Начальная Java DB около1.5GiB;
версия/SHA256 сохраняются. Reference labels не используются как cache анализатора.

Исторические R102/R103 benchmark-only результаты и failures сохранены:
[журнал](direct-dependency-experiments.md),
[R102](../benchmarks/results/seekable-payload-v4/evaluation.json),
[R103](../benchmarks/results/explicit-identity-gate-v2/regression.json).
Они отделены от actual runtime выше. Прежняя research-цель20+20 и independent
direct/component >90% не объявлена завершённой.
