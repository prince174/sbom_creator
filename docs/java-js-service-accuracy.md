# Java / JavaScript: actual service accuracy — R107 opt-in experiment, 2026-10-16

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
