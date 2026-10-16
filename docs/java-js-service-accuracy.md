# Java / JavaScript: actual service accuracy — R105, 2026-10-16

Измеряется **final.cdx.json самого сервиса** после фактического запуска сканеров,
reader, identity gate и publisher. Референс открывает только evaluator после
завершения прогнозов. Точное имя **и версия** должны совпасть. Repo/commit не
передаются image-only анализу; граф исходников — отдельное обогащение.
Все три SBOM и полный scanner inventory сохраняются.

**Java пока не проходит >90% на всех сложных проектах.** Новый сервис воспроизводит
сильные Java-эксперименты, но новый Microservices образ упирается в payload budget.
JS проходит компонентный порог на измеренной раскрытой выборке; универсальной
гарантии точности для любых образов это не даёт.

## Java: реальные итоговые SBOM

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

## JavaScript:12 свежих image-only запусков без project lockfiles

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

## Граф и оставшиеся шаги до выпуска

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
