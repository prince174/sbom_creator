# Java / JavaScript: точность сервиса и нового reader — 2026-10-16

Сравниваются точные имена **и версии** компонентов итогового `final.cdx.json`. Совпадение количества не считается совпадением компонентов. Все три SBOM (`final/os/full`) сохранены и проверены по schema. Референсы открывает только evaluator после предсказания.

## Java: реальные class/resource bytes, эксперимент R102

| Проект / область оценки | TP / FP / FN компонентов | Precision | Recall = exact-version coverage | Прямые связи |
|---|---:|---:|---:|---|
| Spring Petclinic,92 известных packaged dependencies |90 /3 /2|96.77%|97.83%|16 UNKNOWN/FN |
| Javalin,8 согласованных native/CDX владельцев |128 /0 /0|100%|100%|55 shipped UNKNOWN/FN |
| Dropwizard,16 согласованных native/CDX владельцев |893 /0 /14|100%|98.46%|443 UNKNOWN/FN |

Версии среди совпавших идентичностей: Petclinic98.90%, Javalin/Dropwizard100%. Javalin имеет ещё6 владельцев со scope UNKNOWN; Dropwizard ещё18. Их raw deltas сохранены отдельно, в acceptance они не превращены в успех. Это три раскрытых development-репозитория, а не24 независимых проекта. Нового независимого acceptance нет.

[Воспроизводимая оценка](../benchmarks/results/seekable-payload-v4/evaluation.json), [freeze](../benchmarks/results/seekable-payload-v4/candidate-freeze.json), [регрессия](../benchmarks/results/seekable-payload-v4/regression.json).

Dropwizard улучшился относительно R100:0/0/907 →893/0/14 на тех же16 владельцах. Подтверждены реальные `.class`/resource bytes для2147 из2406 логических записей; это coverage evidence, не отдельная метрика точности. Все14 FN — один `listenablefuture@9999.0-empty-to-avoid-conflict-with-guava`, повторённый у14 владельцев. Физически JAR2199bytes содержит только manifest/Maven metadata, без классов. Его НЕ исключали из референса ради порога: он остаётся FN. [Диагностика](../benchmarks/results/seekable-payload-v4/dropwizard/empty-artifact-diagnosis.json).

Reader один раз нормализует слой и проверяет DiffID/config. ZIP проверяет стандартный parser, `.class` проверяется по magic bytes, ресурсы — по фактическому содержимому. Повторные payload proofs переносятся между файлами только после полного SHA256 каждого физического JAR; имя/версия/ребро из этого не выводятся. Identity/path/layer связываются прежним строгим Syft/Trivy bridge. Изменённый body при одинаковом ZIP directory не переиспользует proof.

Ресурсная политика R102 новая и явно экспериментальная:8GiB disk normalization; отдельно8GiB потоковых SHA256 verification reads (1MiB chunks),32MiB/read128MiB actual payload-window reads,16MiB unique ZIP directory ledger/100k entries/256 indexes,4096 views и180s cooperative witness deadline. Индексы парсятся независимо и закрываются после witness; статистика parsed entries отдельно от unique ledger. На Dropwizard:701,432,545 verification bytes,134,014,511 actual window bytes,703,148,544 normalized bytes. Это НЕ прежняя512MiB политика R100 и не production resource acceptance. Peak RSS/hard filesystem quota не доказаны.

## Что выдаёт сам сервис сейчас

Runtime `src` не менялся относительно baseline4f29791; R102 включён только в benchmark. Сервисный Petclinic по-прежнему имеет0 известных packaged компонентов из92; Petclinic REST —0/106. Javalin известен FAILED_OUTPUT_BUDGET. Новый отдельный запуск **неизменённого** сервиса на Dropwizard завершился ошибкой `image_scan / RuntimeError`, итоговые SBOM не опубликованы; это не нулевой успешный результат. [Свежий baseline](../benchmarks/results/runtime-baseline-r102/dropwizard.json). Экспериментальный final не подменяет production result.

## JavaScript: текущий сервис, без lockfile

Повторно проверены сохранённые результаты неизменённого runtime: hashes reference/final и schemas36 final/os/full. Новый engine scan сейчас не выполнялся.12 реальных пар,8 с непустым component reference;4 пустых не повышают macro. Source/image project lockfiles отсутствуют в производных входах, платформа Node/npm и ОС отдельно, вся inventory сохранена.

| Метрика | TP / FP / FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|
| Компоненты, точные имена+версии |306 /9 /1|97.14%|99.67%|98.39%|
| Прямые связи |102 /0 /1|100%|99.03%|99.51%|

Component macro на8 положительных проектах:P93.48%,R99.88%,F196.08%; owner-status coverage11/12. Conditional version accuracy100%, exact component-version coverage99.67%. Результат раскрытых fixtures с фиксированным `/app/` не доказывает общий production ownership. Слабый проект Axios:P61.54% из-за5 app-local test-fixture extras; Pino имеет1 extra transport fixture; Nest пропускает `@tokenizer/token@0.3.0`. [Все проекты, версии и hashes](../benchmarks/results/runtime-accuracy-r102/javascript.json).

## Что осталось до >90% в сервисе

1. Интегрировать проверенный image reader + engine identity evidence через явные production gates: registry acquisition, ресурсы/конкурентность/диск, сохранение inventory и трёх SBOM. Экспериментальные monkeypatch/trust registration не являются интеграцией.
2. Довести Java source-owner/direct graph: Maven BOM/parent/optional/reactor/profile scope; source Dropwizard timed out180s. Не угадывать прямые связи по наличию JAR. Пока16/55/443 известных direct edges в этих final остаются UNKNOWN/FN.
3. Разобрать scope18+6 владельцев и известные component ошибки (Hibernate, пустой служебный JAR) без фильтрации по эталону; исправить слабые JS fixtures и проверить свежие workspace/optional/peer/no-lock controls.
4. Достроить5 Java и8 JS референсных пар до20+20 основных; заморозить классификатор до новых независимых контролей. Текущий корпус15Java+12JS, плюс отдельный DBCP;28 пар всего. Порог нужен отдельно для языка и для components/direct, с версиями, coverage и регрессией.

377 selected service/prototype tests passed,3 skipped; Ruff/schema checks passed. Все исходные неудачные варианты R102v1/v2/v3 сохранены; v4 — текущий кандидат. Runtime и развёрнутые сервисы не изменены.


## R103: отдельный identity gate, без изменения точности

Новый benchmark-кандидат `explicit_identity_gate.py` разделяет два факта: наличие физических class/resource bytes и подтверждение координат пакета по image/path/layer. Раньше отказ identity bridge технически записывался как неподтверждённый payload. Теперь исходный физический факт сохраняется, а отдельный binding UNKNOWN запрещает включение конкретной записи. Envelope привязан SHA256 к полному adapted catalog и payload observations; это только доверенный внутрипроцессный результат адаптера, не новый пользовательский вход и не механизм аутентификации внешнего SBOM.

Повторно опубликованы девять final/os/full из замороженных R102 catalogs и физических observations, без новых scanner/reader запусков. Все координатные мультимножества и выбранные artifact IDs совпали с R102. У Boot/Javalin/Dropwizard соответственно 1/1/4 записи имеют подтверждённые bytes, но UNKNOWN identity; они остаются вне final. Проверены stale catalog/payload, подмена координат/path/layer, отсутствующий/дублированный audit, sibling с тем же PURL и сохранение npm observations. [Регрессия](../benchmarks/results/explicit-identity-gate-v2/regression.json), [заморозка](../benchmarks/results/explicit-identity-gate-v2/freeze.json).

Это исправление семантики evidence в отдельном прототипе, НЕ рост precision/recall и НЕ интеграция в runtime. Java/JS цифры выше не изменились. Следующий существенный этап — пассивный source-owner graph и профили/модули, затем свежие независимые optional/reactor/Gradle/workspace controls; текущие 16/55/443 direct UNKNOWN/FN не устранены. Нужны ещё5 Java и8 JS реальных пар.
