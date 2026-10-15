# Журнал экспериментов: прямые зависимости

## B0 — стартовая оценка, 2026-10-13

- Версия: 0.5.0, commit `20f287b60d358692c843526704cd44e71ed4012f`.
- Цель: установить честный baseline перед ежечасными улучшениями.
- Метод: повторно вычислены показатели по 6 размеченным fixture и сохранённым
  результатам 60 тестовых проектов; проверены хеши final SBOM и ground truth.
- Итог: 13 TP / 0 FP / 0 FN / 18 TN для наличия на 31 размеченном случае;
  ещё 276 итоговых идентичностей этих fixture не размечены. Это не direct accuracy.
- По 60 проектам: 10 089 INCLUDE, 2360 UNKNOWN; 4165 записей вне ОС и 6090 пакетов ОС.
- Поиск `sbom.json`, `bom.json`, `*cyclonedx*.json` в benchmark/workspace не выявил
  парных эталонов сборочного плагина; известные final.cdx.json произведены нашим
  сервисом/Syft и не могут служить независимым эталоном.
- Direct precision/recall/F1: **не оценены**, baseline для этих метрик отсутствует.
- Реализация не изменялась. Этот коммит фиксирует оценку, а не улучшение точности.
- Свидетельства: [JSON](baseline-accuracy-20261013.json),
  [таблица](direct-dependency-top5.md), `benchmarks/evaluate_baseline.py`.

Следующий эксперимент: подготовить контролируемый проект с прямой зависимостью A,
её транзитивной B, test/build-only зависимостями и сторонним пакетом базового образа.
Получить CycloneDX при сборке на зафиксированном commit; доказать direct-ребро
корня к A по графу и декларации. Сначала оценить B0 на этом эталоне, затем проверить
гипотезу соединения manifest/lockfile графа с образным evidence. Расширять на шесть
языков и отдельную контрольную выборку. Эталон не передавать анализатору.

## R1 — сборочные эталоны для 60 проектов, 2026-10-13

- По запросу пользователя выполнены контролируемые сборки всех проектов основного
  manifest: по 10 на Java, JavaScript, Python, Rust, Go, Ruby.
- CycloneDX Maven 2.9.3, npm 6.0.1, Python 7.5.0, cargo 0.5.9, gomod 1.12.0;
  Ruby — официальный репозиторий, commit `7efedd6422cc32d9bdefbb6eddb7b4eaa3857309`.
  Опубликованный Ruby 1.1.0 не поддерживает JSON; неудачные попытки сохранены локально.
- Maven package; npm production install/pack и build для axios/lodash;
  Python wheel build/install; cargo auditable build; go build; gem build/install.
  Тесты самих библиотек не запускались: это эталоны указанного профиля сборки.
- Все опубликованные SBOM проверены по официальным схемам 1.5/1.6 и целостности
  ссылок. Для Gson и SLF4J выбран модуль, соответствующий прежнему image recipe;
  агрегатные и Rust workspace SBOM сохранены дополнительно.
- Ruby-плагин не формирует dependency graph. Отдельный native-graph.json получен
  из gemspec собранного пакета и фактически разрешённых Bundler версий. Генераторный
  SBOM не переписан и не выдан за граф, которого он не содержит.
- Для plain lab-python добавлена тестовая упаковка `lab-python 0.0.0+benchmark`;
  это интеграционный fixture с одним app.py, а не авторская декларация зависимостей.
  Для Go assetfinder после исходной GOPATH-сборки добавлен модуль без сторонних deps;
  для Python certifi корень PEP 621 выведен из METADATA установленного wheel.
- R1 не доказывает улучшения алгоритма или точность B0. Новые сборки могут разрешить
  другие версии, поэтому `old_image_pair_verified=false` во всех 60 результатах.
- Следующий этап: подтвердить соответствие версий/профилей старым образам либо
  получить новые парные образы из этих же сборок; затем считать direct TP/FP/FN
  отдельно от наличия библиотек, с разделением provided/build/runtime scope.
- [Сводная таблица](build-references-v1.md),
  [реестр и ссылки на эталоны](../benchmarks/references/build-v1/index.json).
  Рабочий сервис и его политика отбора компонентов не изменялись.

## R2 — проверка сопоставимости R1/B0, 2026-10-13

- Состояние перед работой: main `1b41c10`, дерево чистое, активных benchmark-процессов нет.
- Гипотеза: старые образы можно использовать с новыми эталонами без повторных сборок.
- Проверены совпадение commit и хеши сохранённых source/image Syft, final CycloneDX,
  сборочных SBOM и native-графов. Сопоставление координат намеренно не считается
  доказательством полной PURL-идентичности, парности сборки или прямой связи.
- По 389 корневым рёбрам: 365 совпадений координат в образах, четыре случая другой
  версии, 20 отсутствующих. Совпадающий результат final/image не означает полноту direct.
- Версии расходятся в jinja/werkzeug (MarkupSafe) и psych (date/stringio).
  Следовательно, гипотеза универсальной сопоставимости без новой проверки отвергнута.
- Точные Git blob манифестов показывают: 15 отсутствующих Rust-компонентов объявлены
  build-dependencies; три Java — provided; два Java — optional. Причина отсутствия
  optional-компонентов пока не установлена; все 20 не объявляются FN сервиса.
- У 30 проектов нет положительных корневых рёбер; их нельзя засчитывать как успешное
  подтверждение версий или использовать для завышения метрик.
- Исследованы официальные сведения о cdxgen, Trivy и Syft. В таблице теперь пять
  подходов с явным статусом неоценённых кандидатов; победитель не назначен.
- Проверки: пять unit-тестов диагностического сопоставления, полный аудит 60 пар,
  Ruff. Эталоны неизменны, runtime не менялся. Это коммит отчёта, не улучшение алгоритма.
- Следующий этап R3: один непустой JavaScript-проект (express), runtime-образ и
  CycloneDX из одной сборки, проверка прямых рёбер по package.json. Затем H1 в
  отдельном экспериментальном модуле, без передачи эталона анализатору; контрольную
  часть выборки закрепить до настройки правил. Не запускать повторно R1 целиком.
- [Отчёт](reference-pairing-audit-v1.md), [машиночитаемые рёбра](reference-pairing-audit-v1.json),
  воспроизведение: `python benchmarks/audit_reference_pairing.py`.

## R3 — парная сборка Express и фиксированный holdout, 2026-10-13

- Начало: main `55ca6b2`, дерево чистое, активных benchmark-процессов нет.
- Собран Express из закреплённого commit, CycloneDX npm 6.0.1 выполнен в builder;
  runtime получил тот же каталог приложения, 1048 записей дерева совпали.
- 31 корневое ребро совпадает с production dependencies; версии подтверждены
  lockfile и package.json установленного пакета в runtime. Эталон и генератор
  отсутствуют во входах анализатора. Исходный checkout чистый.
- Отрицательные попытки: `.npmrc` запрещал lockfile (в рецепте явно включён);
  harness сравнивал OCI index и config (исправлена проверяемая цепочка digest).
  После исправления использованы уже готовые артефакты, новая сборка не запускалась.
- B0: 267 final / 89 OS / 356 full; 13 UNKNOWN; все три схемы валидны.
  31/31 координат прямых зависимостей присутствуют, но dependencies пуст:
  direct precision/recall/F1 не определены. Улучшение алгоритма не заявляется.
- Зафиксированы 48 development / 12 holdout, по 2 на язык, до настройки H1;
  это не слепое исследование, предыдущий просмотр R1/R2 раскрыт в протоколе.
- Проверки: 5 unit-тестов harness/partition, повтор хешей/схем/деревьев/версий,
  Ruff. Runtime сервиса не менялся. Время полного прогона и peak resources — null.
- [Отчёт](paired-express-v1.md), [JSON](paired-express-v1.json),
  [split](../benchmarks/direct-evaluation-split-v1.json).
- Следующий шаг R4: H1 как отдельный экспериментальный модуль с code/image inputs;
  Express — development. Не настраивать правила на holdout, не передавать SBOM
  эталона анализатору и не сокращать основной inventory ради красивых direct-метрик.

## R4 — npm H1.1, 2026-10-13

- Начало: main a2dbf94, дерево чистое, дубликаты проверок не запущены.
- Реализован отдельный чистый экспериментальный классификатор, два входа:
  исходный package.json и Syft image JSON. Эталон и build lock не передаются.
- Express development: TP=31, FP=0, FN=0, precision/recall/F1=100%, UNKNOWN=0/31.
  Это узкий результат, не измерение всего сервиса и не доказательство выигрыша
  на контрольной выборке. B0 direct-метрики остаются неопределёнными.
- 21 тест H1, повторная проверка R3 receipts/деревьев/образа/трёх схем, Ruff.
  Неподдерживаемые cases остаются UNKNOWN. Runtime и inventory не менялись.
- Сохраняется как эксперимент, не как принятая реализация улучшения B0.
- Следующее: парные сборки двух JavaScript holdout-проектов и однократная оценка
  зафиксированного H1.1 без настройки на их результатах.
- [Протокол и ограничения](npm-h1-development-v1.md), [рёбра и метрики](npm-h1-development-v1.json).

## R5 — npm holdout, 2026-10-13

- Начало: main 95f4f1e, чистое дерево, активных benchmark-процессов нет.
- H1.1 зафиксирован SHA256 из R4; правила не менялись. Подготовлены парные
  Axios (реальный Rollup build) и isarray (pack), CycloneDX после prune dev.
- Axios: TP=0, FP=0, FN=3, UNKNOWN=3, recall/F1/coverage=0%, precision=null.
  Причина — неподдерживаемые ^ ranges. isarray: нет ни эталонных, ни ложных рёбер;
  метрики пустой положительной выборки null, не 100%.
- H1.1 не принят. Production и три SBOM сохранены. 27 tests, Ruff, hash/tree/image
  checks и схемы трёх SBOM обеих пар прошли; Express R3 перепроверен.
- Ошибки harness: Axios pack/prepare требовал Husky; новый recipe делает build
  с dev-инструментами и prune. isarray graph без dependsOn вызывал KeyError;
  добавлен regression-test и продолжение с готовых образов, без повторной сборки.
- Следующий шаг: независимые development-fixtures для semver/node-semver;
  раскрытый npm holdout использовать далее только для regression. Нужен новый
  заранее фиксированный контроль для следующего решения о внедрении.
- [Протокол](npm-h1-holdout-v1.md), [метрики](npm-h1-holdout-v1.json).

## R6 — независимый npm range matcher, 2026-10-13

- Начало: main 2389927, дерево чистое, benchmark-процессов нет.
- Отдельный эксперимент exact/tilde/caret для полных стабильных версий;
  H1.1 сохранён байт-в-байт. 12 288 синтетических комбинаций сверены с
  node-semver@7.7.2: 0 расхождений, 666 true / 11 622 false.
- На этом наборе UNKNOWN снижен с 4096 до 0; это coverage функции range,
  не улучшение метрик SBOM. Ни один проект/holdout не использован.
- 56 unit/regression tests прошли, Ruff; numeric/length limits и unsupported
  inputs остаются UNKNOWN. Production/три SBOM не изменены.
- Следующее: закрепить новый независимый npm-контроль до интеграции H2;
  затем проверить отдельный H2 на development и раскрытых regression-парах,
  после чего один раз оценить новый контроль. Не внедрять matcher напрямую.
- [Протокол](npm-range-development-v1.md), [метрики](npm-range-development-v1.json).

## R7 — H2.1 и предрегистрация нового контроля, 2026-10-13

- Начало: main 666bbe1, дерево чистое, benchmark-процессов нет.
- До интеграции выбраны Koa/Fastify/Hapi, только ls-remote HEAD; точные SHA
  и протокол сохранены в benchmarks/npm-control-v2.json. Манифесты не читались.
- H2.1 сохраняет тело classify H1.1, меняет только matcher на R6; тест проверяет
  идентичность правил. 67 tests, Ruff, input/reference hashes и 9 SBOM schemas passed.
- Раскрытый regression: Express 31/0/0 без изменения; Axios TP 0→3, FN 3→0,
  FP=0; isarray без ложных рёбер, положительные метрики null. Не независимый gain.
- Production не менялся. H2 и protocol SHA256 заморожены в отчёте до нового контроля.
- Следующее: парные сборки трёх новых control repositories, однократная оценка
  замороженного H2.1; не заменять неудобные случаи и не настраивать правила.
- [Протокол и regression](npm-h2-regression-v1.md), [JSON](npm-h2-regression-v1.json).

## R8 — парные сборки и контроль H2.1, 2026-10-13

- Начало: main d8368f8, дерево чистое, benchmark-процессов нет.
- Все 3 preregistered проекта собраны на точных commit; CycloneDX/npm lock,
  installed versions, app trees и image identity проверены. Oracle не вход H2.
- H1 micro TP=3 FP=0 FN=48; H2 TP=50 FP=0 FN=1. Precision 100% без снижения,
  recall/coverage 5.88%→98.04%, F1 11.11%→99.01%; 3/3 проектов оценены.
- Fastify pino union range остаётся UNKNOWN/FN. Правила H2 после раскрытия
  не менялись. Это узкий npm gain относительно H1, не всех языков и не метрика B0.
- Ошибки harness: scoped group/name (исправлено с тестом, Fastify образ reused);
  Hapi save=false мешал lockfile, v1/v2 failed, v3 с явным save=true успешно.
  Точные рецепты/профили сохранены; неудачные проекты не заменялись.
- 74 tests, Ruff, 9 схем SBOM и hash/installed evidence checks passed.
- Следующий этап: интеграция проверенного npm-профиля без удаления inventory,
  с полным runtime regression/schema/security gate. Union отдельно не расширять
  по раскрытому контролю. H2 production ещё не внедрён.
- [Отчёт](npm-h2-control-v2.md), [рёбра и метрики](npm-h2-control-v2.json).

## R9 — интеграция H2.1, 2026-10-13

- Начало: main 324e198, дерево чистое, benchmark-процессов нет.
- Подтверждённый npm-profile перенесён в src без benchmark imports; версия 0.6.0.
  Manifest loader ограничен и валидирует типы/JSON; unsupported остаётся UNKNOWN.
- Direct edges между существующими package identities в final/full; inventory
  и старые graph edges сохранены. Добавлен direct-dependencies.json, inputs прежние.
- 6 paired replay прошли настоящий Syft convert и pipeline; совпадение с frozen H2,
  18 schema checks. Independent metrics остаются R8, не названы новым holdout.
- Full tests 208 passed; прежний skip и отдельный Windows symlink permission skip.
  Oversized test ID исправлен после ошибки setup, повтор успешен. Ruff passed.
- Следующее: расширение development coverage и следующий язык с парным reference;
  не трактовать оставшиеся компоненты как transitive и не настраивать union по R8.
- [Отчёт](runtime-npm-v1.md), [replay](runtime-npm-v1.json). Deployment не менялся.

## R10 — Python declaration readiness, 2026-10-13

- Начало: main 8f4ed12, дерево чистое, benchmark-процессов нет.
- Проверены 8 Python development по Git blob точного commit; holdout не читался.
  6 static (2 непустых, 4 пустых), 2 UNKNOWN без pyproject. Static name sets
  совпали с R1, но версии/парность/markers не оценены, precision/recall null.
- Набор слабый по разнообразию: два одинаковых Bitbucket manifest и только
  MarkupSafe в обоих положительных проектах. Не объявлять это высокой точностью.
- 5 tests + Ruff passed. Runtime/три SBOM не менялись; отдельный коммит аудита.
- Следующее: парная Jinja wheel/venv/CycloneDX сборка на закреплённом commit,
  проверка installed METADATA и root graph; затем отдельный Python-прототип,
  не использовать host markers или setup.py execution в runtime.
- [Протокол](python-declarations-v1.md), [данные](python-declarations-v1.json).

## R11 — парная Jinja wheel/venv сборка, 2026-10-13

- Начало: main b0b8976, чистое дерево, benchmark-процессов нет.
- Построен Jinja2 3.1.5 wheel, установлен с pinned MarkupSafe 3.0.4;
  CycloneDX 7.5.0 и runtime используют одинаковый /project, tree/config проверены.
- Source/installed/reference подтверждают одно прямое runtime-ребро MarkupSafe.
  Корневая version в reference отсутствует (dynamic в pyproject): UNKNOWN,
  эталон не исправлялся. Babel extra=i18n не выбран в профиле.
- Registry allowlist harness исправлен после image_scan failure; продолжено
  с готовым image archive без повторной сборки. Ошибка root-version проверки
  выявила ограничение reference, теперь явно записано, не превращено в успех.
- 11 tests, Ruff, hashes/OCI/metadata/3 schemas passed. 16 final/106 OS/122 full.
  Python direct accuracy null, runtime не менялся, holdout не использовался.
- Следующее: Syft installed metadata evidence и отдельный Python-прототип;
  static unconditional dependencies, не исполнять setup.py/host markers.
- [Протокол](paired-jinja-v1.md), [проверка](paired-jinja-v1.json).

## R12 — Python P1.0 development, 2026-10-13

- Начало: main aaddd9f, чистое дерево, benchmark-процессов нет.
- Syft сохраняет Requires-Dist и METADATA paths. P1 связывает static безусловное
  source requirement с installed root declaration и пакетом в том же окружении.
- Jinja development: TP=1 FP=0 FN=0, version MarkupSafe 3.0.4 совпала. Это не
  доказательство общей Python accuracy; root version reference отсутствует/null.
- 11 tests + Ruff; R11 revalidation passed. Runtime 0.6.0 и inventory неизменны.
- Ограничения: нет markers/extras/URLs/prerelease/dynamic dependencies; UNKNOWN,
  нет host evaluation. Metadata path, не host-specific sitePackagesRootPath.
- P1 frozen SHA в отчёте. Следующее: paired Flask/Packaging из исходного holdout,
  no tuning; сохранить ограничения nonblind R1/R2 и честно считать UNKNOWN/FN.
- [Протокол](python-p1-development-v1.md), [результат](python-p1-development-v1.json).

## R13 — frozen Python P1, исходный holdout, 2026-10-13

- Начало: main 8fc98cf, чистое дерево, активных benchmark-процессов нет.
- Парные Flask/Packaging wheel/venv/CycloneDX сборки на исходных commit.
  P1 SHA и split проверены; правила не менялись, runtime 0.6.0 неизменен.
- Flask: TP5 FP0 FN0, пять точных версий; conditional importlib-metadata UNKNOWN,
  неактивна в native Python3.12 profile. Покрытие деклараций 5/6, 83.33%.
- Packaging: пустой прямой граф, метрики null; root version reference отсутствует.
  Пять положительных рёбер одного проекта не доказывают общую Python accuracy.
- 16 tests + Ruff; обе реальные сборки и hashes/tree/OCI/METADATA/3 schemas passed.
  Не global blind control; зависимости разрешены при сборке, hashes сохранены,
  fresh network rebuild может дать другие версии. Peak resources не измерены.
- Следующее: hardening недоверенных Python inputs и дополнительный независимый
  положительный контроль до интеграции; не тюнить на раскрытом holdout.
- [Протокол](python-p1-control-v1.md), [данные](python-p1-control-v1.json).

## R14 — input robustness Python P1, 2026-10-13

- Frozen P1 на 16 некорректных синтетических входах: 11 exceptions, 2 DIRECT
  с некорректными ID, 3 UNKNOWN. Достижимость в runtime не доказана.
- Experimental guard: 0 exceptions/невалидных DIRECT на тех же случаях;
  некорректный вход целиком UNKNOWN, coverage null, без изменения frozen P1.
- Jinja/Flask/Packaging predictions полностью равны baseline, включая версии
  и UNKNOWN. На контрольных парах повторены hashes/tree/OCI/metadata/3 schemas.
- 29 tests + Ruff + replay passed. Runtime 0.6.0 неизменен. Не accuracy improvement;
  не готовый production loader, общий ресурсный бюджет ещё не проверен.
- Следующее: независимый положительный контроль, затем bounded loader/integration.
- [Протокол](python-p1-guard-v1.md), [данные](python-p1-guard-v1.json).

## R15 — frozen P1 HTTPX control, 2026-10-13

- Main 5c87b9a, чистое дерево, активных benchmark нет. HTTPX0.28.1 выбран до
  source inspection этого этапа; обнаружен старый source cache/scan, not blind.
- Реальная Hatchling wheel/venv/CycloneDX сборка, source commit закреплён;
  frozen P1 и guard неизменны. TP4 FP0 FN0, versions4/4, UNKNOWN0, coverage100%.
  Root version reference отсутствует/null. Runtime0.6.0 неизменен.
- Ошибка pin hatch-fancy-pypi-readme24.2.0: исправлена на24.1.0; logs сохранены.
- 34tests+Ruff; tree/hash/OCI/METADATA/3schemas passed. Новые immutable refs;
  сетевое повторное разрешение версий не гарантирует идентичной сборки.
- Следующее: bounded source loader и общий input budget, затем Python evidence
  integration/replay. Контроль не использовать для подбора правил.
- [Протокол](python-p1-control-v2.md), [данные](python-p1-control-v2.json).

## R16 — общий бюджет P1 отклонён, 2026-10-13

- Main7d25a74, чистое дерево, benchmark-процессов нет. Experimental root loader
  1МиБ и общий бюджет250000узлов/16Ми символов/глубина64.
- 36tests passed, symlink1skip Windows, Ruff passed. Manifest documents/hashes
  сохранены. Но replay4пар: все UNKNOWN, каталоги305602–317102узла.
- Контроль Flask+HTTPX: TP0 FP0 FN9 (было TP9), recall0, precision undefined.
  Packaging пустой, не успех. UNKNOWN всего анализа отражён count=null.
- Критерий принятия не пройден: никакой runtime/правил P1/guard не менялось.
  Эксперимент сохранён только в benchmarks; это отрицательный результат.
- Следующее: ограниченная проекция полей P1 с equivalence/ambiguity tests,
  отдельно контракт размера Syft; не подгонять общий лимит к контролю.
- [Протокол](python-p1-boundary-v1.md), [данные](python-p1-boundary-v1.json).

## R17 — ограниченная проекция P1, 2026-10-13

- Main72c9774, чистое дерево, benchmark нет. Лимиты R16 не увеличивались;
  бюджет применяется к полям, читаемым frozen P1/guard, все кандидаты/ID сохранены.
- Replay4пар полностью равен guarded P1: Jinja1DIRECT, Flask5+UNKNOWN1,
  Packaging0, HTTPX4. Контроль TP9 FP0 FN0 восстановлен относительно отвергнутого
  R16; относительно исходного P1 accuracy не выросла. Runtime неизменен.
- 57tests+1Windows symlink skip, Ruff, hashes/paired control3schemas passed.
- Ограничение: это parsed-object projection, не preparse Syft JSON limit;
  peak resources не измерены. Не объявлять production-ready.
- Следующее: аудит acquisition/parser контракта размера Syft, затем integration.
- [Протокол](python-p1-projection-v1.md), [данные](python-p1-projection-v1.json).

## R18 — исправлен обход лимита вывода перед Syft JSON parsing, 2026-10-13

- Main0f18bee, clean, benchmark нет. Runtime уже имел max_sbom_bytes64МиБ,
  но race size-check→poll позволял завершившемуся процессу превысить лимит.
- Два детерминированных теста stdout/stderr33при32 падали до исправления;
  добавлена финальная проверка и read(limit+1). Ровно limit принимается.
- 211tests passed,2skip,1knownwarning; Ruff; real Syft1.51.1 version passed.
  128saved catalogs максимум8904584bytes, превышений64МиБ нет. Не новый scan.
- Это runtime resource fix, не accuracy improvement; P1 не интегрирован,
  inventory/3SBOM/API неизменны, deployed services не менялись.
- Следующее: интеграция Python evidence и bounded manifest/projection,
  Python/npm control replay + full regression/schema/security.
- [Контракт и ограничения](syft-input-limit-r18.md).

## R19 — Python P1 integrated,0.7.0, 2026-10-13

- Mainb68f33b, clean, benchmark нет. Перенесены frozen P1/guard/projection и
  bounded root loader; новый runtime packaging26.3, без исполнения проекта.
- Python direct edges добавляются только между компонентами выбранного inventory;
  отсутствующие/неоднозначные owner/target UNKNOWN. Npm-only report совместим,
  mixed profiles объединены; неполный профиль не маскируется unknown_count0.
- Реальный convert+schema/replay4Python+6npm: predictions относительно frozen
  совпадают, component refs/старые edges и3SBOM сохранены. Python control TP9
  FP0 FN0, versions9/9; FlaskUNKNOWN1/coverage83.33%. Packaging empty null metrics.
- 0.6.0 не имел Python direct classifier, его precision undefined;0.7.0 добавляет
  coverage, не заявляется рост accuracy относительно experimental P1.
- 272tests passed,3skipped,1knownwarning; Ruff passed. Release070 повторные
  публикации отдельно от старых immutable refs, новых сборок нет. Deploy не был.
- Следующее: расширять сложные Python профили без тюнинга на контроле; Java/Rust/
  Go/Ruby paired direct evaluation. Не выдавать узкий контроль за60пар.
- [Результаты и ограничения](runtime-python-r19.md), [Python](runtime-python-r19.json),
  [npm](runtime-npm-r19.json).

## R20 — Maven development audit, 2026-10-13

- Maind26b9d5, clean, benchmark нет.8Java development, holdout не читался.
-52root declarations:40test,2provided,10безscope; parent5/8, profiles8/8.
  Gson/SLF4J rootaggregators отличаются от модулей сохранённых references.
- Сохранены raw fields/SHA, management/plugins/profiles отдельно. Не resolver;
  effective scope/version null, pairing false, precision/recall null.
-6tests+Ruff passed. Pytest oversized parameter setup исправлен короткими ids.
  Production0.7.0 неизменен, новых сборок/изменений эталонов нет.
- Следующее: paired Commons Text; effective POM/native graph только evaluation,
  module owner и build/runtime scope не смешивать.
- [Протокол](maven-declarations-v1.md), [данные](maven-declarations-v1.json).

## R21 — paired Commons Text, 2026-10-13

- Mainf0e0310, clean, benchmark нет. Exact commit, pinned Maven image;
  real package + CDX2.9.3 + tree3.8.1 + effective POM/active profiles.
- Root commons-text1.13.0 → commons-lang3 3.17.0 согласован с JAR metadata.
  Artifact-only scratch image содержит2JAR, безJRE/OS, исполнение не проверялось.
- Первое export ожидало sbom.json, parent задаёт другой outputName; исправлен
  путь, failed recipe/log сохранены, сборка повторена. Saved CDX version2.9.3.
-5tests+Ruff и revalidation hashes/tree/OCI/JAR/native/effectivePOM/3schemas passed.
  final2/OS0/full2; Java direct accuracy null, runtime0.7.0 неизменен.
- Следующее: J1 development по source/embedded POM/Syft; effective POM только oracle,
  profiles/parent не исполнять в runtime. Holdout не читать для тюнинга.
- [Протокол](paired-commons-text-v1.md), [проверка](paired-commons-text-v1.json).

## R22 — Java Syft evidence audit, 2026-10-13

- Mainfb3123e, clean, benchmark нет. Source graph13edges (12test,1scope absent),
  image dependency-of0; JavaPomProject schema не хранит declarations.
- Embedded Commons Text POM побайтово равен source; это не effective profile.
  Нетестовый кандидатcommons-lang3 3.17.0, effective scopeUNKNOWN без resolver.
- JSON hashes+R21 tree/OCI/native/JAR/3schemas revalidation и Ruff passed.
  Runtime0.7.0 неизменен; accuracy null. Неверный upstream filename URL404,
  выводы по локальному pinned schema/catalog evidence.
- Следующее: J1 source graph/raw POM/image GAV, сначала наследование/profile
  counterexamples; unresolved scope UNKNOWN. Oracle только для оценки.
- [Протокол](java-syft-evidence-v1.md), [данные](java-syft-evidence-v1.json).

## R23 — J1 scope gate, 2026-10-13

- Main21db3f4, clean, активного benchmark нет. Первый этап J1 только в benchmarks.
- Parent/profiles/management/modules/property expressions блокируют scope inference.
  Кандидат compile/runtime сам по себе не создаёт direct edge.
- Commons Text: все8 raw declarations UNKNOWN, включая подтверждённый эталоном
  commons-lang3. Улучшения coverage нет; в runtime не внедрять.
-12synthetic tests, Ruff, R21 hash/OCI/JAR/native/3schema revalidation passed.
  System scope требует отдельной проверки systemPath, остаётся UNKNOWN.
- Следующее: bounded local parent resolution и реальная development fixture;
  remote parent/неизвестный профиль UNKNOWN. Затем owner/GAV matching.
- [Протокол](java-scope-j1.md), [данные](java-scope-j1.json).

## R24 — local parent identity chains, 2026-10-13

- Mainfe0760f, clean; обнаруженные Python процессы принадлежат codex_worker.
- Эксперимент читает regular Git blobs точного commit, проверяет literal parent
  GAV, relativePath, границы, циклы и бюджеты. Не effective model resolver.
-8development проектов,29POM:10local chains (7с переходом),5outside repository,
  14unresolved/mismatched identity. Включены test/example POM, не module coverage.
-14unit cases и Ruff passed. Новых сборок, изменений runtime и эталонов нет.
  Commons Text UNKNOWN не устранён; улучшение direct accuracy не заявляется.
- Следующее: Gson local inheritance/management + profiles; парный reference
  конкретного модуля до оценки. [Протокол](java-local-parent-v1.md).

## R25 — Gson profile influence audit, 2026-10-14

- Mainb5c768d, clean; только codex_worker Python процессы, benchmark нет.
- Exact source commit и SHA R24: локальная цепочка Gson подтверждена.
  Все4профиля NO_STATIC_REFERENCE_FOUND для dependency sections,2имеютbuild.
- Добавлен аудитор косвенных property references, включая циклы. Это не
  activation/effective-model resolver; settings/CLI/plugins не моделируются.
-36Java tests и Ruff passed. Runtime/эталоны/топ5 неизменны; direct metrics null.
- Следующее: парный Gson module build с CDX/native/effective POM/profiles,
  затем проверка ограниченного наследования. Не использовать R1 как image pair.
- [Протокол](gson-profile-impact-v1.md), [данные](gson-profile-impact-v1.json).

## R26 — paired Gson module, 2026-10-14

- Main1cbf3df, clean, benchmark не запущен. Создан чистый exact-commit checkout.
- Maven pinned image, package + CDX2.9.3 makeBom + tree3.8.1 + effective POM.
  JDK17 active; Gson2.11.0 → error_prone_annotations2.27.0 подтверждены JAR.
- Первая сборка упала из-за отсутствующих test-classes при maven.test.skip;
  убран этот флаг, skipTests сохранён, failed recipe/log оставлены локально.
- Builder/runtime artifact trees совпадают; OCI/config/Syft binding проверен.
  final2/OS0/full2; UNKNOWN30. Scratch безJRE, исполнения приложения нет.
-5общих verifier tests, Ruff, repeat hash/tree/OCI/native/JAR/3schema passed.
  Runtime0.7.0 не изменён, direct accuracy не измерена, holdout не использован.
- Следующее: J1 owner/GAV на парном Gson, bounded local model без oracle input.
- [Протокол](paired-gson-v1.md), [результат](paired-gson-v1.json).

## R27 — Gson owner/GAV evidence, 2026-10-14

- Main4e1ab73 clean, активных benchmark нет. Новый этап J1 в benchmarks.
- Source declaration + module location + dependency-of + unique image GAV:
  Gson2.11.0/error_prone_annotations2.27.0 CORROBORATED_CANDIDATE.
- Direct/scope/build-use не доказаны.3test declarations UNKNOWN на этапе
  identity evidence, их отсутствие не считается runtime FN. Oracle graph не читался.
-8unit cases, Ruff, R26 hash/tree/OCI/JAR/native/3schema revalidation passed.
  Runtime/эталоны/места топ5 неизменны, direct metrics null.
- Следующее: bounded local dependencyManagement/declarations merge;
  scope/owner сравнивать с reference только после prediction.
- [Протокол](java-gav-evidence-v1.md), [данные](java-gav-evidence-v1.json).

## R28 — local dependencyManagement projection, 2026-10-14

- Main611e892 clean, benchmark нет. Новый эксперимент literal management only.
- Gson:4/4GAV+scope совпали с build effective POM, включая восстановленные
  JUnit4.13.2/Truth1.4.2 test versions. Reference читается после prediction.
- Не direct accuracy: одна development model, settings/CLI/plugins неизвестны;
  inherited declarations/import/nonliteral/type/classifier дают UNKNOWN.
-49Java tests и Ruff passed, runtime/reference/top5 неизменны.
- Следующее: controlled Maven parent/override/profile-scope fixture + actual
  CDX/effective POM comparison до принятия direct classifier.
- [Протокол](java-local-management-v1.md), [данные](java-local-management-v1.json).

## R29 — built scope counterexamples, 2026-10-14

- Main06fdbfd clean, benchmark нет.3synthetic fixtures реально package+CDX2.9.3
  и effective POM на pinned Maven image, предсказание до oracle.
- Parent provided и child runtime совпали. Активный profile даёт test,
  prototype сохраняет UNKNOWN. CDX имеет одно ребро во всех3 при includeTestScope.
- SHA/scope/root graph/3schemas revalidation и Ruff passed. Runtime неизменен.
  Не3новых real projects, image replay не делался, direct metrics null.
- Lifecycle plugin versions записаны в effective POM, отдельно recipe не pinned.
- Следующее: frozen J1 candidate pipeline +2paired Java development coverage,
  не скрывать UNKNOWN remote parents/profiles.
- [Протокол](maven-scope-fixture-v1.md), [данные](maven-scope-fixture-v1.json).

## R30 — combined J1 candidate baseline, 2026-10-14

- Main2b0a4fc clean, benchmark нет. Объединены model/owner/sourceedge/imageGAV.
-2paired development: Gson candidate1/reference1; Commons Text0/1,
  whole-model UNKNOWN из-за внешнего parent, unknown_count=null.
- Candidate reference coverage50%, extra0; не direct precision/recall.
  Snapshot6source hashes сохранён. Production/reference неизменны.
-51Java tests и Ruff passed. До принятия нужны независимые случаи и контроль.
- Следующее: inherited declarations development case и source-only конкурент
  на тех же парах; holdout не расходовать на тюнинг.
- [Протокол](java-j1-candidates-v1.md), [данные](java-j1-candidates-v1.json).

## R31 — Syft source graph baseline, 2026-10-14

- Maince520cb clean, benchmark нет. Saved Syft1.51.1 catalogs,2Java dev pairs.
- Raw edges17:2reference GAV matches,15test вне runtime reference (не ошибки).
- Explicit-scope adapter оставляет2/2matches, но оба raw scope absent.
  J1R30 candidate coverage1/2; разные гарантии, superiority не доказано.
- Unit+Ruff passed, hashes checked. Runtime/refs неизменны; Syft строка топ5
  дополнена фактическим сравнением, без места/direct metrics.
- Следующее: source Syft на R29 inherited/override/profile synthetic builds,
  проверить риск адаптера на известном build scope.
- [Протокол](syft-java-source-baseline-v1.md), [данные](syft-java-source-baseline-v1.json).

## R32 — negative scope-filter experiment, 2026-10-14

- Main9372597 clean, активных benchmark нет. Syft1.51.1 source scan3R29fixtures.
- Inherited provided и active profile test имеют raw scope absent; R31adapter
  оставляет обоих. Runtime override сохраняется корректно.2контрпримера.
- Простой explicit-scope filter отклонён для runtime: GAV-match не даёт scope.
  Не общая accuracy Syft; выборка синтетическая, целевая. Runtime unchanged.
- Catalogs отдельно frozen, hashes в report; R29hash/scope/CDX verifier и Ruff passed.
- Следующее: независимый конкурент или paired coverage другого языка;
  J1 не ослаблять до absent scope=compile.
- [Протокол](syft-scope-counterexamples-v1.md), [данные](syft-scope-counterexamples-v1.json).

## R33 — cdxgen pre-build compatibility, 2026-10-14

- Mainaaa47ba clean, процессов benchmark нет. Pinned cdxgen13.4.0 b84786d.
- Node24.19.0, pnpm12.10.1 frozen/ignore-scripts install; pnpm11 отклонён,
  dlx12 native package missing; official Windows binary SHA512 verified.
-2Java source-only pre-build scans с child denied завершились exit1, SBOMнет.
  jvmBom.js816 вызывает Maven tree для parent. Clean-env repeat подтвердил.
- Изолированный output/TEMP; initial fs-read/temp denials сохранены в логах.
  Runtime/source неизменны, direct metrics null, не accuracy failure.
- Ruff passed; топ5 cdxgen статус обновлён. Следующее: isolated build-enabled
  comparison либо Trivy source baseline; не приписывать failed run precision0.
- [Протокол](cdxgen-prebuild-v1.md), [данные](cdxgen-prebuild-v1.json).

## R34 — Trivy Java source comparison, 2026-10-14

- Main47bc776 clean, benchmark нет. Official Trivy0.75.0 Windows SHA verified.
-2Java paired development source: TP2FP0FN0,versions2/2. Только2positiveedges,
  network Maven metadata allowed, не superiority/6language accuracy.
-3synthetic: provided excluded/runtime included/profile excluded. Последнее
  не доказывает activation: inactiveprovided тоже исключён. Нужен counterexample.
-5SBOM1.7 official schema validation, graph unit и Ruff passed. Source/runtime
  неизменны, top5Trivy строка обновлена. Official schemas frozen с outputs.
- ПервыйGson scan без disabletelemetry; протокол это фиксирует, остальные disabled.
- Следующее: baseline runtime→profile test negativecase +independent Java control.
- [Протокол](trivy-java-source-v1.md), [данные](trivy-java-source-v1.json).

## R35 — Trivy profile counterexample, 2026-10-14

- Main1a29ec8 clean, активных benchmark нет. Synthetic defaultcompile→profiletest.
- Trivy source predicted1edge до oracle. Реальный package/CDX2.9.3 с-Pswitch:
  effective scope test, includeTestScopefalse direct0.1runtime extra edge.
- J1 UNKNOWN сохранился. Не общая accuracy и не новый realproject;
  R34positive2edge metrics остаются ограниченной development оценкой.
- Hash/Trivy1.7+reference1.6/schema/scope/graph/J1verification и Ruff passed.
  Runtime/referenceprevious unchanged, top5Trivy limitation дополнена.
- Следующее: независимая paired выборка следующего языка; Java adoption пока
  неизвестные профили не разрешены доказуемо.
- [Протокол](trivy-profile-v1.md), [данные](trivy-profile-v1.json).

## R36 — paired Go hey, 2026-10-14

- Main4e36853 clean, benchmark нет. Development go-hey clean exactcommit.
- Go1.24.13 pinned image; generator1.12.0 officialbinary SHA verified.
  go build + appCDX + native package/module lists + binary build info.
- Первая generation без.git упала; повтор с.git/buildvcs true прошёл,
  failedrecipe/log сохранены. Native directx/net, transitivex/text в binary.
- Binary tree builder/runtime равен, OCI/config/Syft binding passed;
  final4/OS0/full4/INCLUDE4. Presence inventory не directaccuracy.
- Repeat hashes/nativeimports/binarymodules/OCI/3schemas и Ruff passed.
  Runtime0.7.0 unchanged, direct metrics null. Execution/peakresources не измерены.
- Следующее: G1 root go.mod/import +binarymetadata; tags/replaces/workspace UNKNOWN.
- [Протокол](paired-hey-v1.md), [данные](paired-hey-v1.json).

## R37 — Go G1 declared binary candidates, 2026-10-14

- Main6893508 clean, benchmark нет. SourceSyft не имеет owner/directgraph;
  imageedges содержит transitive x/text иstdlib вместе с x/net.
- G1 exactcommit/cleanbuild/mainModule/binarylocation +literal go.mod:
  x/net candidate1 совпал с reference, indirectx/text excluded. Не direct proof.
-10unit cases+Ruff passed. Inputs/ref hashes checked afterprediction.
  Runtime/refs unchanged, direct metrics null, workspace/tags/imports unresolved.
- Следующее: non-indirect dependency из другого main/test/tag, присутствующая
  вbinary транзитивно; проверить FP до принятия G1.
- [Протокол](go-g1-candidates-v1.md), [данные](go-g1-candidates-v1.json).

## R38 — multimain negative labeling/build audit, 2026-10-14

- Main4cd7dec clean, benchmark нет. Synthetichey othermain directlyimports x/text,
  requireindirect removed; localfixturecommit, source derivative отдельно.
- Native selectedmain directx/net; CDXrootmodule edgesx/net+x/text. Labelagreementfalse.
- Binary vcs.modifiedtrue несмотря hostclean. G1 UNKNOWN/unconfirmedcommit,
  FPне доказан; eligible_for_direct_accuracyfalse. Причинаdirtyне установлена.
- Pairtree/binding/3schemas прошли, но этоpresencepair. Immutable failedlabels
  сохранены, не groundtruth. R36repeat verifier+Ruff+hashaudit passed.
- Следующее: новый namespace Linuxcleancheckout/gitstatus beforebuild;
  module-direct и selected-main-import-direct размечать отдельно.
- [Протокол](go-multimain-v1.md), [аудит](go-multimain-audit-v1.json).

## R39 — clean multimain repeat, 2026-10-14

- Mainfb18413 clean, benchmark нет. Новая пара samefixturecommit с Linux
  normalization и statusbefore/after; binarymodifiedfalse/exactrevision.
- G1 candidates2 совпали сmoduleCDXdirect2, selectedmainnativeimports1:
  x/text extra дляselected-main. Это граница G1, не общийprecision.
- Tree/OCI/config/hash/4schemas/prediction revalidation и Ruff passed.
  Runtime0.7.0 unchanged; R38неперезаписан. Dirtycauseнеизолирована.
- Следующее: G2 static import subset сbinaryGOOS/GOARCH/tags; ownermodule/main
  отдельно, unsupportedUNKNOWN; Hey+counterexample затемcontrol.
- [Протокол](go-multimain-v2.md), [данные](go-multimain-v2.json).

## R40 — G2 main selection stage, 2026-10-14

- Mainded2676 clean, benchmark нет. Syft metadata не содержит mainpackagepath.
- External Go1.24.13 AST/MatchFile helper, no projectexecution. Buildcontext
  изimage, customtags/cgounsupported. Hey1maincandidate; multimain2→UNKNOWN.
- Fixturecomments/OSfilename/tests/cgo filtering, actualhelperbuild и Ruff passed.
  Directmetricsnull; coverage loss multi-main explicit, runtimeunchanged.
- Следующее: binary payload debug/buildinfo.Path какexistingimageinput,
  неreferencehint; затемsourceimportgraph. Helper пока толькоbenchmark.
- [Протокол](go-main-selection-v1.md), [данные](go-main-selection-v1.json).

## R41 — binary entry from image payload, 2026-10-14

- Main8e216ef clean, benchmark нет. ExternalGo debug/buildinfo reader noexecution.
- OCI1layer bounded hashchecked payload→entry Path/mainmodule. Hey иmultimain
  entryroot., снимаетR40ambiguity безreferencehint. Cleancommit checks passed.
-2realpayload reads+invalidbinary rejection+Ruff passed. Rootmanifest fieldname
  поправлено platform_manifest_digest. Layerhash/size/entry/binary budgets added.
- Runtime unchanged, directgraphnotimplemented. Singlelayeronly, general malformed
  inputs/whiteouts unsupported. SHAhelper/source/binary inreport.
- Следующее: AST import traversal fromentry/platformcontext, rootmodule only,
  test/othermain excluded; unsupportedUNKNOWN.
- [Протокол](go-binary-entry-v1.md), [данные](go-binary-entry-v1.json).

## R42 — G2 source import traversal, 2026-10-14

- Main8c89515 clean, benchmark нет. ASTindeximports +binaryentry+binarymodules.
- Hey иsynthetic выбранныеmain: G2native matches1+1,extra0,missing0.
  G1syntheticextra1 устранён. Но CDXmodule-root2 vsG2main1 →modulemissing1.
- Не primaryaccuracyimprovement: scope различен, independentcontrol пока нет.
  Runtime unchanged; G2 frozen6files hashes beforecontrol.
-13G1/G2unit tests+actualparserbuild+2replay+Ruff passed. No new projectbuild.
- Следующее: независимая paired control до тюнинга, module/main метрики отдельно;
  корпуса Rust/Ruby ещё требуют paired references.
- [Протокол](go-g2-imports-v1.md), [данные](go-g2-imports-v1.json).

## R43 — fixed Go empty control, 2026-10-14

- Mainbd91b59 clean, benchmark нет. G2freeze6SHA checked before selection;
  fixedholdout go-httprobe, notblindedR1R2 known. Selection saved beforecontents.
- Paired Go1.24.13/CDX1.12 build, nativegraph0/CDXdirect0/G2zero. FP0,
  precision/recallnull: emptycontrol не positiveaccuracy gain.
- Firstharness failed on omittedcomponents emptyCDX. Benchmark-only getdefault[]
  fixed; G2unchanged. Pair2/OS0/full2 presence, not2directdeps.
- Freeze/hash/tree/OCI/4schemas/R36regression/Ruff passed. Runtime unchanged.
- Следующее: positivecontrol доG2acceptance либо Rust/Ruby pairedcorpus;
  никаких правил поholdout не менять.
- [Протокол](go-control-httprobe-v1.md), [данные](go-control-httprobe-v1.json).

## R44 — positive fixed Go control, 2026-10-14

- Mainff8ea90 clean, benchmark нет. Fixedholdout lazygit,6frozenSHA verified
  beforecontents. Go1.24.13 pinned/linuxamd64/CGO0/vendor/CDX1.12 build.
- Native selectedmain33, G2matches33FP0FN0,versions33/33. CDXmodule-root34,
  xoterminfo scope difference1. Не100%primaryprojectgraph, runtimeunchanged.
- Initialmetadata go list -m all failedvendor; mainmodulelisting only заменён,
  fullpackages/binarymetadata retained. No classifier/sourcechanges.
- Fullreplay/hash/binary/cleancommit/OCI/4schemas+13Go tests+Ruff passed.
  Verifier tuple/JSONlist comparison normalized. Pair63/OS0/full63 inventory.
- Следующее: G2production guard/payload/multilayer/helperdelivery design,
  module/main отдельно; Rust/Ruby расширять без тюнинга наcontrol.
- [Протокол](go-control-lazygit-v1.md), [данные](go-control-lazygit-v1.json).

## R45 — Syft Go payload acquisition bridge, 2026-10-15

- Maine35bf82 clean, benchmark нет. Productionalready SyftFiles content reader,
  но binarypaths нетвglobs. Experimental singleexactpath config, runtimeunchanged.
- Hey11.7MB/Lazygit29.3MB payload SHA match, packageinventory/edges unchanged.
  PrivateJSON15.6/39.1MB under64MiB, payloadlimit32MiB.
-2layeroverwrite image returnsnewbinary, notstale; graphunchanged.3scancomparison
  +Ruff passed. Registry/deletions/manybinaryaggregateguards ещёнепроверены.
- No project builds/new directmetrics. FrozenG2notchanged; этоacquisitioncheck.
- Следующее: deletion/oversize/registryidentity +helperdelivery beforeintegration.
- [Протокол](syft-go-payload-v1.md), [основной](syft-go-payload-v1.json),
  [overlay](syft-go-overlay-v1.json).

## R46 — payload deletion/size boundaries, 2026-10-15

- Main6cef34b clean, benchmark нет. External deleted/missing/oversize fixtures.
- Actual image application/.wh.app проверен; finalSyft pathabsent, oldbytes
  не возвращены. Missingpath и32MiB+1regularfile тоже unavailable.
-3failurechecks повторены сwhiteoutaudit, Ruff passed. Runtime unchanged,
  no directaccuracy improvement, no userapplication execution.
- Следующее: registry/auth/digestpinning, aggregatebudget/helperdelivery/guard
  передG2integration; frozencontrolrulesunchanged.
- [Протокол](syft-go-payload-failures-v1.md), [данные](syft-go-payload-failures-v1.json).

## R47 — aggregate Go payload budget, 2026-10-15

- Main20ca1fc clean before experiment; no duplicate benchmark running.
- Metadata preflight: total decoded payload <=32MiB, literal unique targets,
  regular files, conservative base64/JSON estimate within64MiB output cap.
- Actual scratch image: Hey11,718,317 + Lazygit29,263,807 bytes. Singles pass;
  combined40,982,124 returns whole UNKNOWN before any content scan. No silent
  target truncation; unknown dependency count null.
- Eight pytest cases, Ruff and actual metadata scan passed. Parsed metadata
  memory is not bounded by this preflight; output estimate is not a RAM proof.
- Negative acceptance result: tighter resource budget reduces multibinary
  coverage. Keep experimental; no runtime adoption or directaccuracy claim.
- Next: registry/auth/digestpinning and helperdelivery/productionguards.
- [Protocol](go-payload-aggregate-v1.md), [data](go-payload-aggregate-v1.json).

## R48 — reject mismatched payload identity, 2026-10-15

- Main247add5 clean, no benchmark running. Continued acquisition guard checks.
- Real Syft rescans of Hey/Lazygit with deliberately wrong expected config SHA
  both rejected before returning payload. R45 retains matching-identity positives.
- Targeted scanner tests and Ruff passed. Registry digest unit tests use mocked
  metadata; no live registry/authentication claim. Official Syft source docs
  confirm explicit registry backend exists, experimental bridge remains archive-only.
- No runtime/classifier change or direct accuracy gain. Next: controlled registry
  fixture, auth isolation and mutable-tag/digest identity, then helper delivery.
- [Protocol](go-payload-identity-v1.md), [data](go-payload-identity-v1.json).

## R49 — registry payload/tag-race fixture, 2026-10-15

- Maind067bfa clean, no duplicate check running; inspected existing registry
  harness and pinned Syft registry configuration source before implementation.
- Dedicated loopback registry: Hey tag scanned, replaced with clean multimain
  image, changed expected config rejected; original immutable manifest rescan
  retained original payload. Actual network scans, no mocked registry metadata.
- Ruff and24 targeted tests passed; owned registry container removed. Docker
  only in external fixture harness; production/frozenG2 unchanged.
- Limit: unauthenticated loopback HTTP only. TLS/auth/isolation/index behavior
  not claimed, direct accuracy null. Next: authenticated TLS fixture and helper
  delivery/production guards. No algorithm acceptance or top5 ranking change.
- [Protocol](go-registry-identity-v1.md), [data](go-registry-identity-v1.json).

## R50 — authenticated TLS payload fixture, 2026-10-15

- Main6771828 clean; no benchmark running, unrelated services untouched.
- Read pinned Syft registry option source. Optional CA/auth in experimental
  registry scan helper; isolated temporary Docker config and random test password.
- Actual TLS/basic-auth read passed; missing/wrong credentials, wrong authority
  and unrelated CA all rejected. No raw scan/credential data in report.
- Owned loopback registry and temporary key/password files removed. Ruff,
  R49 tag-race regression and24 targeted tests passed.
- No production/classifier acceptance, direct accuracy null. Limits: no bearer
  flow/proxy/index/general isolation proof. Next: helper delivery/guards with
  module-root and selected-main meanings kept separate.
- [Protocol](go-registry-auth-v1.md), [data](go-registry-auth-v1.json).

## R51 — compiler-free Linux helper delivery, 2026-10-15

- Main6f95734 clean; no duplicate experiment running. Frozen R42 hashes verified.
- Pinned Go1.24 offline build of two passive readers; two different source paths
  produce identical binaries with trimpath/buildvcsfalse. Same builder, not an
  independent reproducible toolchain claim.
- Scratch/nonroot/read-only/no-network/cap-drop readers match frozen Windows
  outputs exactly on Hey source+binary. No application build or execution.
- Ruff +13 G1/G2 tests passed. No production Dockerfile/runtime/classifier
  change, accuracy null. This removes packaging uncertainty only.
- Next: bounded invocation and unsupported-build guards before integration;
  keep module-root and selected-main metrics separate.
- [Protocol](go-helper-delivery-v1.md), [data](go-helper-delivery-v1.json).

## R52 — experimental G2 context gate, 2026-10-15

- Main097b61e clean, no duplicate benchmark running. Frozen G2 files unchanged.
- Separate pure eligibility gate rejects unsupported metadata before traversal;
  includes duplicate settings and module-prefix collision/path traversal guards.
- Actual Hey metadata positive +13 negative mutations pass. G1/G2 regression:
  total27 tests, Ruff passed. Eligible does not mean proven direct dependency.
- No runtime acceptance or accuracy claim; corpus coverage remains unmeasured.
  Next: bounded invocation/hostile input checks and positive-control replay.
- [Protocol](go-g2-context-v1.md).

## R53 — bounded context-gated replay, 2026-10-15

- Main7a52764 clean, no duplicate benchmark running. Frozen hashes checked.
- Passive helpers bounded to30s/4MiB output, payload32MiB. Existing four fixtures
  remain eligible; unchanged selected-main TP1/1/0/33, all FP0/FN0.
- Empty httprobe P/R null; partitions separate. Gate4/4 only known cached set,
  no new accuracy gain or general coverage claim. Runtime unchanged.
-27 tests passed. Initial Ruff B023 fixed by explicit context binding, then passed.
- Next: hostile helper inputs and whole-corpus coverage before any integration.
- [Protocol](go-context-replay-v1.md), [data](go-context-replay-v1.json).

## R54 — passive helper negative inputs, 2026-10-15

- Main98227d9 clean, no duplicate check running. Frozen helper sources unchanged.
- Invalid/oversized binaries and malformed/oversized source rejected under5s/
  4KiB invocation budgets. Valid panic-init source parsed without executing init.
- Ruff passed; acquisition/context suites40 passed1 platform skip. Temporary
  inputs removed. Deterministic examples only, no general security/accuracy claim.
- Runtime unchanged. Next: original Go corpus eligibility/UNKNOWN audit before
  integration, with paired reference expansion evaluated separately.
- [Protocol](go-helper-failures-v1.md), [data](go-helper-failures-v1.json).

## R55 — ten-project Go source prerequisite audit, 2026-10-15

- Main40e8a2a clean; no duplicate benchmark running. Exact commits/clean trees
  and frozen rule hashes verified, unchanged development/control membership.
- Source parser10/10, narrow declaration reader7/10. Assetfinder missing root
  go.mod; yq/upterm unsupported syntax. These stay UNKNOWN, no rule relaxation.
- Binary context UNKNOWN for all rows in this source-only audit; not a claim
  that prior paired evidence vanished. No direct coverage/accuracy metrics.
- Ruff +27 tests passed. Runtime unchanged. Next: paired waybackurls development
  build/image reference, then other development fixtures and Rust/Ruby expansion.
- [Protocol](go-corpus-context-v1.md), [data](go-corpus-context-v1.json).

## R56 — paired waybackurls development build, 2026-10-15

- Main66b7868 clean, no duplicate build running. Controlled exact-commit build
  with pinned Go1.24/CGO0/linuxamd64 and CDXgomod1.12 during actual build.
- Immutable reference receipt, binary/tree/image binding and three output schemas
  checked. Native/CDX/G2 external edges0; P/R null, not accuracy improvement.
- Runtime inventory2/OS0/full2 reflects app+stdlib, not two direct dependencies.
- Passive verifier +Ruff passed. Production/frozen classifier unchanged.
- Next: paired unfurl development positive fixture, then Rust/Ruby expansion.
- [Protocol](paired-waybackurls-v1.md), [data](paired-waybackurls-v1.json).

## R57 — positive paired unfurl development fixture, 2026-10-15

- Main6b1dbce clean, no duplicate build running. Exact-commit pinned build/CDX
  reference and image pair created; tree/binding/three schemas checked.
- Frozen G2/native/CDX build root agree DomainParser1 exact version. Additional
  tldomains declaration retained separately, absent from build root graph.
- Generic recipe loop variable accidentally named app generator-provenance.json;
  actual binary identity/bytes verified. Immutable receipt preserved; generator
  corrected for future builds, verifier uses sole regular application file.
- Passive verification, waybackurls regression, Ruff and17 tests passed.
- No runtime/control accuracy improvement claimed. Next: Rust/Ruby paired corpus.
- [Protocol](paired-unfurl-v1.md), [data](paired-unfurl-v1.json).

## R58 — Rust fd reference scope audit, 2026-10-15

- Main7d3319c clean, no duplicate experiment running. Started Rust expansion by
  auditing existing reference before fresh pairing; no new build claimed.
- CDX22 root edges mapped by exact Cargo package IDs: normal21/build1.
  Retained metadata unfiltered by platform, so activation remains UNKNOWN.
- Official Cargo metadata documentation checked; scope kind is not proof of
  execution in Linux build. Old image remains unpaired; accuracy null.
- SBOM provenance hash and Ruff passed. Runtime unchanged. Next: fresh fd pair,
  explicit target/features/profile and filtered metadata plus build artifacts.
- [Protocol](rust-fd-scopes-v1.md), [data](rust-fd-scopes-v1.json).

## R59 — Rust fd build checkpoint, 2026-10-15

- Main78b99ee clean, no duplicate build running. Fresh pinned-base exact-commit
  fd build/runtime stages completed in .work/paired-fd-v1; logs/IDs retained.
- Explicit GNU Linux target/default features/debug/locked build. CDX0.5.9,
  cargo-auditable0.6.6; filtered +unfiltered metadata and tool versions exported.
- Actual generator help confirms default host target. Ruff passed; runtime
  service unchanged. No paired receipt/accuracy claim yet.
- Next: continue existing stage IDs, validate tree/archive/schema/edge scopes
  and analyzer replay. Do not launch a duplicate build.
- [Checkpoint](paired-fd-checkpoint-v1.md).

## R60 — Rust fd pair validation completed, 2026-10-15

- Main89a3d83 clean, no duplicate build. Continued R59 IDs; no rebuild.
- Builder/runtime trees equal, archive/config identity bound to analyzer image;
  three output1.6 schemas and reference1.5 schema verified.
- Initial wrong1.6-only reference validation fixed by existing benchmark1.5
  validator. Existing finished analysis resumed without overwriting outputs.
- Immutable receipt includes target-filtered metadata;22 root edges normal21/
  build1 mapped. Execution not inferred. Baseline UNKNOWN retained, accuracy null.
- Ruff/pairing-reference tests passed. Runtime unchanged. Next: Rust declaration
  ownership/scope assessment on development pair and Ruby paired expansion.
- [Protocol](paired-fd-v1.md), [data](paired-fd-v1.json).

## R61 — fd source ownership/scope association, 2026-10-15

- Main89ed4e0 clean; no duplicate experiment. Source-only extraction26 root
  declarations before opening reference; version requirements remain unresolved.
-22 build reference edges uniquely associated by name/kind/target. Four other
  declarations retained; activation UNKNOWN. Association is not direct accuracy.
- Cargo docs checked; alias/optional/inheritance preservation test and Ruff pass
  after exception-type lint correction. No runtime change.
- Next: lockfile/image version-owner ambiguity assessment on development pair.
- [Protocol](fd-declarations-v1.md), [data](fd-declarations-v1.json).

## R62 — fd lock/image version association, 2026-10-15

- Mainaa9395d clean, no duplicate check running. Source/lock/image candidate
  association precedes oracle access; uniqueness and default registry required.
-20 associated versions overlap22 reference edges; two remain without candidate,
  no outside associations. This is not direct-edge proof or accuracy improvement.
- Activation UNKNOWN, direct_edge_provenfalse, ambiguous/missing rows retained.
  Cargo requirement solving/overrides not implemented; no runtime adoption.
- Two tests and Ruff passed. Next: inspect missing identities before control
  evaluation, without silently reducing coverage.
- [Protocol](fd-versions-v1.md), [data](fd-versions-v1.json).

## R63 — explain fd UNKNOWN identities, 2026-10-15

- Main6606d20 clean, no duplicate checks running. No candidate rule changes.
- nix0.24.3/0.29.0 both in lock/image; root requirement0.29.0 retained, no
  unimplemented Cargo resolution replaced by newest/first heuristic.
- version_check0.9.5 declared build scope, in lock, absent from image. Expected
  lifecycle distinction, not automatically scanner error or runtime dependency.
- Evidence assertions and Ruff passed. UNKNOWN retained, direct accuracy null.
- Next: Ruby paired reference; defer Rust requirement solver/control evaluation.
- [Protocol](fd-unknowns-v1.md), [data](fd-unknowns-v1.json).

## R64 — user priority Java/JavaScript, 2026-10-15

- User explicitly narrowed priority to Java/JavaScript, reference images and
  three closest techniques; direct dependencies first. Defer Rust/Ruby expansion.
- New source competitor runs on Koa/Fastify/Hapi/Gson/CommonsText. Koa Trivy18/0/0,
  cdxgen18/5/0; our prior18/0/0. No global ranking from one comparable project.
- Fastify/Hapi source graphs UNKNOWN; Java Trivy Maven429, cdxgen child denied.
  Retain failures, no empty-graph success. Reference not supplied to scanners.
- Adapter recognizes Trivy root package-lock wrapper; two tests/Ruff pass.
- Next: legitimate image manifest/lock acquisition for source+image variants,
  Java paired expansion and comparable coverage before final top3 selection.
- [Comparison](java-js-top3.md).

## R65 — npm image manifest/lock comparison, 2026-10-15

- Maincac1324 clean, no duplicate check running. Existing runtime exports contain
  root locks for Fastify/Hapi; extracted bounded regular files, no reference input.
- Same image manifests/locks: Trivy51/4/0, cdxgen51/52/0 on Koa/Fastify/Hapi.
  Our saved H2.1 baseline50/0/1. Preliminary npm ordering only; excess scope
  edges retained, not oracle-filtered. Trivy recall tradeoff explicitly recorded.
- Six SBOM schemas and two adapter tests passed. Ruff import ordering fixed,
  then passed. No runtime change. Next: excess-edge scope audit/production modes
  and Java comparison, not Rust/Ruby expansion.
- [Comparison](java-js-top3.md), raw results under results/npm-image-manifests-v1.

## R66 — npm competitor scope normalization audit, 2026-10-15

- Main7fe7bef clean, no duplicate running. All4 Trivy and49/52 cdxgen excess
  edges map to dev-only root declarations. Raw production-scope mismatch is not
  automatically wrong declaration discovery.
- Manifest-only dev exclusion before oracle: Trivy51/0/0, cdxgen51/3/0; existing
  H2.1 50/0/1. Preliminary ordering changes. Disclosed cases, no independent gain.
- Evidence assertions/re-evaluation and Ruff pass; runtime unchanged. Next:
  fresh Java/JS paired comparison and external reference-verification command.
- [Evidence](npm-competitor-scopes-v1.md).

## R67 — optional post-analysis reference evaluation, 2026-10-15

- User authorized production/verification modes and20 Java/JS paired projects.
  Production defaults unchanged; reference only evaluated after runner completes.
- CLI/API optional verification with reference CycloneDX1.6,8MiB validation,
  explicit runtime scope; missing owner/profile/scope =>UNKNOWN. Build binding
  caller-asserted, no cryptographic attestation claim. No classifier gain claimed.
-274 tests passed3 skipped, Ruff passed; known Starlette deprecation warning.
  Three inventory outputs unchanged. First stage only,20-pair target outstanding.
- New user question: prefer ready-made engines and standard postbuild/package
  manager approaches; do not duplicate complete Maven/npm resolution logic.
- [Contract and limitations](verification-mode.md).

## R68 — real npm verification replay, 2026-10-15

- Maine309fc8 clean initially; continued user Java/JS task. Existing six npm
  runtime results reproduce31/3/0/18/14/18 TP and only Fastify FN1, no FP.
- Empty isarray metrics null. Added missing/extra coordinates, version accuracy,
  declaration coverage and input/result hashes; equal-count wrong-version test
  produces FP1/FN1 rather than success. No classifier changes.
- Targeted API/evaluator tests and Ruff passed. Next: finish new Debug pair
  already building, then remaining Java/JS corpus. No duplicate build.
- [Replay](evaluation-replay-v1.json).

## R69 — Debug JavaScript pair, 2026-10-15

- Continued already-running Debug build; no duplicate. CycloneDX build/root ms
  dependency matched runtime and evaluator TP1/FP0/FN0, versions1/1, UNKNOWN0.
- Tree/image binding/three schemas passed in pairing harness; Ruff passed.
  Only harness project choices extended; classifier unchanged.
- User reiterated Java/JavaScript only. Seven JS/two Java pairs complete.
  Next: remaining JS builds and Java expansion; other languages deferred.
- [Pair](paired-debug-v1.md).

## R70 — Chalk pair and API reference isolation, 2026-10-15

- Existing Chalk build completed; no duplicate. Tree/image binding/three schemas
  passed. Empty direct graph yields0/0/0 with null accuracy, not100% success.
- API test verifies reference never passed to runner, evaluation happens after
  analysis, artifact authenticated/downloadable. Eight API/evaluator tests pass.
- Ruff passed. Eight JS/two Java pairs now complete. Next: ms/commander then
  Java expansion; workspace/optional/profile coverage tracked separately.
- [Pair](paired-chalk-v1.md).

## R71 — ten JavaScript reference pairs reached, 2026-10-15

- Continued sequential ms/commander builds, both completed. Tree/config binding
  and three schemas passed. Immutable receipts retained; no classifier changes.
- Ten JS references now ready, Java remains2. Replay all ten uses saved R19
  results for first six and current results for new four. ms direct evaluation
  UNKNOWN, empty Chalk/Commander metrics null; no artificial accuracy gain.
- Next: Java Commons Compress pair and eight remaining Java projects, explicit
  workspace/optional/profile coverage; other languages deferred.
- [Status](java-js-pair-status.md), [evaluations](java-js-pair-status.json).

## R72 — Java Commons Compress pair, 2026-10-15

- Completed earlier-running build, no duplicate. Seven direct edges agree
  CDX/native/effective POM; tree/config binding/three schemas checked.
- Replay validates receipt hashes/root labels. Existing Java pairing tests pass;
  generic harness Ruff passes. Three Java/ten JS pairs now complete.
- User explicitly requires >90% components for Java/JS too: score exact package
  identities/versions independently from direct-edge metrics, not count equality.
- Next: seven remaining Java pairs, then three-technique comparison.
- [Pair](paired-commons-compress-v1.md).

## R73 — Commons Lang Java pair, 2026-10-15

- Exact-commit controlled Maven/CDX build, clean source, root graph agrees native/effective POM; empty runtime graph remains unscored.
- Artifact tree, image binding and four schemas pass. Four Java pairs complete.
- Next: Commons IO, then remaining Java pairs, component and direct comparisons separately.

## R74 — Commons IO Java pair, 2026-10-15

- Exact-commit Maven/CDX pair completed, tree/config binding and schemas pass. Empty direct graph unscored. Five Java pairs complete. Next: Commons Codec.

## R75 — component identity baseline, 2026-10-15

- Component identity/version scoring added as separate benchmark. Known fixture
  app paths only; whole-image platform records retained, no runtime filtering.
- Commons Compress7vs7 hides two namespace mismatches (ASM/XZ), only5exact matches.
  Some npm app-local extras remain. No >90% acceptance or alias guessing.
- Equal-count mismatch/empty tests and Ruff pass. Next: finish Java pairs and
  compare identity resolvers against fixed references. Codec build already running.
- [Baseline](project-components-baseline-v1.md).

## R76 — Commons Codec Java pair, 2026-10-15

- Exact-commit build/CDX/native/effective graph agreement; empty direct graph remains unscored. Tree/config binding and schemas pass. Six Java pairs complete. Next: Commons CSV.

## R77 — Commons CSV Java pair, 2026-10-15

- Exact-commit Maven/CDX/native/effective POM agree two direct runtime edges; tree/config binding and schemas pass. Seven Java pairs complete. Next: Jsoup.

## R78 — Jsoup Java pair, 2026-10-15

- Exact-commit Maven/CDX/native/effective graph agreement; zero external direct runtime dependencies unscored. Tree/config binding and schemas pass. Eight Java pairs complete. Next: SLF4J module.

## R79 — SLF4J module Java pair, 2026-10-15

- Exact-commit slf4j-api module in multi-module checkout built with CycloneDX makeBom; effective/native module owner agrees, direct runtime graph empty. Tree/config binding and schemas pass. Nine Java pairs complete. Next: Commons CLI.

## R80 — ten Java reference pairs completed, 2026-10-15

- Commons CLI exact-commit Maven/CDX pair verified; native/effective empty runtime root, tree/config binding and schemas pass.
- Ten Java and ten JavaScript pairs now complete. Empty positive graphs do not inflate accuracy. Next: full20-pair technique comparison with component and direct scopes separate.

## R81 — full20-pair comparison and optional fingerprint candidate, 2026-10-15

-40 competitor attempts completed;30 SBOM schemas valid. TrivyJava7/0/4,
  JS components188/0/0; passive Java cdxgen unavailable. No missing-run zero success.
- Fixed shallow nested-component evaluation; regression test added. Raw Syft
  fixture-scope Java9/2/2, JS188/8/0. Preserve platform inventory separately.
- Exploratory explicit optional declarations + image claims + repository SHA256
  resolves four missing Java candidates:11/0/0. No oracle hints/alias table.
  No runtime adoption or independent gain claim; freeze/control needed next.
-275 service tests pass3 skipped; targeted graph/count/optional tests and Ruff
  pass;20-pair status updated. User's >90% production goal not yet complete.
- [Comparison](java-js-twenty-comparison.md).

## R82 — independent positive Java control and nested evaluator, 2026-10-15

- Candidate 374eb33 hashes frozen before new Commons DBCP 2.13.0 build; annotated tag peeled to exact commit 3cccba8e127cf55a4a30c5056e0bb9ec09446fd7. New real Maven/CDX/image pair, tree/config/schema checks passed.
- Unchanged prediction yields 3/0/0 components and direct candidates. No optional declarations: this control does not independently validate the optional fingerprint correction. No production >90% claim. See java-positive-control-v1.json.
- Runtime evaluator now indexes nested components and metadata owner; regression covers nested root and dangling analysis targets. Full service suite 276 passed, 3 platform skips; Ruff passed.
- User clarified lockfile may be absent in production. Lock-assisted JS scores are a separate favorable stratum; they cannot establish no-lock production accuracy. Next: source manifest plus image package metadata replay without source or image lockfiles; UNKNOWN for unresolved owners/versions.
- cdxgen13.4 Java failure diagnosed in jvmBom.js createJavaBom: attempts Maven dependency:tree -N through safeSpawnSync despite passive flags; Node child-process policy rejects it. Not a general Java capability failure.

## R83 — build-enabled cdxgen Java comparison, 2026-10-15

- Corrected the overly restrictive competitor protocol: cdxgen13.4 may execute Maven in an external capability-dropped container without secrets/socket. Service runtime remains passive. Source read-only; oracle only read after prediction; all 11 schemas and zero process exits checked.
- Original 10 Java projects: components/direct11/0/0 on four positive roots. Frozen DBCP control3/0/0. Six empty roots do not inflate accuracy. This substantially improves cdxgen's measured Java compatibility, but does not satisfy production integration because it invokes project build tooling.
- [Detailed report](cdxgen-build-enabled-v1.md), commands/tool versions/image digest/raw logs retained. CPU/memory limits are not peak usage. No cross-mode speed ranking.
- Explicit fixed20 development selection prevents new control receipts entering tuning replays. Targeted graph/count/optional tests7 pass and Ruff passes. No runtime algorithm change in this stage.

## R84 — service replay without JS project lockfiles, 2026-10-15

- All10 disclosed JS fixtures replayed with project lockfiles absent from source and runtime /app. No install/resolution/project execution. Non-lock file/mode/link/hash tree equality, derivative OCI/scanned-config binding and final project projection verified. Original reference pairs unchanged.
- Exact components188/8/0, P95.92%, R100%, F197.92%; positive-root macro P92.59%, R100%. Direct85/0/1, P100%, R98.84%, F199.42%. Owner-status coverage9/10; UNKNOWN ms has zero known reference direct edges, not counted as success. Four empty roots excluded from accuracy means.
- Axios component precision61.54% and Fastify94% remain visible; eight test/benchmark fixture coordinates retained. Existing pino direct FN retained. Lock-assisted engine scores do not substitute for this no-lock service replay.
-284 tests passed,3 skipped; Ruff and30 schema/payload/binding checks pass. [Report](java-js-no-lock-v1.md). No runtime algorithm improvement claimed; next independent generic ownership validation and passive Java integration. Automation updated to preserve no-lock and full external cdxgen requirements, stale pair counts corrected.

## R85 — stratified expansion frozen; first larger Java pair, 2026-10-15

- Added20 exact-commit candidate repositories, ten per priority language; target20 primary pairs per language. Six development/four holdout per language, candidate hashes and root-source snapshots frozen before tuning. Planned cases include Spring applications, Maven reactors (Dropwizard34 declared modules), Gradle/Kotlin, pnpm workspaces, TypeScript compilation and native/peer/optional packages. Pinned is not built or scored.
- Commons Configuration2.11.0 real Maven/CycloneDX/image pair completed:15 direct runtime edges, native/effective/CDX agreement, tree/config binding and three service SBOM schemas checked. This single new root has more direct edges than all previous ten Java primary roots combined. No classifier adjustment or accuracy improvement claimed.
- [Sampling/admission/holdout protocol](java-js-expanded-corpus-v1.md). Large applications, module owners and resource failures stay explicit; empty monorepo roots cannot establish success. Next: Pino held-out pair, runnable Spring Boot image, then per-module recipes for remaining pinned candidates.

## R86 — executable application pairs and new no-lock controls, 2026-10-15

- Expansion now adds4 pairs total (Configuration from R85, Spring Petclinic, Pino, compiled Nest starter):25 verified build/SBOM/image triples overall,13Java/12JS including the separate DBCP control.16 frozen expansion candidates remain unbuilt. Native npm root versions verified for both new JS controls; app/logging/health smoke checks pass in isolated disposable containers.
- Pino no-lock: components12/1/0, direct11/0/0. Nest no-lock: final components106/0/1, direct6/0/0. Native graphs, bound derivative payloads and existing final/os/full invariants validated. Missing type package and extra fixture retained; no holdout classifier tuning.
- Spring real fat JAR65,830,920bytes exceeds32MiB payload budget, yielding zero final app matches and extensive payload/identity UNKNOWN. Raw inventory66/26/40 vs build SBOM is DIAGNOSTIC only: starters/POMs, devtools, packaging tools and resource-JAR scope are not fully adjudicated, so acceptance metrics are null rather than fabricated runtime ground truth. Boot image itself passes health UP.
- No-lock guard exposed raw-image/final-output divergence for Nest. Scoring now uses final service output with raw inventory separately; no rescans duplicated, resume-only timing labelled. Original10 JS no-lock baseline unchanged. Failed partial-clone acquisition preserved, recovered with clean upstream source.
-298 tests passed3 skipped; acquisition/payload targeted15 passed; Ruff, reference and three-view schemas, tree/config/native/smoke checks pass. Production source unchanged from4f29791. [Report](java-js-expanded-results-v1.md). Next: scoped boot reference labels, bounded large-JAR regression, then remaining Maven/Gradle/workspace recipes; no global >90% completion claim.

## R87 — Boot packaging truth and first reactor attempt, 2026-10-16

- Evaluation-only SHA256 linkage now labels all106 Petclinic build artifacts from the primary real-build CycloneDX oracle and copied dependency bytes. Actual nested JAR hashes confirm92 packaged dependencies:90 class-bearing and2 resource-bearing;14 build artifacts are absent (13 metadata-only starters and devtools). Preserve16 build-direct edges separately from9 packaged direct edges. Packaging presence does not prove execution.
- Six coordinates missing from the filtered native tree are confirmed by unique primary CycloneDX hashes, not guessed aliases. One packaging-added jarmode-tools JAR remains UNKNOWN. No reference is exposed to classifiers; runtime source and32MiB limits remain unchanged. This is evaluation evidence, not improved service accuracy.
- Immutable reports: [v1](../benchmarks/results/boot-packaging-labels-v1/report.json), [v2](../benchmarks/results/boot-packaging-labels-v2/report.json), [v3](../benchmarks/results/boot-packaging-labels-v3/report.json), with source snapshots. v1 resource taxonomy was wrong for META-INF/resources; v2 corrects it; v3 completes primary-hash labels. Tests cover resources/multi-release classes and ambiguous coordinate/hash matches.
- First pinned Javalin reactor build failed before compilation: git-commit-id plugin requires .git, omitted from the external build context. Reactor reports19 projects including nested modules, not merely8 root declarations. Pair remains incomplete and uncounted; original25 pairs unchanged. Failed recipe/log preserved in benchmarks/.work/paired-javalin-reactor-v1; experimental builder remains uncommitted pending successful verification. Next: preserve exact Git metadata in the isolated context, enumerate every shipped owner, then resume this reactor experiment.


## R88 — real nested Maven reactor and output budget failure, 2026-10-16

- Continued the same Javalin experiment, preserving prior failed recipe/log checkpoints. Exact Git metadata fixes git-commit-id without changing source; local Git config/hooks/logs excluded from the external build context. Recursive declarations enumerate18 descendants plus root. Real reactor install succeeds; explicit CycloneDX2.9.3 makeBom addons supply module oracles after root aggregate invocation produced only the aggregate.
- Immutable pair now binds19 validated reference schemas and18 native/effective owner graphs to identical build/final application trees and final image digest.72 module-direct edges,55 across14 shipped JAR owners;4 POM-only modules remain separate.26 total pairs (14Java/12JS, DBCP separate);15 expansion candidates still pending.
- Unchanged production service fails image_scan on64MiB Syft output capture limit; diagnostic retry confirms exceeded output limit. Archive84,517,376bytes; no final/os/full published. Failure remains in expanded results with55 known shipped-owner edges unmatched and null accuracy; no limit relaxation or reference-based filtering. Full aggregate128 components includes reactor artifacts and is not a runtime direct oracle.
-77 targeted acquisition/payload/scanner/benchmark tests passed,1 skipped; full configured service suite276 passed,3 skipped (known Starlette warning). Ruff and reference hashes/schemas/native/tree/archive binding checks pass. See [expanded results](java-js-expanded-results-v1.md). Report/acquisition change only. Next: bounded evidence capture for repeated/large JARs, then independent controls and expanded top-three replay; no production acceptance claim.

## R89 — separate inventory from inline JAR contents, 2026-10-16

- Hypothesis: the Javalin output-budget failure is caused by base64 JAR payload duplication in Syft JSON, not inventory metadata size. Development-only prototype removes archive content globs while retaining all-file metadata and the same catalogers. The same original digest-bound local archive supplies passive layer/path evidence,32MiB per read,128MiB cumulative reads. This local-archive bridge is NOT a production registry solution; runtime files and limits unchanged.
- Real replay succeeds in28.05s: stripped image catalog5,105,364bytes versus baseline exceeding64MiB;200 artifact evidence probes,198 confirmed/2unconfirmed,93,180,452 cumulative bytes read,zero budget rejections. All final/os/full schemas validate and outputs are retained. Commit/tree clean and image config digest agree with the original immutable pair. Peak RSS was not measured, so no memory-performance claim.
- Recognition remains insufficient. Initial raw per-owner build-reference distance152/33/65 is diagnostic only: six module transitive sets disagree between real CycloneDX and native runtime trees (notably context-mock36 vs4). Both outputs retained; no candidate filtering by oracle. Eight agreeing owners:109TP/19FP/19FN (P/R85.16%); six scope-unresolved owners remain UNKNOWN, not dropped from coverage success. Kotlin/ASM namespace differences remain visible. All55 shipped direct-reference edges remain unmatched; no Java direct classifier improvement.
-53 prototype/payload/scanner/pipeline tests pass; Ruff passes. Tests prove aggregate rejection before layer reads, enforce32MiB even if caller asks for more, and stop repeated reads at the exact aggregate cap. [Reproduction/evaluation](../benchmarks/results/jar-content-budget-v1/), commands: check_jar_content_budget.py then evaluate_jar_content_budget.py. v1 raw evaluator result preserved; scoped-v2 marks native/CDX disagreement explicitly. Not independently accepted and not integrated.
- Next: retain bounded scanner-produced evidence without an extra local archive requirement, compare ready-made passive engine identities on this development stratum, and freeze a new candidate before fresh independent controls. Large Boot outer/resource JAR support remains unresolved; do not relax limits or count this diagnostic replay as production coverage.


## R90 — ready-made passive JAR identity engine, 2026-10-16

- Hypothesis: Trivy Java metadata/hash DB can recover canonical Maven coordinates where Syft guesses namespaces from manifest text, without project execution or a custom Maven resolver. Trivy0.75.0 binary hash verified; original immutable image archive is sole scan input, clean environment; oracle access only in post-analysis evaluators. Offline Java DB snapshot SHA256/metadata retained. Official [Java detection documentation](https://trivy.dev/docs/latest/coverage/language/java/) distinguishes JAR metadata/DB from source-POM resolution and does not promise JAR dependency graphs.
- Negative attempts retained: license-only JSON scan exits0 with zero language files (JAR license unsupported, invalid accuracy sample); actual CycloneDX image scan without initialized Java DB fails. Public DB initialization costs938MiB download/1,553,915,904bytes expanded. Following scans offline, no socket/engine/project process. Local frozen DB replay is checked by SHA256; mutable public tag is not a retrievable immutable guarantee.
- Same Javalin image and eight native/CDX-agreeing owners: Trivy128TP/0FP/0FN, exact-version component P/R100%; Syft raw image109/19/19, P/R85.16% (same as R89 final for these owners). Six scope-UNKNOWN owners remain visible and excluded only from adjudicated component scores, not declared successful. All55 shipped direct edges still unmatched; one project is not eight independent projects. Schema1.7 and image config binding verified. A second replay yields identical200 coordinate/path pairs.
- Petclinic nested fat-JAR check:90/3/2 exact packaged component identities/versions, P96.77%/R97.83%; one packaging-added UNKNOWN is conservatively charged as FP, Hibernate group and models-version errors retained. Own application excluded, full image retained.16 build-direct edges remain UNKNOWN. No reference-informed prediction or rule changes.
-22 schema/graph tests pass, Ruff passes. [Current table](java-js-top3.md), reports under trivy-reactor-image-v1/v2/v3 and trivy-boot-image-v1. Passive component inventory improvement only, not runtime integration or independent acceptance. cdxgen full Maven mode is not ranked as a comparable image-only method. Next: freeze Trivy candidate plus evidence/owner strategy before fresh held-out Java controls; continue remaining15 complex reference builds.

## R91 — passive owner graphs and optional declarations, 2026-10-16

- Frozen Trivy0.75.0 source scan of the exact Javalin checkout, isolated empty HOME and offline-scan flag, no Maven/project execution.19 POM files detected. Graph owner lookup must follow the unique POM-path wrapper to its owner ref: repeated owner PURLs from different source contexts make global PURL lookup ambiguous. Strict normalizer rejects duplicate references and leaves missing/dangling owner graphs UNKNOWN.
- Raw source candidate across14 shipped owners:42TP/0FP/13FN, P100%/R76.36%. Across all18 labelled modules:59/18/13. POM-only parent output mixes module containment with dependency edges;18 extra relations remain reported, not silently accepted as direct.
- Official pinned [Trivy parser](https://raw.githubusercontent.com/aquasecurity/trivy/v0.75.0/pkg/dependency/parser/java/pom/parse.go) skips optional declarations. A separate POM-only projection changes only unprofiled direct optional flags, preserving original checkout and recording every original/projected POM hash; profiles and managed optional fields untouched. This is parser assistance for root-direct candidates only: its transitive/component graph is not build truth.
- Projection offline shipped-owner candidate49/0/6, P100%/R89.09%/F194.23%; all-module66/18/6. Missing six include imported Jetty/Jackson managed-version entries; no version guessed from mere image presence.29 graph/projection/schema tests pass, Ruff passes. Component identity engine results remain R90; no combined runtime accuracy claim, no deployed changes.
- Metadata-enabled projection attempt fails fast with Maven Central429 and Retry-After1800. Do not retry before2026-10-15T21:28:21Z; retry-policy.json retained, failed run unscored. No native resolver executed, no oracle input to any scanner/projection. Experimental predictor hashes frozen before fresh held-out evaluation, [report](../benchmarks/results/trivy-reactor-source-optional-v1/evaluation.json). Next: respect network backoff, verify resolved remote-metadata mode or keep UNKNOWN, then fresh complex control builds; production acceptance still absent.

## R92 — passive metadata mode recovers the remaining direct versions, 2026-10-16

- Resumed central metadata once after the original Retry-After boundary. It failed429 again (now prometheus-metrics-core POM); renewed not-before2026-10-15T21:58:33Z preserved. Backoff runner selects the latest server deadline, checks predictor/projection hashes before requests, and never scores a failed partial output. Tests cover exact boundary, timezone offsets and renewed deadlines.
- Used the ready engine's documented [config-file Maven mirrors](https://trivy.dev/docs/v0.75/guide/coverage/language/java/#mirrors) rather than a custom resolver. Central URLs are mapped to the [Google-hosted mirror](https://docs.cloud.google.com/docs/buildpacks/java#google_cloud_hosted_maven_central_mirror) without origin fallback configured; no credentials, empty HOME/cache, no Maven/project execution. Provider [mirror page](https://storage-download.googleapis.com/maven-central/index.html) explicitly says it is not an officially supported Google product: benchmark evidence, not a production SLA choice. No further request to the rate-limited origin was intentionally made.
- Same unchanged optional projection and strict path-bound graph adapter: shipped-owner direct55TP/0FP/0FN, exact P/R/F1/versions100%, all14 shipped owners. Previous offline49/0/6 retained; six missing managed versions now resolved through public POM metadata. All18 labelled source modules72/18/0: POM-only module-containment extras remain unresolved, not erased. Root aggregate is not treated as a direct graph. This single disclosed development project is not independent acceptance or a global Java success.
- Repeat from another empty HOME/cache reproduces all19 owner candidate graphs exactly. First mirror run about96s, CPU/RSS not measured; network POM responses not pinned by hashes, so this is observed repeat stability, not immutable remote reproducibility. Local candidate/code/config hashes frozen before fresh complex controls. Runtime source unchanged from4f29791; no service integration, network security/resource hardening or generic source/image module binding claimed.
-32 graph/projection/backoff/schema tests pass, Ruff passes; schema1.7, source commit/tree and immutable reference hashes verified in evaluation. [Result and freeze](../benchmarks/results/trivy-reactor-source-optional-mirror-v1/evaluation.json), [repeat](../benchmarks/results/trivy-reactor-source-optional-mirror-v1/reproducibility.json).26 reference pairs unchanged;15 complex candidates still pending. Next: fresh independent positive Java controls and continued reference builds, preserve POM/profile/owner UNKNOWN, then bounded production-compatible source/image integration if controls support it.

## R93 — fresh positive Java control and corresponding real Boot pair, 2026-10-16

- Added held-out Petclinic REST4.0.2 exact afc8fc1d3b8ec8de69414482b3bd70a1da78cb95: real Maven/CycloneDX2.9.3 package, primary121 components/21 root compile-runtime direct edges, native/effective/CDX agreement, immutable reference/image digest and equal artifact trees. External build uses explicitly recorded central mirror settings, pinned Maven/JRE17 images and default Maven profiles. Image passes isolated read-only network-none health UP, no published ports, cap-drop/1GiB/2CPU; generated credentials/raw app logs not published.27 total pairs (15Java/12JS including DBCP),14 expanded projects still pending.
- R92 predictor/config hashes and R90 image DB verified BEFORE fresh prediction; loader uses unchanged project_pom/extract algorithms, no oracle read by source/image tool. All predictions finish before labels/evaluation access. No rule changes based on this control. This is one independent positive Spring Boot stratum, not a replacement for20+20 or diverse independent reactors/Gradle/workspaces.
- Candidate source build-declaration direct21/0/0, P/R/F1/exact versions100%, one owner resolved with zero unknown targets.12 direct artifacts packaged,9 absent (8 metadata-only starters plus annotation processor): absence is not a direct declaration error. This control has zero root optional declarations and no reactor, so does NOT independently validate optional-projection or module-containment fixes.
- Evaluation-only SHA256 linkage labels all121 build artifacts:106 packaged (105class/1resource),15 not packaged,1 packaging-added jarmode UNKNOWN. Passive candidate image components104/3/2, conservative P97.20%/R98.11%/F197.65%; one UNKNOWN charged FP, Hibernate group and models-version mismatches retained. Version accuracy among matched identities99.05%, exact-version coverage98.11%. One project/owner makes macro=micro here; no language-wide extrapolation.
- Crucially these are external candidate scores. Unchanged service final confirms0/106 known packaged app coordinates (0/0/106, recall0); known21 direct edges unmatched. Baseline final/os/full and summary saved separately, no raw-image score substituted for final. Expanded status now shows known packaged misses for both Boot pairs while retaining packaging UNKNOWN and full-build deltas.
-290 tests pass,3 platform skips, known Starlette warning; Ruff, primary/candidate/three-view schemas, hash/native/tree/config binding and smoke pass. [Fresh-control report](../benchmarks/results/petclinic-rest-frozen-control-v1/evaluation.json), [packaging labels](../benchmarks/results/petclinic-rest-packaging-labels-v1/report.json), [receipt](../benchmarks/references/paired-petclinic-rest-v1/receipt.json). Runtime unchanged; next bounded production-compatible candidate integration/regression and remaining complex references. If this case informs tuning, it ceases to be fresh independent acceptance for the new rules.

## R94 — internally acquired archive without Docker, 2026-10-16

- Hypothesis: R89's local archive can be an internal passive registry-acquisition artifact instead of another required user input. Official [crane pull](https://github.com/google/go-containerregistry/blob/v0.22.1/cmd/crane/doc/crane_pull.md), [release0.22.1](https://github.com/google/go-containerregistry/releases/tag/v0.22.1), downloaded Windows archive checked against published release SHA256 (no detached-signature claim). No Docker subprocess/socket, project execution, reference labels or host credential store used by this experiment.
- Existing immutable Javalin image blobs were served by an ephemeral loopback registry fixture, requested by exact platform manifest digest. Crane writes a Docker-compatible internal tarball; raw config digest matches original image and platform/diff-ID count checks pass. R89 metadata-only scanner plus bounded original-layer evidence completes in27.89s (HTTP pull2.09s). A reviewed repeat with added coordinate assertions completes in28.59s (pull0.55s):200 reads/93,180,452bytes,32MiB per-file and128MiB aggregate unchanged. All final/os/full schemas validate; all three component-coordinate multisets exactly match R89. Inventory quality and direct edges have NOT improved.
- [v1](../benchmarks/results/registry-archive-bridge-v1/report.json), [repeat with equality assertions](../benchmarks/results/registry-archive-bridge-v3/report.json), three outputs retained. HTTP/--insecure was used ONLY for the ephemeral loopback fixture, never a production registry. Isolated HOME/DOCKER_CONFIG avoids inherited credential helpers; configured credentials, redirects and malicious registry behavior have not been fully validated. Archive growth is sampled under8GiB, not a hard filesystem quota; peak RSS unmeasured.
- Negative authenticated-TLS attempt on Windows failed before analysis; no outputs or accuracy assigned. Both negative CLI probes also failed, so they are NOT credited as successful authentication checks. [Failure evidence](../benchmarks/results/registry-archive-bridge-v2/report.json). Platform-trust hypothesis follows Go's [Windows system roots](https://raw.githubusercontent.com/golang/go/go1.25.0/src/crypto/x509/root_windows.go) versus [Unix SSL_CERT_FILE handling](https://raw.githubusercontent.com/golang/go/go1.25.0/src/crypto/x509/root_unix.go); stderr was discarded by the redacting helper, so exact failure attribution remains unproven. No host CA installed and no insecure TLS workaround attempted. Next validate a trusted TLS positive control in the Linux external harness before drawing auth-negative conclusions.
-284 service/prototype tests pass,3 skips (known Starlette warning);41 focused payload/scanner/prototype tests pass, Ruff passes. This is acquisition feasibility plus a retained transport failure, NOT runtime integration, a new accuracy rank or independent acceptance.27 pairs unchanged,14 expanded builds pending. Large/nested/resource JAR evidence and source-owner integration remain next; do not substitute raw inventory for payload proof.
