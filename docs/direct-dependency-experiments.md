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
