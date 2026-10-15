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
