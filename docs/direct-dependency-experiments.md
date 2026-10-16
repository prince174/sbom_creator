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

## R95 — trusted TLS and authentication positive control on Linux, 2026-10-16

- Tested the R94 platform-trust hypothesis with official checksum-verified crane0.22.1 Linux/amd64 in a fresh external harness. The Python container is pinned by its local image ID, non-root65532, read-only root, no capabilities, network none,512MiB/1CPU; only paired image bytes, fixture CA/key, tool and harness are mounted. No source, reference, host credential directory, Docker binary or socket is available inside. Docker is used only by the external launcher, never by the predictor.
- A TLS registry on container loopback serves the existing exact Javalin platform digest with synthetic Basic authentication. Correct credentials plus explicit fixture CA succeed; acquired config digest matches. With the positive control established, untrusted CA is specifically rejected as x509, missing credentials and wrong password specifically as401. No --insecure flag, host trust-store change or external network was used. This resolves the Linux TLS/auth feasibility gate; Windows custom-CA injection remains unimplemented and the R94 negative report is preserved.
- [Harness checks](../benchmarks/results/registry-tls-linux-v1/harness.json), [pinned tool/image/code and resource configuration](../benchmarks/results/registry-tls-linux-v1/run.json). Reproduce with run_registry_tls_linux.py and the recorded official crane binary/hash. Common trusted fixture code moved to registry_fixture.py without changing the R94 archive-binding method. Synthetic credentials are removed after the run; no headers/passwords/stderr are published. Cross-host redirects, malicious credential helpers, hard disk quotas and full service integration remain unverified.
- Runtime/classifiers and27-pair corpus unchanged,14 complex candidates pending; no accuracy/rank/independent-acceptance claim. Next bounded large/nested/resource JAR evidence plus owner/identity integration, retaining metadata-only negatives and final/os/full. Full service and prototype regression:288 pass,3 skips; known Starlette warning. Ruff passes.

## R96 — bounded large/nested/resource JAR witnesses, 2026-10-16

- Development hypothesis: replace full in-memory reads of large outer JARs with temporary disk files copied in1MiB chunks. The32MiB ordinary/nested in-memory limit remains; separate outer128MiB/cumulative disk256MiB caps, ZIP directory2MiB each/16MiB cumulative,100k aggregate entries,8 nested levels and200x inflate limit are enforced. ZIP directory declarations are checked before ZipFile allocates its index; ZIP64/multidisk and compressed outer image archives are unsupported UNKNOWN. Witnesses read class magic or a byte from selected resource types; they do not prove coordinate identity, directness or runtime execution.
- Negative checks cover metadata-only and root POM/package descriptors, false class magic, traversal, duplicate names, symlinks, wrong final-layer/size, oversized copy/directory, nesting depth and inflate bombs. Windows ZipInfo silently normalizes backslashes; validation now checks orig_filename as well. Version1 evidence/code bytes are retained; version2 adds conventional build-descriptor exclusions, with unchanged real-project results. These cases informed development, never a fresh control.
- Real disclosed Petclinic fat-JAR replay now completes and preserves final/os/full schemas in19.80s.130,397,105bytes copied to disk across2 source files/92 nested JARs;4,236,340 directory bytes/39,047 entries, zero rejections. No inline archive base64 or64MiB-output increase. But Syft coordinate errors remain: final exact packaged components66TP/26FP/26FN, P/R/F171.74%, versus baseline0/0/92. Both candidate and reference contain92 components: equal counts hide26 incorrect identities. Matched-identity version accuracy100% has only71.74% exact-version coverage; it is not a global version/identity success. All16 known build-direct edges remain UNKNOWN/FN; packaging-added UNKNOWN remains conservatively visible.
- [Three outputs, limits and post-analysis evaluation](../benchmarks/results/bounded-boot-evidence-v2/evaluation.json), [witnesses/counters](../benchmarks/results/bounded-boot-evidence-v2/report.json), [earlier version with exact code snapshot](../benchmarks/results/bounded-boot-evidence-v1/). Oracle labels are opened only after prediction and complete outputs; original build-reference hashes verified. One development project makes macro=micro, not language-wide accuracy. No runtime adoption: precision is insufficient, Trivy's better image coordinates and owner graphs are not yet combined with these witnesses.
- Existing Javalin evidence regression:198 previous class witnesses retained, no losses; one additional javalin-bundle logback.xml resource witness,199/200 total. One unconfirmed/rejected artifact remains visible.92,517,293bytes copied,5,369,613 directory bytes/53,586 entries,14.77s. [Coverage report](../benchmarks/results/bounded-javalin-evidence-v2/report.json). This is evidence coverage, not a new TP or component/direct accuracy claim. Catalog/archive config digest rechecked separately and in the replay script.
-25 new bounded/security tests and313 full service/prototype tests pass,3 skips, known Starlette warning; Ruff and all three SBOM schemas pass. Runtime src remains unchanged;27 pairs/14 pending. Peak RSS, hard disk quotas, all hostile layer/ZIP cases and generic registry-to-owner integration remain open. Next: freeze a strict Trivy path+layer+image identity bridge to bounded payload evidence, retaining disagreements/ambiguity as UNKNOWN, then new independent complex controls and remaining reference builds. Do not integrate this71.74% candidate or substitute raw inventory to meet the threshold.

## R97 — passive identity bridge with bounded physical evidence, 2026-10-16

- Hypothesis: use ready-made Trivy0.75.0 canonical image identities at an exact archive path/layer, while keeping R96 physical witnesses and the existing reconciliation/export pipeline. No Maven/npm resolver, project execution, Docker or oracle input was added. Official pinned [Trivy CycloneDX marshaller](https://raw.githubusercontent.com/aquasecurity/trivy/v0.75.0/pkg/sbom/cyclonedx/marshal.go) exports inventory properties; its dependency graph is deliberately ignored here.
- trivy_payload_bridge.py requires one matching image-config digest, one canonical final file/layer, one archive identity in EACH engine and a bounded witness in that same virtual archive. Duplicate/conflicting/missing path/layer/PURL/name/version/group, shaded multiple identities and unmatched witnesses become UNKNOWN. No namespace aliases guessed. Original full Syft catalog and peer CDX are retained, every bound identity records its original name/PURL/version and path/layer. Non-Java artifacts/witnesses remain unchanged. This prototype uses the existing payload selection gate for unbound identities while retaining the actual observed-payload fact in audit; a production identity gate still needs explicit integration.
- Both disclosed development predictions and final/os/full publication finish before evaluator opens build labels. Petclinic candidate final89TP/3FP/3FN, exact P/R/F196.74%, versus R96 final66/26/26 (71.74%). Count delta remains0 (92/92). Matched-identity version accuracy98.89%, exact-version coverage96.74%. Hibernate namespace/models-version and packaging-added jarmode UNKNOWN are retained among discrepancies.16 known build-direct edges still0/0/16, UNKNOWN charged FN. Runtime src is unchanged; this is a candidate final output, not deployed service accuracy or acceptance.
- Coverage loss versus raw Trivy is explicit: raw90/3/2 becomes final89/3/3. The extra missing font-awesome resource JAR has no Syft archive-package entry, so the conservative intersection cannot bind it. No oracle-based filtering or manufactured Syft entry was used. [Loss accounting](../benchmarks/results/trivy-payload-bridge-v1/coverage.json). This must be addressed or explicitly adjudicated before adoption; passing90% does not excuse silent recall loss.
- Javalin candidate final across the SAME8 native/CDX-agreeing owners scores128/0/0 exact owner/component instances (micro/macro P/R/F1100%) versus original Syft109/19/19.6 owners still have scope UNKNOWN;55 known shipped-direct edges remain0/0/55.198 of200 Syft Java archive entries are bound; the two unknowns preserve a conflicting access path and ambiguous archive identity. These eight owners belong to one disclosed repository, not eight independent controls.
- [Frozen code and input hashes](../benchmarks/results/trivy-payload-bridge-v1/candidate-freeze.json), [evaluation/per-module results](../benchmarks/results/trivy-payload-bridge-v1/evaluation.json), [independent-process exact replay](../benchmarks/results/trivy-payload-bridge-v1/repeat.json). Both adapted catalogs, payload gates and audits reproduce exactly; producer versions Syft1.51.1/Trivy0.75.0 verified. All six final/os/full schemas validate. Replay/conversion timings exclude acquisition/scanning; peak RSS unknown.24 new negative/identity/JS-preservation tests and337 service/prototype tests pass,3 skips, known Starlette warning; Ruff passes.
- No runtime adoption, rank promotion or independent acceptance:27 pairs and14 complex builds pending. Next freeze a candidate that can corroborate Trivy-only resource JARs without inventing Syft attribution, integrate passive source-owner evidence with explicit scope/profile UNKNOWN, and test new independent complex pairs. Continue the remaining reactor/Gradle/workspace builds; do not terminate on these disclosed development scores.

## R98 — Trivy-only resource archive with explicit producer, 2026-10-16

- Repaired R97's conservative intersection loss generically: supplemental packages require a unique peer Maven identity, the same config digest in BOTH catalogs and actual archive bytes, one final regular outer archive in the matching layer, a bounded nested-archive chain and positive class/resource bytes. Existing Syft paths, even UNKNOWN/ambiguous ones, are never bypassed. No font-awesome name rule, alias guessing, oracle lookup or Trivy dependency-graph inference. Metadata-only, missing/wrong-layer/config, duplicate-peer, unsupported-chain and missing-payload cases stay UNKNOWN.
- The new package is explicitly attributed to trivy-java-archive-cataloger, not fabricated as a Syft discovery. The benchmark alone registers this trusted producer together with mandatory payload evidence and policy experimental-trivy-only-payload-v1. Tests prove the unchanged service rejects the unregistered producer and the experimental registration still rejects missing witnesses. Original Syft inventory, peer CDX and per-package audit remain available. Runtime src is unchanged; this trust registration is NOT deployed or accepted production code.
- On the SAME disclosed Petclinic input/scope, candidate final90TP/3FP/2FN, precision96.77%, recall97.83%, F197.30%; conditional version accuracy98.90%, exact-version coverage97.83%. It recovers R97's extra resource-JAR FN without adding FP:89/3/3 becomes90/3/2, matching raw Trivy's component counts through actual corroboration. Count93 versus reference92 remains+1; packaging-added jarmode UNKNOWN is conservatively charged FP, Hibernate namespace/models-version errors remain. All16 known build-direct edges remain UNKNOWN/FN, not inferred from inventory.
- The added physical witness is a byte from nested font-awesome.css under META-INF/resources;66,512,269bytes copied,41,503 directory bytes/381 entries,one outer/one nested file,zero rejection under the unchanged R96 budgets. Existing Javalin remains128/0/0 across8 agreed owners;6 scope-UNKNOWN owners and55 direct UNKNOWN/FN persist. Its ambiguous/unsupported archive entries are not supplemented. One development repository with eight owners is not independent project coverage.
- [Freeze/evaluation and six SBOMs](../benchmarks/results/trivy-only-payload-v1/evaluation.json), [physical/producer audit](../benchmarks/results/trivy-only-payload-v1/boot/supplement.json), [independent-process repeat](../benchmarks/results/trivy-only-payload-v1/repeat.json). Fresh bounded reads reproduce adapted catalogs, evidence and audit exactly; exported final/full both retain the explicit Trivy producer. Replay/new-witness/conversion times7.23s Boot/4.19s Javalin exclude cached engine scans/acquisition; peak RSS unknown.12 new tests and349 service/prototype tests pass,3 skips, known Starlette warning; Ruff, Syft and six final/os/full schema checks pass.
- No runtime adoption or rank promotion: no independent acceptance, source-owner/direct integration or new pair yet (27 pairs/14 pending). Next PRIORITY is a new independent complex reactor/reference build with per-module labels, followed by the frozen R98 image and R92 source-owner candidates without tuning on the control. paired_maven_reactor.py is currently Javalin-specific; generalize external recipes with actual per-module build coordinates/toolchains, never root-POM or pinned-only success. Continue the remaining Java/JS pairs before claiming the overall thresholds.

## R99 — fresh complex Dropwizard reactor pair; frozen predictors fail resource gates, 2026-10-16

- Prepared new independent holdout Dropwizard exact14b738b8ca8a52cb245f855cee0dcc68327f1d72. R98 image and R92 source predictor/config hashes were frozen BEFORE build/oracle access; classifier functions and runtime remained unchanged. Exact checkout root SHA256, clean index/tree and commit verified after isolated Windows EOL normalization; source bytes are the original Git blobs, not a patched project.
- Real controlled Maven3.9.16/Temurin17 build (exact base digest in recipe), CycloneDX2.9.3/schema1.6:39 reactor projects,39 module references,34 shipped JAR owners,5 POM owners,443 compile/runtime direct GAV edges. Per-module Maven effective coordinates/finalName/output path are consumed by a trusted external Java helper; no assumption that module names or versions equal the root. Effective declarations/native graph/CDX root edges agree; no classifier/type-qualified direct edges occurred. Aggregate is NOT a direct-dependency label.
- Explicit -P!all-modules disables the profile's additional docs/e2e/benchmark modules; literal root/nested modules, including literal documentation examples, remain in the recipe. Tests compile but are not executed. This is a library/reactor artifact image, not an executed application or a health-check claim. Build and final application trees match; each primary JAR SHA256 agrees; index/platform/config binding verified. [Immutable receipt](../benchmarks/references/paired-dropwizard-reactor-v1/receipt.json), [module labels](../benchmarks/references/paired-dropwizard-reactor-v1/module-labels.json).28 pairs now exist (16Java incl DBCP/12JS),15 primary Java/12JS; expansion7 ready/13 pending (5Java/8JS).
- Frozen passive Trivy image scan succeeds in18.44s and retains2406 raw components; this count is NOT an accuracy result or a direct graph. Frozen source optional/mirror scan reaches180s timeout with an unresolved-version warning; no source SBOM/owner prediction completed. No retry, fallback to build .m2, altered classifier, or empty-success score. [Source run/log](../benchmarks/results/dropwizard-frozen-control-v1/prediction-v1/source/run.json).
- Continued only the unfinished image candidate using the completed image scan, without repeating source/scans or reading evaluation labels. Metadata-only Syft scanning finishes, but the frozen bounded payload collector repeatedly reopens the same gzip layer rejected by its512MiB expanded-layer budget. The final artifact tree is703,148,544bytes; compressed image layer627,366,681bytes. Observed process reads23,091,407,634bytes after roughly3 minutes prompted a manual stop of the verified owned predictor process. This is an operational negative, NOT a pre-registered timeout comparison or measured component precision/recall. [Resource-stop evidence](../benchmarks/results/dropwizard-frozen-control-v1/prediction-v1/image-resource-stop.json); exact executed adapter snapshots/hashes and completed source/Syft/Trivy intermediates retained. No final/os/full could be published for this failed control, and none are fabricated. The443 known direct edges remain unmatched; no global threshold or rank promotion.
-357 service/prototype tests pass,3 skips, known Starlette warning; Ruff,39 reference schemas, hash/native/effective/tree/config checks pass. Expected rejection of duplicate image continuation verified. No existing pair rebuilt, runtime algorithm changed or deployed service touched. This is a reference/evaluation infrastructure commit, not an algorithm improvement.
- Next: safely cache failed-layer evidence outcomes or otherwise bound repeated indexing without raising budgets; test security/liveness and existing evidence regression before any adoption. Dropwizard is now disclosed for resource tuning and must not be advertised as fresh independent acceptance for rules tuned on it. Diagnose passive-source resolution under a separately frozen resource policy rather than silently lengthening this180s result. Continue the13 remaining real complex Java/JS builds and freeze before fresh controls.

## R100 — bounded rejection cache completes the disclosed control, 2026-10-16

- Hypothesis: deterministic failure of one immutable layer/archive must be remembered instead of reopening/decompressing it for every package. Added a SEPARATE benchmark candidate cached_jar_evidence.JarFiles; frozen R96/R98 code and runtime src remain unchanged. Only layer-index-wide failures poison that exact layer; invalid file/size/copy failures do not poison peers. ZIP rejections are keyed by exact virtual archive with a256-entry fail-closed cache. Previously validated archives remain reusable when the rejection cache is full. All original byte/index/depth/ratio limits remain unchanged.
- Each attempt owns an ExitStack: failed contexts close immediately and newly cached handles are rolled back, preventing reuse of a closed layer after a later file mismatch. Successful handles stay owned until normal reader close. Five liveness/security tests verify one index operation for20 repeated rejected-layer/archive reads, unchanged UNKNOWN, invalid-file isolation, closed-layer rollback, valid-reader reuse and cache-cap behavior. Intermediate v1/v2 snapshots retained; their complete Dropwizard outputs agree in outcome, but they do not include the final defensive rollback/cache-cap guards. Exact executed source hashes are preserved, never overwritten.
- Current v3 completes real Syft source/image acquisition, bounded evidence and final/os/full publication in94.11s (earlier candidates93.49/93.97s); cached Trivy image inventory is reused, so timing excludes its18.44s scan and image acquisition. One layer failure is reused2405 times across2406 JAR artifacts; no class/resource bytes are confirmed or copied. This closes repeated processing, NOT the oversized-layer support gap. The unchanged512MiB expanded-layer limit still rejects the703MB artifact image. No peak RSS or hard disk quota claim. [Run, freeze and all three views](../benchmarks/results/cached-dropwizard-evidence-v3/run.json).
- Post-analysis evaluation only after publication: on16 native/CDX-agreeing shipped owners, final component instances0TP/0FP/907FN, recall/F1=0, precision undefined; exact-version coverage0, conditional version accuracy undefined.18 other shipped owners have native/CDX transitive-scope disagreement and retain UNKNOWN plus complete raw deltas. Module macro recall/F1=0; these are owners in ONE disclosed repository, not16 independent projects. All443 known direct edges remain UNKNOWN/FN; the prior source timeout is not retried. [Negative accuracy result](../benchmarks/results/cached-dropwizard-evidence-v3/evaluation.json). No threshold, rank promotion, integration or acceptance.
- Known Boot/Javalin regression repeats fresh physical reads: every witness/error/path is identical; adapted catalogs, identity audit (serialized tuple/list normalization) and payload evidence exactly match R98. Old counts and limits do not change; zero previously confirmed witness lost. [Regression and current candidate hash](../benchmarks/results/cached-jar-regression-v2/report.json).353 selected service/prototype tests pass,3 skips, known Starlette warning; Ruff, schemas, original predictor freezes and clean exact source verified.
- Corpus remains28 pairs,15 primaryJava/12JS plusDBCP,13 expanded pending. This commit improves benchmark liveness and exposes previously unavailable failure metrics; it is NOT a production accuracy change. Next: a separately frozen bounded-index/acquisition approach for legitimate large layers with resource/security proof, plus source-owner resolution/profile handling and the13 remaining complex builds. Do not simply raise limits, silently drop the failed Dropwizard case, or call this disclosed tuning case fresh independent acceptance.

## R101 — separate bounded seekable layer index, physical-access proof only, 2026-10-16

- Hypothesis: declared payload size is not the retained TAR index size. Replace repeated gzip traversal in a NEW prototype with one internal disk normalization, full uncompressed [OCI DiffID](https://github.com/opencontainers/image-spec/blob/v1.1.1/layer.md) verification, metadata preflight and bounded seekable file windows. This is NOT an increase of the frozen512MiB expanded-layer gate: R96/R100 remain unchanged. The new policy explicitly adds a separate8GiB cumulative normalization-disk cap,200x inflation/120s normalization-loop guards,1MiB chunks,16MiB aggregate TAR metadata cost and32MiB/read128MiB total window reads. This disk policy needs separate production acceptance; no hard filesystem quota/RSS claim.
- Standard Python3.11 tarfile/zipfile remain the format parsers. Preflight bounds header/extension allocations before tarfile index creation; duplicate canonical paths, traversal/backslashes, sparse records, PAX size overrides/global PAX, deep extension chains and nonzero trailing data fail closed. Links are indexed but never followed for reads. Each requested regular-file view binds exact path, layer DiffID, config digest and size; seeks cannot escape the file. No filesystem extraction or project execution. [Python parser documentation](https://docs.python.org/3.11/library/tarfile.html).
- Frozen BEFORE reading the existing disclosed Dropwizard image/catalog: current v3 internally normalizes703,148,544bytes once and accesses2179 physical regular JAR paths in3.69s. TAR metadata cost2,485,354bytes/2263 headers (including outer container), target windows read8716bytes total. All four-byte probes are ZIP local headers. Config/DiffID checks pass; all2179 path/layer/size/prefix records repeat exactly across the retained v1/v2/v3 probes. These2179 files differ from2406 logical scanner artifacts; do not equate the counts. v1/v2 exact source snapshots retained, v3 additionally bounds aggregate outer+layer metadata before parser allocation.
- [Freeze/report](../benchmarks/results/seekable-layer-index-v3/report.json), seekable_layer_index.py/check_seekable_layer_index.py. This only proves bounded physical access to a previously rejected large layer. ZIP headers are NOT class/resource witnesses, component identities, direct links, runtime use or a new SBOM prediction. No evaluator/reference labels are read, no new final/os/full are fabricated, and the R100 negative accuracy remains unchanged. Runtime/corpus/ranking remain unchanged:28 pairs,13 pending.
-11 new resource/security tests and364 selected service/prototype tests pass,3 skips, known Starlette warning; Ruff and source-snapshot repeat checks pass. Tests include a real ZIP view, one-time normalization, wrong DiffID/size, duplicate/unsafe paths, link rejection, disk/ratio/read/metadata budgets, closed views, oversized/deep extensions and parser-allocation ordering. No production adoption or accuracy improvement claim.
- Next: independently freeze a JAR payload candidate using these seekable views, retain existing ZIP directory/inflation/identity guards and explicit accounting, then compare actual final/os/full on disclosed cases. No raw Trivy inventory substitution. Continue remaining complex Java/JS reference builds and fresh independent controls before runtime adoption; do not repeat header-only probes as accuracy experiments.

## R102 — real seekable JAR payload and final SBOM comparison, 2026-10-16

- User requested actual components and service-vs-reference figures. New seekable_jar_evidence uses R101 physical windows, bounded EOCD preflight, standard ZipFile validation and real class/resource reads, then frozen R98 strict identity/path/layer bridge and existing final/os/full publisher. No oracle input, alias guessing or image-derived direct graph. Code/input hashes frozen before prediction, references accessed only after all nine views completed.
- v1 physical payload hit128MiB read budget (781/2406 Dropwizard witnesses); v2 exact-range per-witness read cache improved to1615 and final671/0/236, P100/R73.98%. v3 independently hashes each physical JAR before sharing payload proofs for identical bytes/relative archive chain:2147/2406 witnesses and final893/0/14,P100/R98.46 on the SAME16 scoped owners. v4 adds closed-cache-view guards; v3/v4 witnesses identical. All versions and exact source snapshots retained. Separate8GiB verification-read budget is explicit, not hidden in the128MiB payload cap. Identity/direct/use inference never comes from the hash.
- Boot final90/3/2 (P96.77/R97.83), Javalin128/0/0 on8 agreed owners unchanged; no previous confirmed physical witness/path lost. Dropwizard18 and Javalin6 additional owner scopes remain UNKNOWN with raw deltas. All16/55/443 known direct edges remain UNKNOWN/FN. Dropwizard14 FN are the same metadata-only empty listenablefuture JAR across14 owners; physical listing confirms no classes, metric is NOT filtered to100%. Full result/version/resource tables in [current service accuracy report](java-js-service-accuracy.md), [post-only evaluation](../benchmarks/results/seekable-payload-v4/evaluation.json).
- Unmodified runtime re-run on Dropwizard fails image_scan/RuntimeError (no final publication); no raw candidate substituted for service. Current runtime unchanged from4f29791. JS12 no-lock saved service finals/reference hashes and36 schemas revalidated: component306/9/1,P97.14/R99.67; direct102/0/1,P100/R99.03.8 positive roots,4 empty; macroP93.48/R99.88, owner-status11/12. AxiosP61.54 remains visible; no new JS scan or independent acceptance claimed.
-377 selected tests pass3skips, Ruff/schemas/freeze/repeat checks. New tests cover real class/resource, metadata-only rejection, nested bytes, unsafe directory/offsets, content-cache equality and changed body with same directory, closed cache views. No private ZipFile parser state is shared. Disk/RSS/concurrency/registry integration and new independent controls remain gates; this is a benchmark accuracy improvement, NOT runtime deployment. Corpus28 pairs,13 pending unchanged. Next production-compatible identity/evidence gates plus Java source-owner/direct integration and remaining complex controls, not another header-only run.


## R103 — explicit identity evidence gate (2026-10-16)

Hypothesis: preserve physical payload truth independently from a rejected package identity, without promoting any previously UNKNOWN package. New benchmark-only `explicit_identity_gate.py` seals trusted adapter audit to complete adapted catalog + payload hashes and image config; each Java observation gets a separate binding status. Missing/stale/duplicate/conflicting bindings fail closed. Non-Java observations unchanged. This is not an externally supplied trust/authentication format and not a production import.

Prediction: `replay_explicit_identity_gate.py` froze code and all cached R102 source/image/provenance/audit inputs before publishing all nine final/os/full. No fresh scanner/acquisition/physical-reader run, no classifier oracle access. Evaluation compared coordinate multisets for all three views and exact selected artifact IDs against R102 only after all outputs existed: identical for Boot/Javalin/Dropwizard. Confirmed physical payload with UNKNOWN identity remains visible in 1/1/4 facts respectively. Existing component scores and all direct FN unchanged; no independent acceptance, accuracy gain, rank promotion, new pair or runtime change. [Freeze](../benchmarks/results/explicit-identity-gate-v2/freeze.json), [regression](../benchmarks/results/explicit-identity-gate-v2/regression.json).

Twenty focused tests cover positive/negative independent axes, stale inputs, forged coordinate/path/layer claims, duplicate/missing audit, same-PURL sibling isolation and npm preservation. Frozen R96/R98/R102 reader/bridge code unchanged. Next: passive source-owner/module/profile candidate, with a new bounded hypothesis for the prior Dropwizard source timeout; never use reference build cache. Continue13 complex pending builds and freeze before fresh controls. Runtime still baseline4f29791 and global >90% goal not achieved.

R103 v2 additionally rejects missing/invalid config digests and mismatched Syft/Trivy-only producer attribution. The completed v1 replay and exact candidate/replay snapshots are preserved; v2 is the current frozen candidate. No reader/bridge/source classifier was changed.

Validation R103:394 service/selected prototype tests passed,3 skipped, known Starlette deprecation warning; Ruff passed. Frozen runtime/reader/bridge source remains unchanged. Nine CDX views per replay validated by the publisher/schema validator.

## R104 — real Microservices reactor and native source-model comparison, 2026-10-16

New exact Petclinic Microservices `1d76b00d683e86b62867a6bf59530f8ab301244f` development pair:9 per-module references,8 shipped JAR owners,100 direct compile/runtime GAV edges with native/effective/CycloneDX agreement. Primary artifact hashes, equal build/final trees and OCI index/platform/config binding verified. Tests compiled/not executed; artifact fixture, no microservices health claim. No completed pair rebuilt. Corpus29 real pairs (16 primary Java/12JS plus separate DBCP); expansion8 ready/12 pending. [Receipt and scoped report](java-microservices-reference-r104.md).

Source prediction completed before evaluator label access. Passive Trivy0.75.0 source projection:76/0/24 direct, P100%/R76%,7/9 owners resolved,2 UNKNOWN;160.812s. Full cdxgen13.4.0/native Maven in an isolated disposable job:100/0/0 on8 shipped owners; raw9-owner graph100/8/0, P92.59%/R100%, because root contains8 module-containment relations. Extras retained; no reference-driven graph filtering. Native duration322.704s. [Post-only owner comparison](../benchmarks/results/java-runtime-direct-r104-control-v1/evaluation.json). Source-model success is not proof of image presence, dependency execution or original unknown TeamCity configuration.

User lifted the historical prohibition on project execution/Docker, then prioritised an image-first MVP. Optional cdxgen enrichment is therefore allowed, but unknown CI recipes/build failures must not block image SBOM. Further foreign-project build-recipe expansion is deferred for the first release; own-service tests/build/reference comparisons continue. These source results are separate from the actual runtime image-accuracy stage R105 and are not a universal >90% acceptance claim.

## R105 — image-first runtime integration and actual final scores, 2026-10-16

Moved the separately tested bounded seekable reader/strict Syft-Trivy identity bridge into the real service path. Production may now receive only an image; repository URL/commit remain a paired optional enrichment input. The service acquires an immutable internal archive through Crane0.22.1, checks config/DiffID/path/layer identity, obtains Trivy0.75.0 JAR coordinates with a hash-recorded Java DB, and confirms actual class/resource bytes before the normal publisher emits final/os/full. No raw peer inventory or reference is substituted for the service final. Original Syft, peer CDX and identity audit are retained. A forged Trivy producer without the trusted in-process binding envelope remains UNKNOWN.

Runtime source backend defaults disabled. Explicit cdxgen jobs are permitted, execute native tooling in a resource-bounded isolated worker, receive neither service secrets nor Docker socket, and publish a separate build-model graph/comparison. They do not add source-only packages to the final image SBOM and do not prove reproduction of an unknown TeamCity build recipe. Source/backend failure leaves the image analysis available, with unresolved graph UNKNOWN. Image-only analysis never invents directness from package presence.

All predictions are completed before the post-only evaluator opens reference labels. Full Windows v2 protocol: Boot0/0/92 after optional helper RuntimeError (partial output retained), Javalin128/0/0 across8 agreeing owners/6UNKNOWN, Dropwizard893/0/14 across16 agreeing owners/18UNKNOWN, new Microservices8/0/132 on1 agreeing owner/7UNKNOWN. Aggregate1029/0/238, P100%/R81.22%/F189.63%; repository macro R51.04%. The complete negative protocol remains visible, not replaced by a favourable subset. Exact frozen code, outputs, failures and scope-UNKNOWN raw deltas retained in [v2](../benchmarks/results/mvp-image-r105-v2/evaluation.json).

Same positive Java code in a fresh serial Boot run produces90/3/2,P96.77%/R97.83%/F197.30%,24.234s. Installed Linux RC, nonroot/read-only/network-none/no socket/no source/reference/credentials, independently produces the SAME93 project coordinates (90/3/2),84.563s including startup. Overall Linux final95 includes2 outside fixture project scope; full inventory retained. Conditional version accuracy98.90%, exact-version coverage97.83%. Original concurrent Windows helper failure cause is not established; serial success does not erase it. [Serial](../benchmarks/results/mvp-image-r105-serial-boot/evaluation.json), [installed Linux](../benchmarks/results/mvp-container-r105-v1/final-smoke/evaluation.json).

New Microservices is a substantive coverage failure: reader consumes134,217,721/134,217,728 allowed payload-window bytes while normalizing1,303,884,800bytes and verifying1,302,810,004bytes of JAR SHA256; only188 artifact instances corroborated. On the single agreeing owner8/140 expected components are recovered, recall5.71%. Seven other owner scopes retain full raw deltas (roughly5–10% recall), not unlabelled success. No budget increase, fixture-specific whitelist or reference filter was used. Original source graph100direct does not repair image coverage. Dropwizard14 metadata-only listenablefuture misses and Boot Hibernate identity/version discrepancies also remain visible.

Twelve fresh JavaScript no-lock image-only actual scans complete all36 SBOMs:306/9/1 exact components, P97.14%/R99.67%/F198.39%, conditional versions100%, exact-version coverage99.67%; macro8 positive projects P93.48%/R99.88%. Four empty roots excluded from positive macro. EVERY project component set equals the saved source-assisted baseline, so no JS component coverage regression. Axios8/5/0(P61.54), Fastify47/3/0, Pino12/1/0 and Nest missing @tokenizer/token0.3.0 retained. Total272.091s includes fresh source-empty/image Syft scans and publication; local archive acquisition excluded. Executed source is a snapshot, immune to concurrent Java-only integration edits. [Fresh JS evaluation](../benchmarks/results/mvp-js-r105-v1/evaluation.json).

Image-only graphs remain intentionally unestablished: JS103 known direct edges and Java16/55/443/100 remain UNKNOWN/FN against reference build graphs. Previous source-assisted direct scores are not relabelled as image-derived. The user's first-release goal now prioritises delivered components; original broader research acceptance is not declared complete. Java is still below90% on the new complex resource stratum, despite strong Boot/Javalin/Dropwizard cases. No rank promotion or universal guarantee. Further foreign build recipes are deferred while this concrete runtime gap is addressed.

The first R105 attempt retained an integration negative: Trivy0.75 emits CycloneDX1.7, while the initial peer boundary accepted only1.6. It therefore preserved partial/UNKNOWN Java results. The revised boundary accepts official1.7 only for the Trivy peer; published service SBOM remains1.6. A later failure-boundary-only catch for malformed optional-peer schema preserves image/non-Java analysis; positive gates are unchanged. v2/serial freezes precede that small guard; their exact executed source/Dockerfile snapshots are retained. Read-only Linux cache path is explicitly writable under /workspace. [Current metrics and limitations](java-js-service-accuracy.md).

Final validation:457 service/selected benchmark tests passed,3 skipped, known Starlette deprecation warning; Ruff and schema checks passed. Final installed Linux image `sbom-creator:mvp-r105-final` config SHA256 `318289b205c2bd0597dfbb1cf6a20169f39cefe598758f5ca91d261cd7850a8d` passed the default-config non-root/read-only/network-none Boot pipeline in73.262s (75.062s container), without source/oracle/socket/secrets. All42 installed code/data hashes match the build snapshot; all three coordinate multisets and selected IDs equal the previously evaluated Linux RC. Safety catch regression proves optional peer schema rejection preserves original inventory and non-Java evidence with UNKNOWN instead of aborting the image analysis. No deployed service changed. Microservices resource failure still prevents declaring the full Java threshold reached. Large raw evidence is retained locally and exported losslessly with [restore/hash manifest](../benchmarks/results/mvp-r105-evidence-manifest.json).

## R106 — opt-in bounded STORED nested-window experiment, 2026-10-16

Decision after measurement: retain the R105 reader as stable default. R106 policy
v5 requires `SBOM_JAVA_NESTED_WINDOWS=true`/`Settings(java_nested_windows=True)`;
it is not default production adoption. Micro precision100→99% and recall70.71%
are an explicit unresolved trade-off. Original executed snapshots/freezes remain
unchanged; the subsequent reproduction runner explicitly selects the experimental
option and records its mode. Historical snapshots used the same experimental
reader directly before this opt-in separation; their metrics are not relabelled
as the current default service's output.

Hypothesis: repeated full nested-JAR copying exhausts128MiB payload windows even
when the physical layer is already normalized. Read STORED nested ZIP members
through exact bounded parent-image windows, validate local/central headers,
filename/overlap and complete body SHA256+CRC, and use the existing separate8GiB
verification-read ledger. Retain all header/path/layer/config/identity guards,
32MiB/read128MiB payload windows,16MiB raw-range cache and other resource caps.
Exact physical-range cache persists only within one image reader; parsed ZipFile
objects close after every witness. No reference cache, identity aliases, raw
inventory substitution or source-derived component additions.

Freeze: `run_mvp_r106.py` snapshots executing src+schemas+runner and hashes all16
existing image inputs, pinned tools and Java DB BEFORE any invocation. Four Java
cases run serially(Microservices first), then12 no-lock JS attempts. Analyzer gets
only image/local controlled archive, no repository/commit/reference. A common
completion marker gates the separate post-only evaluator; all45 main published
views plus one failed attempt exist before first oracle access.
[Freeze and full protocol](../benchmarks/results/mvp-r106-v1/evaluation.json).

Actual final Microservices on the SAME single native/CDX-agreeing owner:99/1/41,
P99.00/R70.71/F182.50, compared with R1058/0/132(P100/R5.71).91 additional TP,
one conservative jarmode-tools FP; this explicit precision/recall trade-off is
not hidden or described as dominance. Seven other owner scopes remain UNKNOWN
with full raw deltas. Whole final1878 records versus188 is not a TP count.
Micro consumes91,016,461 payload-window bytes(under128MiB),1,303,884,800 normalized
bytes once,1,952,538,302 SHA/CRC verification bytes, zero copied bytes,
1267 nested windows; fullpipeline158.953s. Remaining misses persist:27 with
BudgetExceeded enum but unrecorded failing guard,1 confirmed physical but unbound
netty-common identity,1 no confirmed physical witness,12 without matching existing
Syft bridge observation. Guard origin remains UNKNOWN, not asserted to be a
specific limit; no rule was tuned from this post-analysis diagnosis.
[Retained diagnosis](../benchmarks/results/mvp-r106-v1/microservices-diagnosis.json).

Actual final regressions on unchanged scopes: Boot90/3/2(P96.77/R97.83),
Javalin128/0/0 on8 agreeing owners/6UNKNOWN, Dropwizard893/0/14 on16 agreeing
owners/18UNKNOWN. Metadata-only Dropwizard misses stay FN. Java known-scope
micro1210/4/57,P99.67/R95.50/F197.54; repository macroP98.94/R91.75/F194.75.
26 owner instances in4 disclosed repositories are not26 independent projects;
31 scope-UNKNOWN owners are not successes. Conditional versions are100% on
Micro/Javalin/Drop and98.90% on Boot, with exact-version coverage equal to recall.
Java source/direct graph remains0/0/614 UNKNOWN, separate from image components.
Four actual Java pipelines total403.187s excluding registry acquisition of the
existing local archive. Peak RSS/hard disk quota/concurrent safety remain unknown.

JavaScript12 fresh attempts:11 publish all3views; exact project components
306/9/1,P97.14/R99.67/F198.39; macro8 positive rootsP93.48/R99.88, conditional
versions100%, exact-version coverage99.67. All three coordinate multisets of11
published outputs match R105. Axios/Fastify/Pino extras and Nest missing
@tokenizer/token remain. Total201.500s. Chalk fails publication with PermissionError,
no final; empty reference is never a perfect positive example. The failure stays
in the main protocol. A separately authorized ONE publisher-only diagnostic replay
of its retained source/image/provenance, frozen code and real Syft conversion
passes in6.000s; all3 coordinate multisets match R105. No new scans/oracle, no
silent substitution, no proven locking fix or exact failing operation.
[JS protocol](../benchmarks/results/mvp-r106-v1/javascript/evaluation.json),
[separate diagnostic](../benchmarks/results/chalk-publish-diagnostic-v1/run.json).
Image-only JS direct remains0/0/103 UNKNOWN.

Preselector481 service/selected benchmark tests pass,3 skips; Ruff passed. Tests include
STORED local-header/CRC/overlap/traversal/duplicate/wrong-layer/path negatives,
cross-witness exact-range-cache bounds and preservation of existing identity
UNKNOWN. First Linux RC Micro attempt independently fails BEFORE Java evidence:
Syft scratch fills the512MiB `/tmp`; this is an operational failure, not an
accuracy score. A separate Linux run of the same experimental code with
TMPDIR/TMP/TEMP=/workspace/process-temp passes517.271s pipeline/524.484s container;
final/os/full1878/0/1878 and all3 coordinate multisets equal Windows. Installed
source hashes and Java DB are unchanged. Workspace scratch is a separate shipping
configuration fix; it neither replaces the failed attempt nor enables the
experimental classifier by default. No new third-party build recipe, rebuilt
reference, runtime deployment or rank promotion; corpus29 immutable pairs unchanged.

Final selector RC `sbom-creator:mvp-r106-final`, config ID
`sha256:ce5737b1915804d33f6c335a3b13f01e6a61da319ff64beba0b70b57dbc55613`:
43 installed source/schema hashes equal freeze;1.282s read-only/nonroot/network-none
configuration smoke verifies defaultfalse, explicittrue, invalidflag rejection,
writable TMPDIR/TMP/TEMP=/workspace and unchanged512MiB `/tmp`. No source/reference/
socket input. Stored-reader SHA256
`26aca377bc5905da73b258bbacebc9a5b7c4de0726860bd82a16a2278078c00f` equals the
measured preselector algorithm exactly. No repeated nine-minute full Micro scan
was run merely for this configuration boundary; this smoke alone is not pipeline
equivalence or a new accuracy score.
[RC configuration proof](../benchmarks/results/mvp-r106-container-selector-v1/config-smoke.json).

Post-selector parity v2 passes using cached scanner catalogs, fresh physical reads
and actual Syft conversion/publication: experimental Micro50.766s exactly matches
R106 adapted catalog, physical evidence and canonical serialized audit; all3view
coordinate multisets and selected artifact IDs equal. Default=false Boot7.890s,
policy v4, preserves R105 stable all3views/IDs. No scanner/acquisition/reference
rerun or new independent accuracy claim. The retained v1 post-publication harness
assertion compared in-memory tuples against JSON lists and failed despite identical
published views/IDs and serialized facts; not a service bug or user obstacle.
[Parity v2](../benchmarks/results/mvp-r106-selector-parity-v2/report.json),
[retained harness negative](../benchmarks/results/mvp-r106-selector-parity-v1/harness-failure.json).
Final post-selector suite489 passed,3 skipped(492total),20.31s;
[XML](../benchmarks/results/mvp-r106-selector-unit.xml). Stable default remains R105;
experimental trade-off is still not accepted as default production behavior.

Next: establish exact bounded-read rejection categories and missing scanner
identity observations without loosening identity/ZIP checks; keep Micro recall70.71
visible, investigate correct packaged-vs-build labels separately, and verify
operational reliability beyond the verified Linux shipping scratch/selector boundary. Java aggregate >90 and JS
positive metrics do NOT establish independent universal >90 or complete direct
graphs. [Current actual service report](java-js-service-accuracy.md).

## R107 — opt-in LRU directory credits, unchanged hard budgets, 2026-10-16

No-oracle diagnostic of the frozen R106 reader reproduces identical adapted
catalog/physical facts and proves742 actual rejections at the256 fingerprint
credit cap; ledger7,689,813bytes/72,282entries, below16MiB/100k and below128MiB
payload windows. The failure is no longer attributed to an unknown guard.
[Diagnostic](../benchmarks/results/mvp-r107-directory-diagnostic-v1/report.json).

Hypothesis:256 credits bound retained fingerprints, not the total number of valid
JARs. New separately frozen `directory_jar_evidence.py` retains256 LRU credits;
eviction does not refund cumulative work. An evicted directory is fully charged
again before standard ZipFile allocation. SAME16MiB cumulative directory bytes,
100k charged entries,32MiB/read128MiB payload,8GiB verification, deadlines and
identity/path/layer/CRC guards. No simple cap increase, guessed alias, reference
input, raw-inventory substitution or default adoption. Explicit nested flag uses
experimental policy v6; stable default remains R105/v4.

R107 four-case runtime predictions use cached Syft/Trivy inventories plus FRESH
physical reads and actual Syft conversion/final-os-full publication. Source/code,
archives and cached inputs freeze BEFORE prediction; marker for all4 gates the
post-only evaluator. Micro124/1/16,P99.20/R88.57/F193.58 on the SAME agreed owner,
25newTP/25fewerFN versus R10699/1/41, no previous included coordinate removed,
no additional FP. Micro final2458 artifact instances is NOT TP count. Seven
other owner scopes remain UNKNOWN/raw deltas. Remaining16 misses:15 metadata-only
starter artifacts without class/resource witness, one netty-common identity
ambiguity despite physical bytes. jarmode remains conservative FP; no exclusions
to force the threshold. [Evaluation](../benchmarks/results/mvp-r107-v1/evaluation.json).

Micro ledger9,813,237bytes/91,317charged entries,256 live directory credits,
106evictions/362charges; no budget guard rejection. Payload95,536,087bytes,
normalization1,303,884,800 once and verification1,952,538,302bytes. Separate
post-only canonical audit explains12 old "not matched" misses:21 raw Syft
observations had namespace=artifactname, but each exact path/layer already had
ONE correct expected Trivy GAV; all21 observations were BudgetExceeded. The prior
diagnostic original-PURL join was too narrow; no new namespace/classifier rule.
Not all39 budget-affected FN became TP, because some starter archives have no
class/resource witness. [Canonical audit](../benchmarks/results/micro-missing-diagnosis-r107-v1/report.json).

Boot90/3/2, Javalin128/0/0(8 agreed/6UNKNOWN), Drop893/0/14(16 agreed/18UNKNOWN)
unchanged. Java micro1235/4/32,P99.677/R97.474/F198.563; repository macro
P98.994/R96.213/F197.526. Scoring remains26 owner instances across4 disclosed
repositories,31 additional UNKNOWN scopes; no independent acceptance. Conditional
versions100% except Boot98.90%, exact-version coverage equals recall. Timings:
Micro58.453s/Boot8.171s/Javalin4.406s/Drop40.969s,112.0s total; cached engines and
image acquisition excluded. Direct0/0/614 remains UNKNOWN, not image-derived.

JS is NOT rescanned:12 cached publisher regressions in84.657s reproduce all36
coordinate multisets and selected artifact IDs. Eleven compare with R106 successful
results; Chalk compares with its separately retained diagnostic publication.
R106 Chalk PermissionError remains FAILED, locking is not claimed fixed. Earlier
positive component metrics306/9/1 stay historical, not a new accuracy measurement.
[Cached JS publication regression](../benchmarks/results/mvp-r107-js-publish-v1/report.json).

501 tests pass,3 skips,20.03s;12 new security cases independently test LRU credit
eviction/recharge, unchanged byte/entry caps, parser-allocation ordering, unchanged
source/default reader and identity negatives.

Actual installed Linux `sbom-creator:mvp-r107`, config ID
`sha256:9030298f955b585040e1059c659e2767471555199fc4f66cb03aaa78780c0fd0`,
passes explicit-v6 image-only pipeline with FRESH Syft/Trivy scans, DB hashing,
physical reads and publisher:523.962s pipeline/527.344s harness, excluding local
archive registry acquisition. Nonroot/read-only/network-none, no source/oracle/
socket/service secrets.44 installed source/schema hashes match freeze;
source/JavaDB unchanged,16export/hash/schema checks pass. final/os/full2458/0/2458,
36UNKNOWN groups; all3 coordinate multisets AND2458 selected artifactIDs match
WindowsR107 exactly. This is installed full-pipeline parity, not a new independent
accuracy measurement or default adoption; four Windows timings remain cached
engine/ fresh physical/publisher only. Linux LRU ledger9,813,237bytes/91,317entries,
256resident/106evictions/362charges/2649hits, budgetguards/rejections0.
Raw catalogs are retained, without a cross-platform byte-equality claim.
[Installed verification](../benchmarks/results/mvp-r107-container-v1/verification.json),
[whole-view/ID comparison](../benchmarks/results/mvp-r107-container-v1/windows-coordinate-comparison.json),
[actual harness timing](../benchmarks/results/mvp-r107-container-v1/microservices/run.json).
No new foreign build recipe/reference/deployment; same29 immutable pairs.

Read-only future-scope audit finds existing real-build module CycloneDX SHA256
for every dependency, zero hash→multiple-GAV collisions, and immutable application
tree SHA256 for delivered standalone JARs. Own-module matches: Javalin185/199files,
Drop2145/2179, Micro1361/1369; unmatched files include primary module outputs.
This supports future separately attested packaged labels without rebuilding;
revalidate build/final TARs/config and nested fat-JAR extras, retain qualifiers,
unknown packaging and metadata-only delivered archives. Never use predictions
to select truth. Current31 UNKNOWN scopes and all current metrics remain unchanged.
[Scope-data availability, not new labels](../benchmarks/results/reactor-scope-audit-r107-v1/report.json).

Next: separate archive-presence vs code/resource-payload semantics for delivered
metadata-only JARs with explicit identity/physical proof and negative controls;
keep current16FN while testing. Installed Linux boundary now passes; independent
packaged-scope proof remains separate. MicroR88.57 still fails >90 despite favourable aggregate;
the opt-in/default split and precision trade-off remain explicit.

## R108 — runtime delivered-archive presence, 2026-10-16

Physical inspection precedes the new classifier: missing Boot starters are actual
metadata-only JARs, manifest/LICENSE/NOTICE and NO pom.properties. No fabricated
class/resource witness, filename GAV or reference-cache input. New runtime v7 has
an explicit archive-presence axis, complete physicalSHA256/SHA1/allmemberCRC,
canonical Maven properties or exact indexed readonly publicDB SHA1 association,
same config/finalregularpath/layer/virtualchain/uniquepeer GAV. DBsha pinned before/
after lookup; DB and Trivy correlated, no publisher/globalGAVuniqueness guarantee.
Internal sealed facts only; API cannot inject proof. Flag defaults false, v4/v6
unchanged. Metadata-only observed_payload remains unconfirmed.

47source/schema files and cached Syft1.51.1/Trivy0.75.0/archives/publicDB frozen
BEFORE four freshphysical/actualpublisher predictions; separate post-only evaluator:
Micro139/1/1 vs124/1/16, Boot90/3/2, Javalin128/0/0, Drop907/0/0 vs893/0/14.
29newTP/zero newFP/zero lost coordinates across3views. Java1264/4/3,
P99.6845/R99.7632/F199.7239; repositorymacroP99.0150/R99.2780/F199.1458;
conditionalversions99.9209/exactcoverage99.7632.1268predicted/1267reference delta+1.
26scored owners/31UNKNOWN remain, no fresh blind acceptance. Micro netty identity,
Boot group/version mistakes and packagingUNKNOWNFP retained.614directUNKNOWN/FN.
[Evaluation](../benchmarks/results/mvp-r108-v1/evaluation.json).

201archiveproofs(170Micro/31Drop),105canonicalproperties/96publichash, all complete
SHA256/SHA1+CRC and payload mappings EXACTR107, including201unconfirmedpayload.
Micro normalization1,303,884,800B once, verification1,953,449,473B,
payload96,514,144B; memberCRC3,950,660B charged toold128MiBordinaryread cap,
index9,814,345B/91,330entries,256resident107evictions. No cap increase.
Drop137ZIP_DIRECTORY_SINGLE retained. Timings63.468/9.875/6.641/49.797s exclude
cached scanner/acquisition cost.103new archive/hash negatives verify duplicates,
shading, escapes, badGAV/path/layer/producer, CRC/truncation/encryption/symlink,
staleproof/DBsnapshot/sibling, warmcache budgets and no rootPOM/packagejson promotion.
604tests pass3skips/Ruff. Freshphysical actualpublisher defaultBootv4/nestedJavalinv6
preserves3views/IDs and nested exactcatalog/payload/audit. JS12cachedpublisher/36schemas/
IDs equalR107 in89.578s, no scanner/physical/oracle calls or new accuracy; original
Chalk PermissionError unresolved. LastfreshJS306/9/1 retains weak fixture roots.

Next: post-only packagedSHA labels for31UNKNOWN via existing immutable build/runtime
TAR/config, held-from-tuning controls and JS weak roots beforedefaultadoption.
No new foreign recipe/reference/deployment; image-first release need not wait40pairs
or complete direct graph. All raw inventories and final/os/full preserved.

R108 separate POST-only packaged-scope groundwork: actual build-app/runtime-app TAR
SHA256 trees and exact OCI/config/DiffID-bound image application tree verified for
all3reactors; predictions not inputs. Unique own-moduleCDX standaloneSHA labels:
Javalin185/199(14UNKNOWN), Drop2145/2179(34attestedprimary separate),
Micro1361/1369(8attestedprimaryfatJAR separate). No forced31UNKNOWN closure or
newscore; nested/shaded primary content/packagingextras remainunlabelled.
[Independent tree binding](../benchmarks/results/reactor-packaged-scope-r108-v1/report.json).

R108 installed Linux full Micro pipeline with FRESH Syft/Trivy passes547.699s,
build31.109s; image/configsha256:aeae62a80a41d2ac2c8dae93a38f96233b7ee822ef74ead045a38211486047da.
47installed hashes,16exports/schema/hash checks, unchangedDB/source. Nonroot/read-only/
network-none/no socket/source/oracle/secrets,3GiB2CPU.2628/0/2628final-os-full,
5UNKNOWNgroups; exact3coordinate multisets/2628IDs/170completearchiveproofs/payloadfacts
matchWindows. Linux actualpayload95,338,413B vsWindows96,514,144; no falsecounterparity.
Cgroupmemory.peak856.0MiB(cache/probes included), notRSS/2GiBacceptance. No fresh
independent accuracy claim. Runtime379469a committed/pushed;46Gitblobs exactfreeze,
pre-existing image_java/__init__.py onlyCRLF/LF differs. Initial exactGitbyte check
negative retained, no executabletext change; actualinstalled47hashes matchsnapshot.
[Installed proof](../benchmarks/results/mvp-r108-container-v1/verification.json).

R108 lossless JSON evidence:340files/738,403,545original bytes retained locally,
120uniquegzip+smallJSON59,310,431B plus separately hashed container export.gz files.
package_mvp_r108.py restore/verify; manifestSHA2565a7b17a87e9541221b995bcb29e94aed01ff16f0727b1a1a390d82242d73762d. OldR105/R106/R107 manifests unchanged. Ruff/schema/hash/diff checks pass.

## R109 — explicit npm type surface and independent packaged SHA scope, 2026-10-16

Runtime change: payload.py accepts a safe explicit types/typings .d.ts final
regular nonempty file under the same package owner, matching manifestname/version
with npmPURL. Duplicate/conflicting/malformed/path/ancestor-link/nested-owner inputs
failclosed; legacy JS/data witness priority unchanged. payload_kind declared_type_surface,
manifestSHA saved; targetfilecontents notread/hashed, no JSexecution/typevalidity/
integrity/authenticity claim. Base rulespolicyv4; Java v7 remainsopt-in unchanged.

47source/schema files and12no-lock archives frozen before freshserial Syft scans/
actualpublisher. All12 succeed/36schemas before post-only oracle. JS307/9/0,
P97.1519/R100/F198.5554,macro8positiveP93.4808/R100/F196.1372,versions100;
Nest107/0/0,+1TP/no removed coords,190.048s localacquisitionexcluded.4emptyroots
notsuccess,9conservativefixture FP retained. Physical4image/197manifest audit confirms
these additional units have real JS/TS bytes, not absent-image defects; no blacklist.
R106Chalk failure preserved, no provenlockingfix. Initial evaluatorimportpreflight
failed beforeoracle, correctedhelperonly, no predictionrerun.

InstalledLinuxNode RC ad9e174893775b55c9c64742a8d243e8bf47125c51b2e592378370e895fdb61f
passes55.292s pipeline/57.610s container/30.281s build,47installed hashes and13exports
verified. Nonroot/readonly/networknone/no source/oracle/socket/secrets,3GiB2CPU.
NonOSfinal308coords+IDs/typesfact EXACTWindows; OS/full PARTIAL:88/396Linux vs89/397
Windows, additionalWindowsELF systemd252.39-1~deb12u2. Rawdeltas and failed strict
parity preserved; no OS filtering/retry or causeclaim. ColdDB/RSS nottested.

POST-only reference work, unchanged R108 predictions: actualfullhash nested/standalone
JAR labels and primary proofs, all56reactor known-owner sets.1259Micro nestedSHA
matches own-moduleCDX. Currentv4labels +v3evaluation3665/14/14,P/R/F199.6195;
Micro1341/12/8, Javalin184/0/1, Drop2140/2/5.47/56archive-only scopes complete;
8packagingextras and1oversizedprimarydirectory remainUNKNOWN, globalopaque/shaded
scope unknownall. Earlier conservativeviews3665/28/14/JavalinmacroP82.806 retained.
14root exclusions only after independent immutableDocker copyrecipe/effective/native/
CDX/canonicalproperties/fullactualSHA proof and no overwritecollision, neverprediction
intersection/filenameguess. OldR10826/31historicalmetrics immutable. IncludingoldBoot
90/3/2 yields3755/17/16,P99.5493/R99.5757/F199.5625 on knownscope, notglobalrecall.

Reference enumeration v1stoppedatdirectorybudget; v2unsupportedUnixdirectorymodes;
v3permits safezero-byte directorymetadata, v4strict primaryattestation. Allretained;
no productionguard/bytebudget changed.40enumeration/primarytests+30evaluatortests.
750totalservice/selectedtests pass3skips/Ruff;76newtypes tests/APIproofrejection.
4Java cachedpublisher regressions106.203s preserve12views/selectedIDs/policyv7;
no scanner/physical/source/oracle calls. Source frozen47==newJSsnapshot.

Nextreleasepriority: existing REST/DBCP held-from-recent-tuning imagecontrols, then
explicitdefaultJava v7 adoption if gates pass. No new foreignrecipe/40pair wait,
no deployment, sourcegraph remainsoptional. Fullinventory and uncertainty retained.

R109 runtime `9010f31` pushed. Lossless evidence:317 JSON,705,873,680 raw bytes,
63,228,323 stored bytes including small JSON;117 unique gzip objects. Manifest
SHA256 `5d7576fdf6be0301a2090bdc4b5742f72c014ec58d1ed1779581cfb80ce6c507`;
`python benchmarks/package_mvp_r109.py restore/verify`. Source binding46 exact/1 CRLF-LF only;
не менять frozen snapshots. Старые R105–R108 manifests сохранены.


## R110 — adopt verified Java archive components as release default, 2026-10-16

Settings/archive true and .env true, nested selector false; old explicitfalse
rollback retainsv4/v6. No reader/identity algorithm tuning or foreign build recipes.
Fresh serial image-only REST104/3/2 P97.196/R98.113,DBCP3/0/0 all100;6publishedviews
before post-only oracle. Held-from-recent-tuning, historically disclosed, not blind.
Bothcontrols metadata-only proofs0; disclosedR108201proof axis remainsseparate.
REST26.938s,DBCP7.516s. Combinedknown-delivered6repos59owners3862/20/18,
P99.4848/R99.5361/F199.5104, conditionalversions99.9482, delta+2;4previousR108/R109
measurements carried explicitly. Opaque/shaded completeness UNKNOWN,47/56reactor
archive scopescomplete; no universal acceptance claim. Direct638Java/103JSUNKNOWN.

Actual installed default RC mvp-r110 configsha256:e7ad622093c917aecc4d8c7e3094286e54c485c91566a5462b6d7c95d9be423f,
REST120.445s/container122.469s/build32.078s,47installed hashes exact,noJavaENVoverrides,
nonroot/readonly/networknone/nosocket/source/reference/secrets3GiB2CPU.16exports
verified; all3coords109/143/252 equalWindows,109nonOSIDs/payload equal;143OSIDsdiffer.
Raw258Windows/253Linux,unknown6/1 preservedseparate;causeUNKNOWN, norescan/filter.

sqlite3.Error added to scanner gracefulboundary: malformedpublicDBUNKNOWN preserves
raw/nonJava+3validviews without raw inclusion. Selector/error/pureNode tests added.
Compose3g/K8s3Gi32Giworkspace40Giephemeral examples parsed only, no deployment.
ColdDBdownload/recovery/hardquota/concurrency not accepted. R11012cachedJS real
publications80.797s preserve36views/12IDsets/alltypefacts vsfreshR109307/9/0;
notnewscanneraccuracy/Chalklockingfix.

Original controlfreeze69entries includes22generatedPYC aftersnapshotimport;preflight
negative preserved.47source plus22inertbase64bytecode archived/validated independently;
future runner sourcefreeze BEFOREimports. No attempts/snapshots overwritten.

R110 runtime `30902eb` pushed;803tests passed/3skips/Ruff/schema/freezechecks.
Commit binding44exact/3CRLF-LF-only,47actualinstalled bytes exactexecutedfreeze.
First focused/fullsuite failures were fixture missingaccessPath/mockSyftconversion,
retained separately; finalfullsuite620pass3skip +183benchmarkpass.

R110 losslesspack250JSON248,951,489rawB ->25,955,415BJSON+gzip86uniqueobjects;
manifestSHA2b2221eefc2dedfce13185c55c2f9fba8e2a36e962e0952e0586d1e7ea56a03a.
`python benchmarks/package_mvp_r110.py restore/verify`, originals retainedlocal,
R105–R109manifests unchanged.


## R111 — atomic public Java DB cache and actual cold/offline reuse, 2026-10-16

Cachepopulatedonlyifabsent. Private siblingstage, fullDBSHA/header/pagecount/metadata/
exactSQLitePK+nonpartialSHA1index+boundedqueryplan checks beforewholepair directory
atomic no-replace. Windowsrename/Linuxrenameat2; externalemptytarget neverreplaced.
Existinginvalidcache/foreignlock preserved; stalevalidcache read-only reused andflagged.
Stagepostexit2GiB/10kentries;metadata16KiB,DBhash1MiBchunks<=2GiB. ConstructorSQLVM
100ksteps/2s;fullquick_checkvalid1.55GBDB timedout2s, notcalledcorrupt/notusedproduction.
FixedCACHE_INVALID/BOOTSTRAP_BUSY/DOWNLOAD_FAILED/DOWNLOAD_INVALID/PUBLICATION_FAILED
exportedwithoutunsafe exceptiontext/paths. No fullintegrity/authenticity/fsyncdurability/
hostile-writerisolation claims.

NewactualbuiltRC4b31c639de2cb444b115dd5ced5bf1fbc9ce98cf3657b6fd2f0923a867f13698,
build35.797s,48installedhashesexactfreeze. Freshnativevolume coldpublicDBoneattempt:
download100.4886s,validate/publish2.2127s,pipeline110.125s/container111.781s.
OfflinewarmnetworkNONEpipeline9.171s/container10.609s,download0,validation2.0171s.
Nonroot10001/readonly/capdrop/nosocket/source/ref/secrets,3GiB2CPU,publicbridgecold,
no oldDBmount;native6symlinkcases+atomicempty/nonempty/toy9casesPASS0skips.
All3coordsets4/0/4 equalcold/warm/R110DBCP,known3/0/0 unchanged;notnewblindaccuracy.

NewpublicDB1,554,915,328B SHA491fe2ddb9cfd09bfb1e216d49541e9b64628621ce3538c23ecee5864bfefd59,
metadataSHA40b61a18939abfcdbedb76959f5c548100ad245f0a04ca4949b67d90a9078bb2,
UpdatedAt2026-10-16,NextUpdateOct19. DIFFERENToldc26ec91d… measured1,553,915,904B;
fulloldJavaaggregate3862/20/18 NOTremeasuredfornewDB. Tagsmutable,publishernotattested.
Newvolume sbom-r111-public-java-1792134539387152100 retained;oldcache/29pairs unchanged.

Peer-onlyoldDB REST252/DBCP4 allGAV/type/properties/path/layer/config exactR110,
freshTrivy4.703/4.125s,noSyft/physical/publisher/oracle/download. v1snapshotbeforefinal
cacheparentguard (noidentitychange);currentinstalledcold/warm coversfinalguard.
889testsPASS9skip (701service+188bench);6Windowslinkprivilege skips verifiedseparately
onLinux,3oldskips. Initialcachefocusedfailure fixtureSQLitecontextcommittedbutdidnot
close DB, fixedsharedtestfixture withclosing;negativeXMLpreserved. Nativecoldharnessv1
sanitizedhostenvcouldnotfindbuildx,failedbeforebuild/network;v2onlynonsecretpluginpaths
restored,ONEactualnetworkdownload. No runtime classifier precision claim/rankpromotion.

Next: compare newpublicDB classifierinputs vsmeasuredcorpus beforeclaimingnewDBscores;
onlychangedfinals neednewpost-eval. No newforeignrecipe/reader-onlyunchangedloops.

R111 runtime `782cae1` pushed. Gitbinding45exact/3CRLF-LF-only,48installedbytes
exactexecutedsource. CRLFprogramsnapshotsretained; exactLF reconstructedfromfrozen
harnessASTmatchespre-execSHA,NOTindependentcontainerargvcapture(reducedinspectomitsArgs).
No rerun/normalization.

R111 pack85JSON3,431,636rawB ->2,101,338B JSON+gzip(4large/2uniquegzip),manifest
SHAdfd8685e0872267314c2f6b661f462acba0143b79352b0363f3d154dd9a398a3.
package_mvp_r111.py restore/verify; originalsretained,newDBinnamedvolumeNOTGit,
oldR105–R110manifestsunchanged.

## R112 — new public Java DB, six actual publications and cache-path fixes, 2026-10-16

Runtime `88de091` pushed. Removed peer mkdir-before-validation and normalized relative
cache to one lexical absolute path before checked ancestors/tool execution. Unsafe
path maps to fixed CACHE_INVALID.722 full-service tests PASS/10skips,188 selected
benchmark regressions PASS; three new peer tests cover preflight/no side effects,
native linked parent and cold/warm relativecache vs subprocess cwd. Native Linux
actual peer with copied48source/networkNONE/no tool/DB/oracle: v2 PASS0skip.
v1 retained rawValueError diagnostic, corrected with fixed wrapper before freeze.
Interim selected testv1 and nonrepo-env fullv2 kept; final repo.venv full-service-v1.

Retained R111 new publicDB exported read-only volume -> separate R112 cache:
1,554,915,328B SHA491fe2ddb9cfd09bfb1e216d49541e9b64628621ce3538c23ecee5864bfefd59,
metadataSHA40b61a18939abfcdbedb76959f5c548100ad245f0a04ca4949b67d90a9078bb2.
Export9.579s, no network/source/oracle/oldDB mount. Old measuredDB c26ec91d… unchanged.

Frozen current48source/schema+tools+siximagearchives+cached ORIGINAL Syft/empty-source
catalogs+newDB/metadata before predictions. Fresh offline Trivy/physical/identity gates/
actual publisher, no download/acquisition/build/reference. All six completed0fail,
18schemas96outputs sealed before POST evaluator. Case seconds Micro118.953,Boot19.031,
Jav13.954,Drop86.797,REST20.781,DBCP7.094; sum266.610 excludes cached Syft/acquisition/
download/freeze. MarkerSHA3e5956bce138b1df96462d17a3dd218e814df1fc4cded6016228be1c184adfd3,
freezeSHAf3e388b13530e65b28c72e1348a2de680e3839d99a568f983e7167716636eac7.

POST same packaged labels: Micro1341/12/8, Boot90/3/2, Jav184/0/1,Drop2140/2/5,
REST104/3/2,DBCP3/0/0; aggregate3862/20/18,P99.4848/R/exactcoverage99.5361/F199.5104,
conditionalversions99.9482,delta+2 (3882pred/3880known). Repository macroP98.8317/
R99.0954/F198.9626; all six repositories/59knownowner sets >90 in this partial scope.
All six raw Trivy GAV/property/path/layer/config multisets,18 final/os/full coordinate
multisets and6 selected-IDsets exactly same oldDB,0added/removed. Separate historical
view1371/7/5 unchanged,31scopeUNKNOWN,59globalshadingpartial/67unknown packaging kept.
Not fresh blind acceptance/independent metadata-only coverage/globalrecall guarantee.
JS R109307/9/0 latestfresh notremeasured; fixtureFP/Chalknegative retained.
No ranking change, no source/direct inference, no foreignrecipes/40pair gate/deployment.
[Predictions](../benchmarks/results/mvp-r112-java-v1/predictions-complete.json),
[POST comparison](../benchmarks/results/mvp-r112-evaluation-v1/evaluation.json).

Installed currentRC sbom-creator:mvp-r112 config46911efe835d118cae7f5decde254c988f6d32504482405bf8273a8c646280b8,
build29.906s (pip downloads allowed),onewarmDBCPnetworkNONEpipeline9.839s/container13.563s,
48installedhashes/defaultv7/3schemas/16exports/actualreadonlyprogramSHA+CmdArgs PASS.
NewDB491fe/metadata40b61 unchanged,download0. All3views4/0/4 and selectedIDs exact
currenthost. Nonroot10001/readonly/nosocket/source/ref/secrets,3GiB2CPU;onlyjoboffline,
notwholebuild. Container removed,ownedrunsubdir/nativevolume retained. No newaccuracy
claim/installedall6claim/OSbitparity/RSS/hardquota/concurrencyacceptance.
Final959unique passingpytestnodes10skips (722service+188bench+37eval+5targetedwith1repeat+8container),
Ruff/seals/schema/hash checks PASS. Containerunitv1stringassertfailure preserved,
v2correctstructuralcheckPASS,oneactualbuild/jobPASSfirstattempt. RuntimeGitbinding
45exact/3CRLF-LF-only;actual48installedbytes exactfreeze, snapshots unchanged.

R112 lossless pack172JSON502,626,212rawB ->38,666,627trackedJSON+gzipB,
48large/45uniquegzip, manifestSHA16fa49694e51a85974aaeeaceb98a7438c7a8e45b830a5758277f9cc20791ad1.
package_mvp_r112.py restore/verify; originals/R105–R111 manifests preserved.
Next practical saved Chalk publication failure diagnosis/genericidentity ambiguity,
not unchanged reader/transport/DB replay or newforeignrecipes. Coverage limitations
remain explicit; component MVP threshold is not universal/fullCI/directgraph claim.

## R113 — publication failure provenance and atomic no-replace, 2026-10-16

Static history audit: originalR106Chalk failure onlyPermissionError at broadstage,
15.671s, nooperation/errno/winerror/traceback/filename. Currentprechangepipeline bytes
exactR1064dab0492...; priorcachedsuccess6.0s is notlockingfix/causeproof. Oldinputs/failure
immutable. No newscan/source/build/DB/oracle. History reports mvp-r113-chalk-history-v1.

Runtime7726706 pushed. New publication.py internalstate/fixedenums; primaryfailure
preserved throughsecondarydiagnostic/cleanup errors. Correctowncommittruth andAPI409
onpostcommitcleanupfailure,CLIexit1/outputblocked. Existingtargetrefusal preserved;
newWindows/Linuxatomicno-replace doesnotreplace racingemptytarget. UnsupportedOS/FS
failclosed,nofsync/hostilewriterclaim. VerificationAPI/CLIstagefallbackfixed. LegacyJSON
replace20attempts/25ms bound unchanged, noaddedscanner/converter/analysis retry.

757fullservicePASS10skip,208benchPASS;26newfault cases+9API/CLI includeconverterpartial,
artifactwrite/replace,dircommit/race,primary+secondarycleanup,diagnosticunavailable/
partial,postcommittruth,forgederrorattrs,CLI/APIredaction/verificationstage/409.
Linuxnative5contracts0skip onfinal49source:atomicpositive/empty+nonemptyconflicts/
firstfailurepreservation/postcommitcleanuptruth. Nativev1predatesfinalgenericfallback
typeguard(pipelineonly),v2all49finalbytes; originalv1retained. Initialpytestwrongmissing
tests/test_cli.py yieldednotests; v2existing22PASS. APIfocusedv1 hadonefallbackexpectation
mismatch(testonly),v2correctcontract9PASS, no runtime failure suppressed.

Frozen49source/schema +16cachedinputs +pinnedSyft BEFORE ONLY2publisher jobs:
originalR106Chalkdiag->priorgooddiag andR109Nesttypefacts->priorR109. Chalk6.453s,
Nest9.531s,total16.125s,2converts. Allthreecoordinate multisets/selectedIDs/wholepayload/
source+imagecatalogs exactbaseline; declaredtypewitness retained. Counts199/89/288,
308/89/397 aren'tTP/accuracy. OriginalR106failure/inputs andallfrozenfilesunchanged.
MarkerSHAd72f8041f23408745e86df26367f92fe784ecac4b602ab3d27674f2db3a366a3,
freeze45fc4dc22296366010173537987dbc88880f6bf2f0fdf613d26794465abd21f7.
No scanner/physical/DB/oracle, no accuracygain/historicalcausefixclaim/rankingchange.
JavaR1123862/20/18,JSR109307/9/0 andallknownscope/UNKNOWNlimitations retained.

Installed RC sbom-creator:mvp-r113 configID
sha256:d87700c34df1d43ced56235d79ce086f986016f73a3bfb7667d802cd9edfbf12:
onebuild32.828s (ordinarypipdownloads),onecachedNestpublisher9.427s/container10.797s.
49installedhashes/defaultarchiveTrue+nestedFalse/nofeatureoverrides,actualreadonly
programSHA+Cmd/Path/Args,13gzipexports PASS. All3views308/89/397+selectedIDs+payload
exacthostNest; declaredtypewitness retained. Nonroot10001/readonly/networkNONE/
3GiB2CPU/no socket/sourceproject/reference/secrets/DB/scanner/physical reads.
Container removed,ownworkspacevolume retained. Notnewaccuracy/scanner/DBacceptance.
Final971unique pytestnodes PASS10skips (757service+208bench+6container),native5/0
separate. HistoricalChalkcauseUNKNOWN;successful replay doesn't provefix.

Final source binding:46exact Git blobs/3CRLF-LF-only;all49actualinstalledbytes
equalexecutedfreeze. Existingcodechangesonlypipeline/service/cli,newpublication.py;
classifier/reader/cache filesunchanged. OldR105–R112manifestsunchanged.
R113losslesspack90JSON78,845,652rawB ->8,848,467trackedJSON+gzipB,
23large/19uniquegzip;manifestSHA25a7c79e5e438dc86db0aab393c2966ebdda3acdab7722918498ab57a8141998.
package_mvp_r113.py restore/verify;originals/exactsnapshots retained.
[Final validation](../benchmarks/results/mvp-r113-final-validation.json).
