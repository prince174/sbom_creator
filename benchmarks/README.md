# Проверка на 60 репозиториях

В 0.4.0 основной final исключает пакеты ОС; отдельные OS/full представления
проверены на [всех 60 сохранённых результатах](../docs/verification-inventory-views-v1.json).
Историческая таблица ниже относится к полному составу 0.3.0 и не перезаписана.
Новые CSV/JSON включают `inventory_scope`, `os_count`, `full_count`; в Markdown
`Final` означает основной результат согласно scope. Старый полный cache не
используется как новый результат без ОС: требуется replay или rescan.

Актуальное повторное сканирование по правилам v3: [таблица](results/rules-v3-20260930/results.md)
и [аудит](results/rules-v3-20260930/audit-final.json). Предыдущие прогоны сохранены
отдельно. Правила — основной режим сервиса; LLM не требуется.
Нативные контрольные образы для всех шести языков создаёт `native_golden.py`;
методика и границы метрик описаны в [отчёте 0.3.0](../docs/rules-v3.md).

`manifest.json` содержит ровно по 10 различных репозиториев для Java, JavaScript,
Python, Rust, Go и Ruby. В нём закреплены полные commit SHA. 3 репозитория —
существующие Python fixtures пользователя с реальными `.py` в Bitbucket Cloud, 57 — публичные
проекты GitHub. Публичные проекты дополняют языки, которых нет в доступном workspace.
Fixtures отличаются от полноценных production-приложений; происхождение не скрыто.
Остальные исходные Bitbucket fixtures вынесены в `fixtures-manifest.json` и
`results/bitbucket-fixtures/`, отдельно от основной матрицы. Шесть из них
(четыре Java demo и два npm demo) содержат только
manifests/CI, без исходников приложения. Для них проверка package metadata
остаётся видимой в SBOM, но `expected_application_*` помечается N/A, а coverage
явно содержит `no application source code`. `lab-npm` содержит CI scripts, а
`lab-maven` — небольшой Java fixture; для единообразия оба также оставлены только
в дополнительных проверках. Старый промежуточный реестр из 11 fixtures и 49 public
сохранён в `results/legacy-fixture-inclusive-20260929/` как история, не итог.

`inspect_bitbucket.py` читает только API GET существующего workspace. Он использует
из `.env` только `BITBUCKET_WORKSPACE`, `BITBUCKET_EMAIL`, `BITBUCKET_TOKEN`.
Административные и модельные ключи не читаются и не копируются. Git получает
read-only token через окружение дочернего процесса, не URL, argv или Git config.
Скрипт ничего не создаёт и не меняет в Bitbucket или TeamCity.

```powershell
.\.venv\Scripts\python.exe benchmarks\run.py --phase all --mode rules
.\.venv\Scripts\python.exe benchmarks\run.py --phase all --language Python
.\.venv\Scripts\python.exe benchmarks\run.py --phase analyze --mode llm
```

Каждый checkout проверяется по HEAD. Syft сохраняет настоящий source scan.
Образы собираются отдельным процессом из checkout: pip install, npm install,
Maven/Gradle, gem build/install, go build и cargo auditable build. Это проверка
контролируемой сборки; образ не выдаётся за образ исходного production pipeline.
Rust имеет дополнительную auditable metadata, которой обычные бинарники могут
не содержать. JavaScript устанавливается с `--omit=dev --ignore-scripts`:
произвольные install hooks не выполняются, сложные bundler-сборки не проверяются.
Простой Bitbucket Python fixture не имеет пакетного metadata: его код помещается
в Python runtime без выдуманной зависимости.

Для Gson и SLF4J собираются библиотечные модули `gson` и `slf4j-api` вместе с
необходимыми reactor parents, а не их отдельные integration/shrinker приложения.
Gson требует компиляции test sources для своего obfuscation шага; эти артефакты
остаются в build stage. В runtime копируется ровно один основной library JAR и
его runtime dependencies. Предыдущие ошибки общих Maven recipes сохранены.

Первый Go build выявил особенность среды: Windows checkout с CRLF после COPY в
Linux воспринимался Git как dirty, поэтому Go записывал `vX.Y.Z+dirty` вместо
release version. Это не ошибка Syft. Исправленный рецепт восстанавливает tracked
файлы того же HEAD с `core.autocrlf=false` внутри disposable build stage перед
компиляцией; checkout на хосте не меняется, версия не подставляется вручную.
Предыдущие попытки, image IDs и SBOM сохранены. Go compiler/module caches используют
обычные content-addressed cache mounts, в runtime копируется только текущий `/out`.

Go/Java/Rust собираются не более чем одним тяжёлым build-процессом одновременно;
Cargo (включая установку auditable), Go и JVM ограничены двумя workers/CPU threads.
Лёгкие Ruby/Python/JavaScript этапы и сканирование могут выполняться параллельно с
одним Rust prebuild. Отдельный worker пишет собственный checkpoint-отчёт, после
чего `merge_prebuild.py` переносит результаты, сохраняя уже выполненный анализ.
Базовые image tags могут изменяться; итоговый immutable Docker image ID и
SHA-256 рецепта сохраняются. Docker ID может быть OCI index или config digest;
выбранный config дополнительно проверяет основной scanner по сохранённому архиву.
Для независимого повторения production-сборок необходимы закреплённые
base-image digests и lockfiles; ряд тестовых библиотек не фиксирует транзитивные
зависимости. Такие ограничения не скрываются заявлением о полной повторяемости.

Результаты сохраняются после каждого репозитория в JSON, CSV и Markdown. Статусы
`checkout_complete`, `source_scanned`, `build_complete`, `failed` не равны
завершённому end-to-end тесту. `completed_rules` требует успешной публикации
настоящего CycloneDX и подтверждения его schema validation основным pipeline.
Режим rules явно отделён от LLM; незапущенная модель не получает оценку качества.

Колонки `expected_application_observed` / `expected_application_in_final` проверяют
одну release-идентичность основного пакета из манифеста по точному PURL. Это
ограниченная проверка: Go local build может сообщать `(devel)`, а GOPATH-only
assetfinder не сохраняет module identity. Gradle fixtures с unspecified version
и обычный Python script не имеют применимой точной пакетной идентичности.
В итоговом прогоне точная release-идентичность обнаружена и включена для 54 из
59 применимых основных пакетов. У `httprobe`, `yq`, `glow` и `scc` каталог
содержит основной Go module с pseudo-version `v0.0.0-<timestamp>-<commit>`;
у `assetfinder` нет module identity. Поэтому эти пять строк имеют `false`.
Для plain Python fixture оценка неприменима. Полная точность инвентаризации
из этих ограниченных наблюдений не рассчитывается.

FP/FN оставлены пустыми: ожидаемая полная инвентаризация не была независимо
размечена, а результат Syft не используется в качестве собственной ground truth.
Наличие компонента в образе не доказывает выполнение его кода. Отчёты фиксируют
отдельно source/image/final counts и INCLUDE/EXCLUDE/UNKNOWN, а также ошибки стадий.
`seconds` и колонка «Сек.» — суммарное время подготовки и зафиксированных попыток этого
репозитория: checkout, source scan, сборки, анализ, чтение cache и replay, включая
неуспешные этапы. Прерванные до checkpoint этапы могут не войти в сумму;
это не latency production API и не производительность LLM. Новые вызовы
сервиса отдельно фиксируют `last_analysis_seconds`. Replay запускается через
`--phase replay`, сохраняет старые каталоги и provenance, не требует новой сборки.
Каталоги без provenance требуют нового сканирования. При повторном чтении результата
проверяются реальные схемы, hashes, commit, Docker image ID и image config digest,
а также режим оценщика; неподходящий cache не считается успешным результатом.

Большие checkout, build logs и сырые каталоги хранятся в `.work` и не коммитятся.
Компактные отчёты и манифест остаются в репозитории. Повторный анализ использует
уже опубликованный успешный результат; `--fresh --phase analyze` запускает новое
сканирование того же immutable образа и сохраняет прежний output. Для отдельной
сборки укажите новый `--work` и `--output`. Образы, volumes и чужие процессы не удаляются.

```powershell
python benchmarks/run.py --phase analyze --mode rules --fresh --output benchmarks/results/new-run
python benchmarks/verify_results.py --results benchmarks/results/new-run/results.json --require-all-complete --check-current-policy
```

Для нового output нужны результаты подготовленных checkout/build (либо сначала
`--phase all`). `--fresh` не подменяет исходники или образы и не пересобирает их.
Сквозной `http_integration.py` использует существующий Bitbucket fixture, отдельный
локальный HTTPS registry и временный сервис с тестовым CA. Токен читается только
для Git; в отчёт не попадает. CA хоста и чужие контейнеры не изменяются.
