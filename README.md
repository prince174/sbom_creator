# SBOM Creator

Python-сервис получает **container image по digest** и выдаёт **CycloneDX JSON 1.6**
по фактическому содержимому образа. **Bitbucket HTTPS URL + полный commit SHA** —
дополнительные входы для объяснения происхождения и графа зависимостей.
Основной режим API и CLI — детерминированные правила, без LLM и модельных ключей.
Загрузку в Dependency-Track выполняет пользователь.

**Текущий MVP: образ — основной вход, репозиторий необязателен.** Syft1.51.1
собирает inventory; для Java Trivy0.75.0 уточняет координаты, а ограниченный
reader подтверждает class/resource bytes больших и вложенных JAR из того же образа.
Crane0.22.1 получает внутренний архив по immutable digest без Docker Engine/socket.
Идентичность, путь, слой и image config связываются отдельно от наличия payload.
Неоднозначность остаётся UNKNOWN, в том числе при сбое дополнительного Java-анализа.
Все три inventory и исходные свидетельства сохраняются.

R109 дополнительно подтверждает type-only npm-компоненты: явные `types`/`typings`
должны указывать на непустой regular `.d.ts` внутри того же package owner, а
name/version manifest — совпадать с npm PURL. Свидетельство имеет
`payload_kind=declared_type_surface`; оно не означает исполнение JavaScript,
валидность TypeScript или проверку целостности `.d.ts`. Manifest SHA256 сохраняется.
Небезопасный путь, borrowed nested package, symlink, conflicting/duplicate fields
оставляют UNKNOWN. Обычные JS/data-package witnesses сохраняют приоритет.
Новый базовый policy — `image-evidence-and-payload-v4`. R110 выбирает Java v7 по умолчанию;
`SBOM_JAVA_ARCHIVE_COMPONENTS=false` явно возвращает прежний payload-only режим.
12 свежих image-only no-lock запусков:307/9/0, P97.15%, R100%;9 дополнительных
поставленных fixture units не удаляются из полного inventory ради метрики.

Репозиторий не требуется пересобирать ради выдачи image SBOM. Дополнительное
Java-обогащение через cdxgen/Maven или пассивный Trivy включается отдельно;
по умолчанию `SBOM_JAVA_BACKEND=disabled`. Оно не добавляет в image SBOM
компоненты, обнаруженные только в исходниках. Успешная модель Maven не означает
воспроизведение неизвестных шагов оригинальной TeamCity-сборки. Текущие метрики,
области оценки и ограничения — в [отчёте точности](docs/java-js-service-accuracy.md).

**0.7.0: прямые Python-зависимости корня проекта.** Сервис автоматически читает
корневой `pyproject.toml` (до1МиБ) и сопоставляет статические зависимости с
Requires-Dist установленного корня и пакетами в том же site-packages. Добавляет
подтверждённые package-to-package рёбра в CycloneDX и `direct-dependencies.json`.
API/CLI входы прежние; установка или исполнение исходного проекта не выполняется.
Markers, extras, URL, dynamic dependencies и неоднозначность остаются UNKNOWN.
Это декларации runtime-зависимостей, не доказательство использования при сборке.
На малом Python-контроле Flask/HTTPX:9точных рёбер/версий,0FP/0FN; не общая
точность Python. npm-профиль и три inventory сохранены.
[Проверки и ограничения0.7.0](docs/runtime-python-r19.md).

**0.6.0: прямые npm-зависимости корня проекта.** Для поддерживаемых деклараций
сервис добавляет связи от package-компонента приложения к пакетам в его локальном
node_modules. Входы прежние; Docker/Node/LLM для этого не нужны. Полный inventory
сохраняется. `direct-dependencies.json` содержит DIRECT/UNKNOWN, причины и SHA256
исходного package.json. Это декларация runtime-зависимости, не доказательство
исполнения или использования при сборке. Поддержаны стабильные x.y.z, ~x.y.z и
^x.y.z; union, prerelease, workspaces и неоднозначные случаи остаются UNKNOWN.
Dev/peer-only и остальные языки npm-профилем не оцениваются.
[Проверки интеграции и ограничения](docs/runtime-npm-v1.md).

**0.5.0: основной image-путь не требует Docker CLI, Engine или socket.** Образы получает
Syft напрямую из registry; новый Java-reader также использует Crane. Сохранены правила, проверка payload и разделение ОС.
[Подробный отчёт миграции и проверок](docs/direct-syft-v0.5.md).

**С версии 0.4.0 основной `final.cdx.json` не содержит пакетов ОС.** Они выдаются
отдельно в `os.cdx.json`; `full.cdx.json` сохраняет полный подтверждённый состав.
Основной результат пока точнее называть «пакеты вне пакетной системы ОС», а не
«гарантированно использованные при сборке проекта»: языковые пакеты и инструменты
из базового образа тоже могут присутствовать. Их происхождение ещё не доказано.

На 60 сохранённых результатах: **4165 записей вне ОС + 6090 записей ОС = 10 255**.
[Проверка разделения и хеши архива](docs/verification-inventory-views-v1.json).
Это повторный экспорт уже проверенного состава, без нового сканирования образов.
Версия 0.4.0 проверена отдельно: [183 passed, 1 skipped на Windows](docs/verification-0.4.0-windows.xml),
[184 passed на Linux](docs/verification-0.4.0-linux.xml), [сквозной Bitbucket/registry/API](docs/verification-http-v0.4.json).

Основа — подход `SCA_accuracy_improvement`: точные входы, evidence и проверяемые
решения по каждому компоненту. Этот проект не меняет исходный сервис.

Схемы: [draw.io](docs/system-workflow.drawio),
[интерактивный HTML](docs/system-workflow.html), [архитектура](docs/architecture.md).

## Решение по компоненту

**Итоговый SBOM строится из подтверждённых записей образа.** Исходники помогают
сопоставлять версии и объяснять расхождения, но не добавляют в итог зависимости,
наличие которых в образе не подтверждено. Очереди приоритетов «сначала совпавшие,
потом только образ» нет: к обоим случаям применяется одинаковая проверка.

Сравнивается объединение кандидатов двух SBOM. Нормализованный PURL сохраняет
экосистему, namespace, точную версию и qualifiers. Версии не объединяются.
Fallback без PURL требует точной идентичности; fuzzy match не разрешает включение.

| Ситуация | Результат |
|---|---|
| В образе и исходниках совпали идентичность и версия; свидетельств образа достаточно | INCLUDE: запись из SBOM образа |
| Только в образе; свидетельств достаточно | INCLUDE; пакеты ОС направляются в отдельный `os.cdx.json` |
| Только в исходниках | UNKNOWN; отсутствие в образе не доказано |
| В исходниках A@1, в образе подтверждена A@2 | A@2 включается; A@1 остаётся UNKNOWN |
| В образе есть metadata, но необходимые файлы не подтверждены | UNKNOWN / PAYLOAD_NOT_CONFIRMED |
| Только скопированный lockfile или неоднозначная идентичность | UNKNOWN |
| Дополнительный Java-reader/Trivy не подтвердил сведения | Основной анализ сохраняется; непроверенные Java-компоненты UNKNOWN, coverage partial |
| Сбой получения входов, сканера, конвертации или schema | Задание failed, final недоступен |

Правила v3 дополнительно проверяют содержимое конечной файловой системы: Python RECORD,
npm entry point/index/код, Ruby gem-файлы, Java class и Go/Rust binary. Оставшаяся metadata
без подтверждённых файлов даёт `UNKNOWN / PAYLOAD_NOT_CONFIRMED`.
Пакеты ОС и image-only зависимости тоже рассматриваются. Наличие metadata не
доказывает выполнение кода. Пакеты ОС сейчас подтверждаются по пакетной metadata;
проверка языковых пакетов устанавливает наличие части payload, а не целостность
каждого файла. Поэтому «подтверждено свидетельствами» не означает гарантию полноты.
Вероятности и оценки TP в режиме правил не назначаются.
Исходные source/image SBOM сохраняются. UNKNOWN делает результат частичным.
Неполученные submodules/LFS отражаются в coverage. В основном image-пути проект
не выполняется. Явно включённый cdxgen backend выполняет project tooling в отдельном
ограниченном job-контейнере; секреты сервиса и Docker socket туда не передаются.

## Linux / Docker

В основном image-режиме **Docker CLI, Engine и socket сервису не нужны**. Образ содержит
Python, Git, закреплённые Syft, Trivy и Crane; Docker CLI доступен только для
необязательного cdxgen coordinator. `syft scan registry:...` получает образ напрямую
по HTTPS. Контейнер работает с UID/GID 10001, read-only root filesystem и без capabilities.
Docker Compose ниже — способ запуска контейнера, а не зависимость внутри сервиса.
Сервис запускается одним процессом; несколько независимых экземпляров не должны делить workspace.

```bash
cp .env.example .env
mkdir -p secrets workspace
# На Linux workspace доступен UID/GID 10001; секреты должны быть читаемы этим UID.
sudo chown 10001:10001 workspace
# Заполните .env, положите токены в secrets/* согласно *_FILE.
docker compose up --build -d
```

Порт: `127.0.0.1:18082`. Для доступа извне используйте HTTPS reverse proxy.
`/health` подтверждает работу API, но не готовность Git/registry.

Для первого Java-анализа Trivy загружает публичную Java DB. В проверенном snapshot
база занимает около1.5GiB; её SHA256 сохраняется с результатом и проверяется до/после
сканирования. Задайте writable persistent `SBOM_TRIVY_CACHE_DIR=/workspace/trivy-cache`,
особенно при read-only root filesystem. Внутренние архивы и нормализованные слои
используют `SBOM_IMAGE_TEMP_DIR=/workspace/image-cache` и удаляются после задания.
Контейнер направляет также scratch-файлы сканеров в `/workspace` через
`TMPDIR`/`TMP`/`TEMP`: небольшого tmpfs `/tmp` недостаточно для крупных образов.
Для offline-работы базу нужно заранее подготовить; недоступная DB даёт UNKNOWN для
неподтверждённых Java-компонентов. R111 загружает отсутствующую DB в отдельный private
stage, проверяет metadata/полный SHA256/SQLite layout/schema/index и публикует пару
DB+metadata одной атомарной операцией без замены существующего target. Ошибка не
оставляет частичный файл на месте рабочего cache. Валидная, даже stale, DB используется
без hidden refresh; stale и metadata SHA отражаются в provenance. Повреждённый
существующий cache сохраняется и даёт fixed error code/UNKNOWN, а не перезаписывается.
[Коды и безопасное восстановление cache](docs/java-db-cache-r111.md).
Начинайте с одного worker: жёсткая дисковая квота и пиковая память нескольких
параллельных больших Java-образов отдельно не измерены.

Для Kubernetes см. [пример Deployment](deploy/kubernetes.yaml): без hostPath,
без service-account token, `runAsNonRoot`, `allowPrivilegeEscalation: false`,
`seccompProfile: RuntimeDefault`. Подставьте свой image digest, hosts и Secret.
Для сохранения результатов используйте PVC вместо тестового emptyDir.
В настоящем Kubernetes-кластере пример пока не проверялся.

### Настройки

| Переменная | Назначение |
|---|---|
| `SBOM_API_TOKEN` / `_FILE` | Bearer token клиента API; без него API выдаёт 503 |
| `SBOM_BITBUCKET_HOSTS` | Разрешённые точные hosts, включая port; через запятую |
| `SBOM_BITBUCKET_AUTH_MODE` | `basic` для Cloud, `bearer` для совместимого сервера |
| `SBOM_BITBUCKET_TOKEN` / `_FILE` | Токен чтения Git |
| `SBOM_BITBUCKET_USERNAME` | Для basic, default `x-bitbucket-api-token-auth` |
| `SBOM_CA_BUNDLE` | PEM CA для Git HTTPS, TLS-проверка остаётся включённой |
| `SBOM_REGISTRY_HOSTS` | Разрешённые registry hosts; image требует явного tag/digest |
| `SBOM_REGISTRY_USERNAME`, `SBOM_REGISTRY_PASSWORD` / `_FILE` | Registry credentials |
| `SBOM_IMAGE_ARCHIVE` | Только офлайн CLI: путь к архиву; API отвергает |
| `SBOM_MAX_ARCHIVE_BYTES` | Лимит временных файлов Syft / входного архива, default 8 GiB |
| `SBOM_IMAGE_PLATFORM` | Default `linux/amd64` |
| `SBOM_WORKERS` | 1–4, default 1; очередь ограничена 16 заданиями |
| `SBOM_SYFT_BINARY` | Путь к Syft, default `syft` |
| `SBOM_TRIVY_BINARY`, `SBOM_CRANE_BINARY` | Пути к закреплённым Trivy0.75.0 и Crane0.22.1 |
| `SBOM_TRIVY_CACHE_DIR` | Writable Java DB cache; для контейнера `/workspace/trivy-cache` |
| `SBOM_IMAGE_TEMP_DIR` | Writable каталог внутренних архивов/слоёв, в образе `/workspace/image-cache` |
| `SBOM_JAVA_IMAGE_EVIDENCE` | Java identity + physical evidence, default `true`; сбой отражается UNKNOWN |
| `SBOM_JAVA_NESTED_WINDOWS` | Экспериментальное чтение STORED nested JAR без копирования; default `false` |
| `SBOM_JAVA_ARCHIVE_COMPONENTS` | Полный поставленный Java-архив как отдельный компонент, включая metadata-only; default `true`, включает nested reader |
| `SBOM_JAVA_BACKEND` | Дополнительный граф исходников: `disabled` (default), `trivy`, `cdxgen` |
| `SBOM_CDXGEN_IMAGE`, `SBOM_DOCKER_BINARY` | Доверенный worker image и Docker CLI для явно включённого cdxgen backend |
| `SBOM_BUILD_TIMEOUT` | Лимит необязательного cdxgen job, default900s |

Секреты не включаются в argv, provenance и сообщения об ошибках.
Git redirects, hooks, inherited Git configs, автоматические submodules/LFS и
конфигурация Syft из репозитория отключены.

### Прямое получение образа и файловые свидетельства

Syft получает образ через `registry:`. Сервис пересчитывает SHA-256 raw manifest/config,
сверяет platform manifest, config digest, платформу и layer diff IDs. Для multi-arch
сохраняются repoDigests. TLS-проверка обязательна; передаются только настроенные
registry credentials, без внешних Docker helpers и пользовательской конфигурации.

Содержимое RECORD и package.json получает Syft из **того же squashed scan**.
Java-архивы больше не включаются целиком в stdout Syft: сервис получает внутренний
архив через Crane и связывает его config/DiffID с результатом сканирования.
Reader один раз нормализует слой, проверяет TAR/ZIP metadata до больших выделений,
читает ограниченные окна и подтверждает реальные class/resource bytes.
Применяются отдельные бюджеты:8GiB нормализации и8GiB потоковой проверки хешей,
32MiB/read и128MiB суммарных payload-window reads; размер outer JAR до128MiB.
Payload proof для одинаковых файлов переносится только после полного SHA256 каждого
физического JAR, без вывода имени/версии/прямоты из hash. Неподтверждённые метаданные, неоднозначный путь/слой/идентичность и
неподдержанный архив остаются UNKNOWN. Metadata-only JAR включается только по
отдельному полному archive presence/identity proof.
Содержимое файлов и scanner-конфигурация удаляются перед публикацией JSON.
Диск проверяется периодически; жёсткие границы задаются лимитами контейнера/тома.

Опция `SBOM_JAVA_NESTED_WINDOWS=true` включает экспериментальный reader с полным
CRC/SHA256 вложенных STORED JAR и теми же бюджетами. R107 хранит до256 directory
credits в LRU; после вытеснения повторный индекс снова расходует общий бюджет.

Измеренный режим R108/v7 принят как default в R110:

```bash
SBOM_JAVA_ARCHIVE_COMPONENTS=true
```

Он также выбирает nested reader и policy `image-delivered-archive-v7`. Помимо
class/resource payload сервис может подтвердить **поставленный архив как компонент**:
полные физические SHA256/SHA1, CRC файлов ZIP, точный image config/path/layer
и GAV через канонический `pom.properties` либо exact full-SHA1 association в
закреплённой публичной Java DB. Имя файла или один scanner inventory недостаточны.
Metadata-only JAR сохраняет `observed_payload=unconfirmed`; наличие кода, исполнение,
прямота и подлинность издателя не заявляются. Public DB и Trivy коррелированы;
SHA1 association не доказывает глобальную уникальность GAV. Original identity/audit
сохраняются. На прежних размеченных областях final: Micro139/1/1, Boot90/3/2,
Javalin128/0/0, Drop907/0/0. Java P99.68%, R/exact-version coverage99.76%;
ещё31 owner scope UNKNOWN. Это раскрытые проекты, не универсальная гарантия.
Прежние v4 и nested-only v6 доступны при явном `SBOM_JAVA_ARCHIVE_COMPONENTS=false`;
при nested=false выбираетсяv4, при nested=true —v6; их regression сохранена.
У существующей установки старое `.env` с false остаётся явным override: обновите
свою конфигурацию осознанно, файл сервис самостоятельно не меняет.
При недоступном Trivy/Java DB
сервис сохраняет raw inventory и помечает неподтверждённые Java components UNKNOWN,
не подставляет raw packages в final. Первый Java scan может загрузить публичную DB
(около1.55GB); закрытой сети нужен заранее подготовленный `SBOM_TRIVY_CACHE_DIR`.
Безопасная параллельность и жёсткие host disk quotas отдельно не сертифицированы.
Начальная загрузка и повторное offline-использование проверяются отдельно от accuracy
и описаны в [отчёте cache](docs/java-db-cache-r111.md). Workspace должен вмещать DB, входной архив, нормализованные слои
и результаты; Kubernetes пример даёт32Gi, для production нужен рассчитанный PVC
и retention. Это не разрешение менять развёрнутые сервисы.
Подробности — в [отчёте](docs/java-js-service-accuracy.md).

## API

`POST /v1/analyses`, `Authorization: Bearer <token>`:

```json
{
  "image": "registry.example.com/team/application@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}
```

Для дополнительного анализа исходников передайте URL и commit **вместе**:

```json
{
  "repository_url": "https://bitbucket.org/workspace/application.git",
  "commit": "0123456789abcdef0123456789abcdef01234567",
  "image": "registry.example.com/team/application:build-123"
}
```

Ответ 202 содержит `id` и `status_url`. Poll `GET /v1/analyses/{id}` до
`succeeded` или `failed`; оба требуют авторизации. В случае успеха:
`GET /v1/analyses/{id}/artifacts/final.cdx.json`.
До успеха скачивание блокируется 409; неподдержанные имена файлов — 404.
После рестарта незавершённые задания помечаются failed, автоматически не повторяются.

API всегда использует правила. CLI также использует их по умолчанию. Даже ошибочно
заданные `SBOM_LLM_*` не читаются и не вызывают обращений к модели. Сохранённый
экспериментальный CLI-режим `--mode llm` запускается только явно, требует собственной
конфигурации `SBOM_LLM_BASE_URL`, `SBOM_LLM_MODEL` и при необходимости ключа.
Он не является частью рабочего режима без LLM; скрытого переключения между режимами нет.

## CLI и локальная разработка

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
# Экспортируйте SBOM_* настройки в окружение; CLI не читает .env автоматически.
sbom-creator analyze --repository-url https://bitbucket.org/workspace/app.git \
  --commit FULL_SHA --image registry.example.com/app:build-123 --output workspace/result-1

# Только фактический состав образа, без Git и пересборки проекта:
sbom-creator analyze --image registry.example.com/app@sha256:FULL_DIGEST \
  --output workspace/image-result-1

# Локальный checkout, тот же режим правил:
sbom-creator analyze-local --source ./checkout --image registry.example.com/app:build-123 \
  --output workspace/result-rules --mode rules
```

`SBOM_IMAGE_ARCHIVE=/absolute/path/image.tar` включает офлайн-режим CLI
для подготовленного архива; HTTP API такую конфигурацию отвергает.
Формат Syft `docker-archive` не требует Docker. Старые переменные
`SBOM_PULL_IMAGE` отклоняется; основной image-анализ не переключается на daemon.
`SBOM_DOCKER_BINARY` используется только явно выбранным cdxgen backend.
Существующий output не перезаписывается. На Windows используется `.venv\Scripts\python`;
для локальной проверки Syft сохранён в `.tools/syft/syft.exe` (не включается в Git).

## Результаты

| Файл | Содержание |
|---|---|
| `final.cdx.json` | Проверенный CycloneDX 1.6 без пакетов ОС; основной результат для ручной загрузки |
| `os.cdx.json` | Отдельный CycloneDX с подтверждёнными пакетами ОС |
| `full.cdx.json` | Полный подтверждённый состав до разделения, включая связи между группами |
| `source.syft.json`, `image.syft.json` | Полные исходные каталоги |
| `selected.syft.json` | Все подтверждённые записи образа, соответствующие `full.cdx.json` |
| `decisions.json` | Все INCLUDE/EXCLUDE/UNKNOWN с evidence и причинами |
| `direct-dependencies.json` | Подтверждённые декларации npm/Python/Java, UNKNOWN и причины; граф не объявляется полным |
| `java-direct-dependencies.json` | Отдельные owner/module/version/scope и ограничения Java source model; без source входа not-applicable |
| `image-original.syft.json`, `image-peer.cdx.json`, `image-identity-audit.json` | При Java-анализе: исходные координаты Syft, независимый Trivy inventory и identity/payload audit |
| `build.cdx.json`, `image.cdx.json`, `build-image-comparison.json` | При успешном необязательном cdxgen backend: source/build model и отдельное сравнение с image inventory; не замена final |
| `coverage.json` | Catalogers, ограничения, неполнота и счётчики причин UNKNOWN |
| `review.json` | UNKNOWN по группам проверки, происхождению, типу пакета, причине и следующему шагу |
| `provenance.json` | Commit, immutable image/config/digest, версии и hashes |
| `summary.json` | Счётчики и статус валидации |

Публикация атомарна, после проверки schemas и ссылок. При ошибке любого этапа
рядом создаётся `<output>.diagnostics` со стадией, типом ошибки и уже полученными
каталогами. Повторная ошибка сохраняется отдельно в `.diagnostics-<suffix>`.
Сырые исключения, способные содержать credentials, не публикуются.
Выданные артефакты сохраняются, временные файлы Syft удаляются после задания. Docker cache у сервиса отсутствует.

Разделение определяется типом пакета/PURL (`deb`, `rpm`, `apk`, `alpm`, `portage`,
`nix`, `opkg`), а не именем вроде `openssl`. Например, Python-пакет с таким именем
не считается пакетом ОС. Это классификация по пакетной системе, не доказательство
того, что компонент является частью ядра ОС или не нужен приложению.
В разделённых документах удаляются ссылки между группами; они остаются в
`full.cdx.json`. Разные документы имеют разные serialNumber. API возвращает
`inventory_scope=non-os-packages-v1`, `final_count`, `os_count` и `full_count`.

С версии 0.3.1 `review.json` имеет `schema_version=2`. Прежние поля сохранены;
добавлены `group_counts`, `observation_counts`, а в элементах — `review_group`,
`observation`, `package_kinds`, `package_types`, `catalogers` и
`dependency_scope=not_established`. API возвращает `unknown_groups` в результате
задания. Наличие исходной декларации не превращается автоматически в признак
dev/runtime. Проверяющий скрипт продолжает читать историческую review schema 1.

| Группа проверки | UNKNOWN в сохранённой выборке 60 проектов |
|---|---:|
| CI-конфигурация | 554 |
| Декларации исходников | 1420 |
| Неоднозначная идентичность в исходниках | 43 |
| Расхождения версий | 72 |
| Неоднозначная идентичность в образе | 1 |
| Недостаточные свидетельства образа | 260 |
| Неподтверждённые файлы пакета | 10 |

[Проверка группировки](docs/verification-review-groups-v2.json): обработаны все
2360 UNKNOWN, без потерь и без изменения decisions/final SBOM. Это обогащение
отчётов сохранённого прогона, не новое измерение точности или новый scan.

В `final.cdx.json` остаются только принятые package-компоненты; файловые объекты
и сводный объект ОС из стандартной конвертации Syft остаются в raw evidence.
Новые SPDX identifiers вне закреплённого списка CDX1.6 сохраняются как названия
лицензий с исходным identifier в properties. Это сохраняет данные при строгой валидации.

Соответствие commit и image не считается доказанным только по паре входов:
`build_link=unverified`. Неизвестные dependency edges не выдумываются.
Удалённые слои образа не входят в scan (`squashed`).

В правилах v2 подтверждённая идентичность не переносит в итог записи той же версии
из lockfile. В `decisions.json` отдельно сохранены все наблюдения и
`selected_image_artifact_ids`. Неопределённость не маскируется удалением из отчёта.

## Проверка на 60 репозиториях (исторический полный состав 0.3.0)

[Сводная таблица](benchmarks/results/rules-v3-20260930/results.md) ·
[CSV](benchmarks/results/rules-v3-20260930/results.csv) ·
[JSON](benchmarks/results/rules-v3-20260930/results.json) ·
[Независимый аудит](benchmarks/results/rules-v3-20260930/audit-final.json) ·
[Точные commits](benchmarks/manifest.json).

Повторно просканированы те же 60 тестовых образов по правилам v3: по 10 Java, JavaScript, Python, Rust, Go и Ruby. 57 публичных проектов дополняют 3 существующих Python fixtures Bitbucket. Подготовка тестовых образов отделена от сервиса. Все результаты имеют partial coverage: 2360 UNKNOWN остаются в отчётах. Основной пакет подтверждён в 54 из 59 применимых случаев.

На отдельных размеченных контролях шести языков: **13 TP, 0 FP, 0 FN** против 12 TP, 4 FP, 1 FN до изменения. Это метрики 31 контрольной идентичности, не оценка полной точности 60 образов. [Подробности и сводка по языкам](docs/rules-v3.md).

В этом прогоне 12 449 идентичностей в контексте конкретного проекта:

| Наблюдение | Всего | INCLUDE | UNKNOWN |
|---|---:|---:|---:|
| Совпали исходники и образ | 1114 | 1114 | 0 |
| Только образ | 9246 | 8975 | 271 |
| Только исходники | 2089 | 0 | 2089 |

Это идентичности, а не 10 255 записей итоговых SBOM: одна идентичность может
соответствовать нескольким расположениям. Расхождения версий затронули 58 пар
«проект — пакет» и уже входят в таблицу.

## Готовность и следующие этапы

Сервис готов к тестовому использованию без LLM; промышленная полнота пока не
подтверждена. Работа продолжается последовательно на тестовых сборках:

1. Выполнено в 0.3.1: UNKNOWN разделены по области проверки — CI, декларации,
   версии, идентичность и файлы образа. Runtime/dev scope без доказательств не назначается.
2. Расширить контрольные сборки: shaded/fat JAR, JS bundles, Python egg-info/native
   wheels, Rust без auditable metadata, Go vendoring и Ruby native gems.
3. Независимо разметить весь состав части тестовых образов, включая транзитивные
   зависимости; измерить precision/recall и документировать слепые зоны.
4. Проверить большие образы, очередь, лимиты диска, таймауты, перезапуск worker и
   недоступность registry на отдельном тестовом стенде.
5. Когда появятся реальные сборки — провести пилот и проверить связь commit/image.

Анализ фактического выполнения кода — отдельная задача; текущая цель сервиса —
подтверждённый состав поставленного образа. Модель для этих этапов не требуется.

После выделения ОС следующий приоритет — связь оставшихся пакетов с проектом:
отличать совпадение с декларациями проекта, подтверждённую транзитивную зависимость
и пакет неизвестного происхождения из образа. Для утверждения «использован при
сборке» нужны свидетельства разрешения зависимостей/сборки. Исходники + образ сами
по себе не доказывают использование build-only зависимостей, которых нет в runtime.

CycloneDX определяет формат, а область инвентаризации выбирает генератор.
Например, [CycloneDX Maven plugin](https://cyclonedx.github.io/cyclonedx-maven-plugin/index.html)
описывает прямые и транзитивные зависимости проекта. Сам [формат CycloneDX](https://cyclonedx.org/specification/overview/)
не запрещает компоненты ОС, контейнеров или приложений.

## Совместное использование с Trivy

Trivy тоже обнаруживает пакеты ОС и языковые зависимости, поэтому инвентаризации
пересекаются. Кроме того, он ищет уязвимости с учётом своих источников advisories;
для пакетов ОС важен контекст дистрибутива. [Документация Trivy](https://trivy.dev/docs/latest/guide/scanner/vulnerability/).

SBOM Creator формирует инвентаризацию и не ищет CVE. Совпадения уязвимостей могут
появиться после анализа SBOM в Dependency-Track. Полное совпадение с Trivy не
измерялось и не гарантируется. Пакеты ОС сохраняются в полном SBOM.

При будущем объединении результатов рекомендуется сопоставлять immutable образ
и платформу, экосистему/namespace/имя/версию пакета, значимые qualifiers (для ОС —
дистрибутив и архитектуру), затем vulnerability ID и подтверждённые aliases.
Один CVE на разных пакетах или образах не является одним случаем. Исходные
идентификаторы, источники, severity и статусы исправления должны сохраняться.
Эта корреляция пока не реализована; складывать счётчики двух сканеров нельзя.

```bash
pytest -q
ruff check src tests
python benchmarks/run.py --help
```

Результаты 0.3.0 и границы точности: [rules-v3.md](docs/rules-v3.md). Предыдущая версия: [0.2.0](docs/rules-v2.md).
История проверок: [verification.md](docs/verification.md).
Тесты включают реальные Syft roundtrip при наличии бинарника, целостность CycloneDX,
фильтрацию зависимостей, невалидные model responses, auth/allowlists и блокировку
частичных результатов. Сведения о заимствованной основе: [THIRD_PARTY.md](THIRD_PARTY.md).

## Точность прямых зависимостей

[Стартовая оценка и сравнительная таблица топ-5](docs/direct-dependency-top5.md) · [Журнал экспериментов](docs/direct-dependency-experiments.md).

Подготовлены [сборочные CycloneDX SBOM для всех 60 проектов](docs/build-references-v1.md):
по 10 на язык, с закреплёнными коммитами, версиями генераторов, рецептами и хешами.
Для Ruby граф сохранён отдельно из Bundler/gemspec; для неупакованного lab-python
добавлена явно помеченная тестовая упаковка wheel. Эти инструменты запускаются
только во внешнем benchmark-окружении, не в рабочем сервисе.

Точность прямых зависимостей B0 ещё не пересчитана: новые разрешённые версии и профили
сборки нужно сопоставить с образами. 100% на 31 размеченном случае наличия компонентов
нельзя переносить на прямые зависимости или весь SBOM.

Syft output ограничен до разбора JSON: `SBOM_MAX_SBOM_BYTES` (по умолчанию64МиБ)
учитывает stdout+stderr одной команды. Превышение приводит к ошибке, не к
усечённому SBOM. Финальная проверка после завершения процесса закрывает гонку
с последней записью вывода. Это лимит байтов вывода, не RAM разобранного JSON.
[Проверки и ограничения R18](docs/syft-input-limit-r18.md).
