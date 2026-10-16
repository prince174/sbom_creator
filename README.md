# SBOM Creator

Сервис формирует CycloneDX JSON 1.6 по фактическому содержимому container image.
Основной вход — образ по digest; repository URL и полный commit необязательны и
передаются вместе. Источники дополняют сведения о зависимостях, но не подтверждают
присутствие компонента в образе. Неизвестный рецепт CI не блокирует image-only анализ.

Image pipeline использует закреплённые Syft1.51.1, Trivy0.75.0 и Crane0.22.1.
Сервис связывает manifest/config/layer identities, проверяет файловые свидетельства
и сохраняет UNKNOWN для неподтверждённых или неоднозначных записей. Java-режим по
умолчанию отдельно подтверждает полные поставленные JAR, включая metadata-only.
Присутствие не доказывает исполнение, directness или подлинность издателя.

## Локальный стенд

Запущенный Docker API: http://127.0.0.1:18082, OpenAPI UI: http://127.0.0.1:18082/docs.
Токен хранится в ignored `secrets/local-mvp/api-token` и не передаётся в URL.
[Готовые запросы и управление локальным стендом](docs/local-docker-mvp.md).

```powershell
.venv/Scripts/python.exe scripts/local_api_client.py analyze `
  --image registry.example.com/team/app@sha256:FULL_DIGEST `
  --output workspace/my-sbom
```

Клиент читает token file, отправляет одно задание, ожидает результат и скачивает
все доступные артефакты. Каждый output должен быть новым. Проверяйте `partial`,
`coverage.json` и `review.json`: succeeded не означает отсутствие UNKNOWN.

## Запуск в Docker

```sh
cp .env.example .env
mkdir -p secrets workspace
# Задайте случайный API token в secrets/api-token; не коммитьте файл.
# Настройте точные SBOM_REGISTRY_HOSTS и необходимые credentials.
# На Linux workspace должен быть доступен UID/GID10001.
docker compose up --build -d
```

Compose публикует только127.0.0.1:18082. Сервис работает как UID10001 с read-only root,
без capabilities; default workers1, 3GiB/2CPU. Docker socket для image-only pipeline
не требуется. Для доступа извне нужен HTTPS reverse proxy. `/health` проверяет
liveness, а не готовность registry/scanners. [Kubernetes example](deploy/kubernetes.yaml)
предназначен для адаптации оператором, не является подтверждением cluster capacity.

## API

Все операции анализа требуют `Authorization: Bearer <token>`.

`POST /v1/analyses`:

```json
{"image":"registry.example.com/team/app@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
```

Ответ202 содержит `id` и `status_url`. Poll `GET /v1/analyses/{id}` до `succeeded`
или `failed`. После успеха `GET /v1/analyses/{id}/artifacts/final.cdx.json` выдаёт SBOM.
До успеха download заблокирован409; неподдержанные имена возвращают404. Незавершённые
задания после restart помечаются failed, автоматически не повторяются.

Для необязательного source enrichment добавьте `repository_url` и `commit`
(полный40/64-character SHA) одновременно. Repository требует HTTPS на настроенном
host; credentials внутри URL запрещены. API всегда использует детерминированные
правила. Экспериментальный CLI LLM режим включается только явно и не является
частью обычного сервиса.

[Verification с reference SBOM](docs/verification-mode.md) выполняет сравнение
после генерации. Production reference не принимает. Reference никогда не является
входом классификатора.

## Результаты

| Артефакт | Содержание |
|---|---|
| `final.cdx.json` | Подтверждённые компоненты вне пакетной системы ОС |
| `os.cdx.json` | Подтверждённые пакеты ОС |
| `full.cdx.json` | Полный подтверждённый состав и межгрупповые связи |
| `source.syft.json`, `image.syft.json`, `selected.syft.json` | Исходные и отобранный inventories |
| `decisions.json`, `coverage.json`, `review.json` | Решения, ограничения, UNKNOWN и следующие проверки |
| `provenance.json`, `summary.json` | Commit/image identity, tools, hashes, counts и status |
| `direct-dependencies.json`, `java-direct-dependencies.json` | Доказанные декларации и отдельные UNKNOWN; не обещание полного графа |
| `image-original.syft.json`, `image-peer.cdx.json`, `image-identity-audit.json` | При Java-анализе original Syft, Trivy и identity/archive audits |

Идентичность сравнивается по экосистеме, namespace, точной версии и qualifiers;
fuzzy matching и выбор версии по эталону не применяются. Source-only запись не
добавляется в image SBOM. Inventory включает поставленные package-like fixtures и
инструменты; их принадлежность проекту не определяется одним именем. Node/npm
platform и ОС требуют отдельной области оценки.

Публикация выполняется атомарно после schema/reference-link checks. Ошибки не
маскируются пустым успешным SBOM; дополнительные Java failures сохраняют raw
inventory и делают подтверждение partial. [Ошибки публикации](docs/publication.md),
[диагностика API](docs/api-debugging.md).

## Конфигурация

| Переменная | Назначение |
|---|---|
| `SBOM_API_TOKEN` / `_FILE` | Bearer token API; без настройки API возвращает503 |
| `SBOM_REGISTRY_HOSTS` | Точные разрешённые registry hosts, включая port |
| `SBOM_REGISTRY_USERNAME`, `SBOM_REGISTRY_PASSWORD` / `_FILE` | Оба credentials вместе либо оба отсутствуют |
| `SBOM_BITBUCKET_HOSTS` | Точные разрешённые repository hosts |
| `SBOM_BITBUCKET_TOKEN` / `_FILE`, `SBOM_BITBUCKET_AUTH_MODE` | Git credentials и basic/bearer |
| `SBOM_CA_BUNDLE` | Git HTTPS CA bundle |
| `SSL_CERT_FILE` | Trust bundle scanner/Crane для registry TLS |
| `SBOM_WORKSPACE` | Persistent writable job/results directory |
| `SBOM_TRIVY_CACHE_DIR` | Public Java DB cache |
| `SBOM_IMAGE_TEMP_DIR` | Временные внутренние архивы и нормализованные слои |
| `SBOM_IMAGE_PLATFORM` | Default linux/amd64 |
| `SBOM_WORKERS` | Default1; независимые экземпляры не делят workspace |
| `SBOM_JAVA_ARCHIVE_COMPONENTS` | Default true: verified complete archive presence |
| `SBOM_JAVA_NESTED_WINDOWS` | При archive=false выбирает nested reader; default false |
| `SBOM_JAVA_IMAGE_EVIDENCE` | Default true; ошибка подтверждения отражается UNKNOWN |
| `SBOM_JAVA_BACKEND` | Optional source graph: disabled(default), trivy, cdxgen |
| `SBOM_CDXGEN_IMAGE`, `SBOM_DOCKER_BINARY`, `SBOM_BUILD_TIMEOUT` | Доверенный worker/coordinator и build timeout |

Первый Java-анализ может загрузить около1.5GiB публичной DB. Missing cache загружается
в private stage и валидируется до atomic publication. Invalid existing cache
сохраняется и требует явного operator recovery; stale valid cache используется без
hidden refresh. [Настройка и восстановление Java cache](docs/java-db-cache.md).

Scratch scanners направляется в `/workspace` через TMPDIR/TMP/TEMP. Reader имеет
отдельные8GiB normalization и8GiB hash-verification budgets,32MiB/read и128MiB
payload windows, а также ограничения TAR/ZIP metadata, depth и inflate ratio.
Это логические ограничения, не доказательство hard disk quota, peak RSS или
безопасной конкурентной нагрузки. Начинайте с одного worker и задайте retention.

## CLI и разработка

```sh
python -m venv .venv
# Активируйте venv, затем:
pip install -e '.[dev]'
sbom-creator analyze --image registry.example.com/app@sha256:FULL_DIGEST --output workspace/result
pytest
ruff check src tests scripts
```

CLI не читает `.env` автоматически. `analyze-local --source PATH` предназначен для
явного checkout; `SBOM_IMAGE_ARCHIVE` — offline CLI, HTTP API его отвергает.
Неизвестные profiles/owners/scopes и opaque/shaded код остаются ограничениями,
а доступная модель зависимостей не выдаётся за точную модель неизвестной TeamCity CI.

[Архитектура](docs/architecture.md), [правила разработки и Git](docs/development.md).
В Git находятся product source, tests и эксплуатационные документы. Benchmarks,
корпуса, эталоны, R&D notes, generated SBOMs, тестовые отчёты и результаты хранятся
локально в ignored directories.
