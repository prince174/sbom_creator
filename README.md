# SBOM Creator

Python-сервис получает **Bitbucket HTTPS URL + полный commit SHA + container image**,
сам получает исходники и образ, запускает **Syft 1.51.1** для обоих входов,
сопоставляет **Syft JSON 16.1.10** и выдаёт **CycloneDX JSON 1.6**.
Основной режим API и CLI — детерминированные правила, без LLM и модельных ключей.
Загрузку в Dependency-Track выполняет пользователь.

Основа — подход `SCA_accuracy_improvement`: точные входы, evidence и проверяемые
решения по каждому компоненту. Этот проект не меняет исходный сервис.

Схемы: [draw.io](docs/system-workflow.drawio),
[интерактивный HTML](docs/system-workflow.html), [архитектура](docs/architecture.md).

## Решение по компоненту

Сравнивается объединение кандидатов двух SBOM. Нормализованный PURL сохраняет
экосистему, namespace, точную версию и qualifiers. Версии не объединяются.
Fallback без PURL требует точной идентичности; fuzzy match не разрешает включение.

| Ситуация | Результат |
|---|---|
| Точная идентичность в пакетной, архивной или бинарной metadata образа | INCLUDE |
| Только исходники, скопированный lockfile, неоднозначная идентичность, недостающие evidence | UNKNOWN |
| Сбой получения входов, сканера, конвертации или schema | Задание failed, final недоступен |

Пакеты ОС и image-only зависимости тоже рассматриваются. Наличие metadata не
доказывает выполнение кода. Вероятности и оценки TP в режиме правил не назначаются.
Исходные source/image SBOM сохраняются. UNKNOWN делает результат частичным.
Неполученные submodules/LFS отражаются в coverage. Сборка приложения, установка
пакетов и запуск контейнера в production-пути не выполняются.

## Linux / Docker

Worker: Linux amd64, Docker Engine **28+** (нужен `image save --platform`),
доступ к Bitbucket и registry. Образ сервиса содержит Git,
Docker CLI 29.8.0 и закреплённый Syft. Docker socket требует выделенного доверенного worker.
Сервис запускается одним процессом; несколько независимых экземпляров не должны делить workspace.

```bash
cp .env.example .env
mkdir -p secrets workspace
# Заполните .env, положите токены в secrets/* согласно *_FILE.
docker compose up --build -d
```

Порт: `127.0.0.1:18082`. Для доступа извне используйте HTTPS reverse proxy.
`/health` подтверждает работу API, но не готовность Git/registry.

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
| `SBOM_IMAGE_PLATFORM` | Default `linux/amd64` |
| `SBOM_WORKERS` | 1–4, default 1; очередь ограничена 16 заданиями |
| `SBOM_SYFT_BINARY` | Путь к Syft, default `syft` |

Секреты не включаются в argv, provenance и сообщения об ошибках.
Git redirects, hooks, inherited Git configs, автоматические submodules/LFS и
конфигурация Syft из репозитория отключены.

## API

`POST /v1/analyses`, `Authorization: Bearer <token>`:

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

# Локальный checkout, тот же режим правил:
sbom-creator analyze-local --source ./checkout --image registry.example.com/app:build-123 \
  --output workspace/result-rules --mode rules
```

`SBOM_PULL_IMAGE=false` допустим для явного CLI benchmark с заранее собранным
образом и allowlisted reference; HTTP API такую конфигурацию отвергает.
Существующий output не перезаписывается. На Windows используется `.venv\Scripts\python`;
для локальной проверки Syft сохранён в `.tools/syft/syft.exe` (не включается в Git).

## Результаты

| Файл | Содержание |
|---|---|
| `final.cdx.json` | Проверенный CycloneDX 1.6 для ручной загрузки |
| `source.syft.json`, `image.syft.json` | Полные исходные каталоги |
| `selected.syft.json` | Отобранные записи образа с целостными ссылками |
| `decisions.json` | Все INCLUDE/EXCLUDE/UNKNOWN с evidence и причинами |
| `coverage.json` | Catalogers, ограничения, неполнота и счётчики причин UNKNOWN |
| `review.json` | Компактный список UNKNOWN: идентичность, причина и следующий шаг проверки |
| `provenance.json` | Commit, immutable image/config/digest, версии и hashes |
| `summary.json` | Счётчики и статус валидации |

Публикация атомарна, после проверки schemas и ссылок. При ошибке любого этапа
рядом создаётся `<output>.diagnostics` со стадией, типом ошибки и уже полученными
каталогами. Повторная ошибка сохраняется отдельно в `.diagnostics-<suffix>`.
Сырые исключения, способные содержать credentials, не публикуются.
Артефакты и Docker cache не удаляются автоматически.

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

## Проверка на 60 репозиториях

[Сводная таблица](benchmarks/results/rules-v2-20260930/results.md) ·
[CSV](benchmarks/results/rules-v2-20260930/results.csv) ·
[JSON](benchmarks/results/rules-v2-20260930/results.json) ·
[Независимый аудит](benchmarks/results/rules-v2-20260930/audit-final.json) ·
[Точные commits](benchmarks/manifest.json).

Повторно обработаны сохранённые сканы всех 60 проектов по правилам v2: по 10 Java, JavaScript, Python, Rust,
Go и Ruby. Независимый аудит подтвердил schemas, hashes, provenance и решения
для 60/60 результатов без ошибок. 57 публичных проектов дополняют 3 существующих
Python fixtures Bitbucket. Подготовка тестовых образов отделена от сервиса.

Все результаты имеют `partial` coverage: 2360 UNKNOWN-идентичностей исключены
из итоговых SBOM. Точная release-идентичность основного пакета подтверждена в
54 из 59 применимых случаев; ограничения Go описаны в [методике](benchmarks/README.md).
Модель для рабочего сценария не нужна. Режим rules не измеряет качество LLM. FP/FN требуют независимой разметки и не подменяются числом удалённых пакетов.

```bash
pytest -q
ruff check src tests
python benchmarks/run.py --help
```

Результаты 0.2.0, контрольный образ и границы точности: [rules-v2.md](docs/rules-v2.md).
История проверок: [verification.md](docs/verification.md).
Тесты включают реальные Syft roundtrip при наличии бинарника, целостность CycloneDX,
фильтрацию зависимостей, невалидные model responses, auth/allowlists и блокировку
частичных результатов. Сведения о заимствованной основе: [THIRD_PARTY.md](THIRD_PARTY.md).
