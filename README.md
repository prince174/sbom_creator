# SBOM Creator

Python-сервис получает **Bitbucket HTTPS URL + полный commit SHA + container image**,
сам получает исходники и образ, запускает **Syft 1.51.1** для обоих входов,
сопоставляет **Syft JSON 16.1.10** и выдаёт **CycloneDX JSON 1.6**.
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
| Подтверждённая идентичность в образе + валидная оценка модели >70 | INCLUDE |
| Достаточные cited image evidence + оценка ≤70 | EXCLUDE по политике |
| Только исходники, скопированный lockfile, неоднозначная идентичность, недостающие evidence | UNKNOWN |
| Неполный ответ, неизвестный evidence ID, нечисловая оценка, сбой модели/сканера/schema | Задание failed, final недоступен |

Пакеты ОС и image-only зависимости тоже рассматриваются. Наличие metadata не
доказывает выполнение кода; оценка модели не является калиброванной вероятностью.
Исходные source/image SBOM сохраняются. UNKNOWN делает результат частичным.
Неполученные submodules/LFS отражаются в coverage. Сборка приложения, установка
пакетов и запуск контейнера в production-пути не выполняются.

## Linux / Docker

Worker: Linux amd64, Docker Engine **28+** (нужен `image save --platform`),
доступ к Bitbucket, registry и настроенной модели. Образ сервиса содержит Git,
Docker CLI 29.8.0 и закреплённый Syft. Docker socket требует выделенного доверенного worker.
Сервис запускается одним процессом; несколько независимых экземпляров не должны делить workspace.

```bash
cp .env.example .env
mkdir -p secrets workspace
# Заполните .env, положите токены в secrets/* согласно *_FILE.
docker compose up --build -d
```

Порт: `127.0.0.1:18082`. Для доступа извне используйте HTTPS reverse proxy.
`/health` подтверждает работу API, но не готовность Git/registry/модели.

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
| `SBOM_LLM_BASE_URL`, `SBOM_LLM_MODEL` | Обязательная явная настройка OpenAI-compatible модели |
| `SBOM_LLM_API_KEY` / `_FILE` | Ключ новой модели; старый проект автоматически не используется |
| `SBOM_LLM_TIMEOUT_SECONDS` | Timeout, default 120 |
| `SBOM_WORKERS` | 1–4, default 1; очередь ограничена 16 заданиями |
| `SBOM_SYFT_BINARY` | Путь к Syft, default `syft` |

Внешняя модель требует HTTPS. Loopback HTTP разрешён для локального сервера.
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

API использует модель. Режим правил доступен только явно через CLI для сравнения
и проверки инфраструктуры; переключения на него при ошибке LLM нет.

## CLI и локальная разработка

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
# Экспортируйте SBOM_* настройки в окружение; CLI не читает .env автоматически.
sbom-creator analyze --repository-url https://bitbucket.org/workspace/app.git \
  --commit FULL_SHA --image registry.example.com/app:build-123 --output workspace/result-1

# Явный benchmark-путь, без LLM-оценки:
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
| `coverage.json` | Catalogers, ограничения и неполнота |
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

## Проверка на 60 репозиториях

[Сводная таблица](benchmarks/results/run-20260929/results.md) ·
[CSV](benchmarks/results/run-20260929/results.csv) ·
[JSON](benchmarks/results/run-20260929/results.json) ·
[Независимый аудит](benchmarks/results/run-20260929/audit-final.json) ·
[Точные commits](benchmarks/manifest.json).

Завершены все 60 проверок в режиме `rules`: по 10 Java, JavaScript, Python, Rust,
Go и Ruby. Независимый аудит подтвердил schemas, hashes, provenance и решения
для 60/60 результатов без ошибок. 57 публичных проектов дополняют 3 существующих
Python fixtures Bitbucket. Подготовка тестовых образов отделена от сервиса.

Все результаты имеют `partial` coverage: 2360 UNKNOWN-идентичностей исключены
из итоговых SBOM. Точная release-идентичность основного пакета подтверждена в
54 из 59 применимых случаев; ограничения Go описаны в [методике](benchmarks/README.md).
Модельный прогон ждёт отдельной модели пользователя. Режим rules не измеряет
качество LLM. FP/FN требуют независимой разметки и не подменяются числом удалённых пакетов.

```bash
pytest -q
ruff check src tests
python benchmarks/run.py --help
```

Результаты проверок и команды повторения: [verification.md](docs/verification.md).
Тесты включают реальные Syft roundtrip при наличии бинарника, целостность CycloneDX,
фильтрацию зависимостей, невалидные model responses, auth/allowlists и блокировку
частичных результатов. Сведения о заимствованной основе: [THIRD_PARTY.md](THIRD_PARTY.md).
