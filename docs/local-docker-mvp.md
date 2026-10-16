# Локальный MVP в Docker

Стенд этой рабочей копии запущен отдельным Compose project `sbom-mvp-local`.
API: **http://127.0.0.1:18082**, OpenAPI UI: **http://127.0.0.1:18082/docs**.
Он слушает только loopback. Другие Docker-сервисы не изменялись.

Токен создан в `secrets/local-mvp/api-token`, не опубликован в Git и не выводится
клиентом. Пример ниже читает его из файла. Успешное задание может быть `partial`:
проверяйте `summary.json`, `coverage.json` и `review.json`, а не только HTTP status.
UNKNOWN означает ограничение подтверждения, не доказанное отсутствие компонента.

## Получить SBOM

Из PowerShell в `G:\code\sbom_creator`:

```powershell
# JavaScript: готовый образ без lockfile из локального HTTPS registry.
.venv/Scripts/python.exe scripts/local_api_client.py analyze `
  --image registry:5000/javascript-nest@sha256:ffd4aad3d668998f13d90a8f3811b545eafc646dd362db66f1a3001f810558d1 `
  --output workspace/my-first-sbom
```

Для Java:

```powershell
.venv/Scripts/python.exe scripts/local_api_client.py analyze `
  --image registry:5000/java-rest@sha256:eab8bc01e585ac49b6af53f520e2489e9209e70b7a59502e301a2592010f56be `
  --output workspace/my-java-sbom
```

Каждый `--output` должен быть новым. Клиент отправляет одно image-only production
задание, ждёт terminal status и скачивает все объявленные артефакты с SHA256 receipt
в `client-report.json`. Источники, commit и reference не требуются.

- `final.cdx.json` — подтверждённые компоненты вне пакетной системы ОС.
- `os.cdx.json` — пакеты ОС.
- `full.cdx.json` — полный подтверждённый состав.
- Raw inventories, provenance, решения и UNKNOWN также сохраняются.

Для прямого API-запроса:

```powershell
$apiToken = (Get-Content -Raw secrets/local-mvp/api-token).Trim()
$headers = @{ Authorization = "Bearer $apiToken" }
$body = @{ image = 'registry:5000/java-rest@sha256:eab8bc01e585ac49b6af53f520e2489e9209e70b7a59502e301a2592010f56be' } | ConvertTo-Json
$job = Invoke-RestMethod http://127.0.0.1:18082/v1/analyses -Method Post -Headers $headers -ContentType application/json -Body $body
Invoke-RestMethod "http://127.0.0.1:18082/v1/analyses/$($job.id)" -Headers $headers
# После status=succeeded:
Invoke-WebRequest "http://127.0.0.1:18082/v1/analyses/$($job.id)/artifacts/final.cdx.json" -Headers $headers -OutFile workspace/downloaded-final.cdx.json
```

В `/docs` передайте полное `Bearer <token>` в поле `authorization` операции.
Не вставляйте токен в URL. `/health` — только liveness, не scanner readiness.

## Свой образ

Замените `--image` на точный `registry/namespace/application@sha256:…`. В локальной
конфигурации разрешены `registry:5000`, `ghcr.io`, `docker.io`, `registry-1.docker.io`.
Для собственного registry добавьте точный `host[:port]` в `SBOM_REGISTRY_HOSTS`
файла `.env.local-mvp` и примените `compose up` ниже.

Для закрытого registry сохраните пароль в
`secrets/local-mvp/credentials/registry-password`; задайте в `.env.local-mvp`
`SBOM_REGISTRY_USERNAME` и `SBOM_REGISTRY_PASSWORD_FILE=/run/credentials/registry-password`.
Оба значения обязательны вместе. Используйте отдельную конфигурацию с allowlist
этого registry для его credentials. Секреты и Docker socket не передаются заданиям.
Для корпоративного CA добавьте сертификат в локальный trust bundle осознанно;
TLS verification не отключается.

## Управление стендом

```powershell
docker compose --env-file .env.local-mvp -f compose.local.yaml ps
docker compose --env-file .env.local-mvp -f compose.local.yaml logs --tail 50 api
docker compose --env-file .env.local-mvp -f compose.local.yaml stop
docker compose --env-file .env.local-mvp -f compose.local.yaml up -d
```

Образ API закреплён по локальному imageID в `.env.local-mvp`. Том
`sbom-mvp-local-workspace` хранит jobs, результаты и отдельную проверенную копию
публичной Java DB; `sbom-mvp-local-registry` — два демонстрационных образа.
Тома external: обычный Compose lifecycle их не удаляет. Raw downloads также
сохранены в `workspace/local-mvp`. Не удаляйте тома ради повторного запроса.

Сервис работает как UID10001 с read-only root, без capabilities/socket, workers1,
3GiB/2CPU. Локальный registry использует отдельный CA; host trust store не менялся.
CA private key не смонтирован в сервис, API получает только public trust bundle
и свой token file. Registry доступен с host лишь на127.0.0.1:18500, без credentials:
он предназначен для этих публичных тестовых образов, не для приватных production images.

Первоначальная подготовка и публикация демонстрационных immutable образов
выполнялись локальными R&D-сценариями. Они остаются на этой машине и не входят
в продуктовый репозиторий. Для новой установки используйте обычный Docker Compose
запуск из README; Java cache будет подготовлен сервисом при первом анализе.
Исходный public cache и завершённые reference pairs не изменялись; новые сборки
Petclinic/Nest не выполнялись. Локальный server certificate действует90дней:
затем его нужно перевыпустить перед новыми registry-запросами.

Присутствие компонента не доказывает исполнение или прямую зависимость. Полнота
opaque/shaded code не гарантируется; исходный граф — отдельное optional обогащение.
Память, диск и параллельность production-нагрузки требуют отдельной оценки.
