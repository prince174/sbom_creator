# SBOM по репозиторию до появления образа

Source-first API выдаёт самостоятельный `source.cdx.json` по HTTPS-репозиторию
и полному commit SHA. Для этого образ приложения не нужен. Если указан будущий
tag образа, сервис отдельно отслеживает его появление, фиксирует доступный digest
и запускает обычный image-анализ. Можно передать образ
позже отдельным запросом.

Это два разных результата:

- Source SBOM описывает зависимости, разрешённые cdxgen в доступной среде
  Maven/Gradle/npm. Рецепт и профили неизвестной оригинальной CI-сборки он не
  подтверждает. Выполнение build tooling может потребоваться; результат не
  гарантирован для произвольного репозитория.
- Image SBOM подтверждает компоненты фактически полученного образа. Ошибка
  source-анализа не заменяет независимый image-only API
  `POST /v1/analyses`. Ошибка или отсутствие образа не отзывают уже опубликованный
  source SBOM.

Результат сравнения показывает пересечение и различия составов. Отсутствие
source-компонента в runtime-образе само по себе не доказывает ошибку: зависимость
могла участвовать только в сборке. Наличие компонента в образе не доказывает его
прямоту или исполнение.

## Запуск локального coordinator

Предполагается, что [локальный Docker MVP](local-docker-mvp.md) уже настроен:
созданы token, trust, рабочий volume и `.env.local-mvp`. Source-first включается
отдельным compose override. Основной image-only compose не получает Docker socket.

Trusted API coordinator получает доступ к Docker daemon, чтобы создавать
изолированные source jobs. Такой доступ даёт coordinator полномочия Docker daemon;
`:ro` у socket mount не делает Docker API доступным только для чтения. Не
публикуйте API без аутентификации и не передавайте daemon socket проектным jobs.

Worker запускается от UID/GID `65532`, с read-only root filesystem, без
capabilities, с ограничением CPU/RAM/PID и writable `/tmp`. Репозиторий поступает
через tar в stdin. Worker не получает socket, сервисные credentials, workspace API
или reference/build caches. Для загрузки зависимостей worker использует сеть;
этот режим не является network-none или egress allowlist.

Соберите worker по инструкции Dockerfile ниже. Затем закрепите его по image ID
для текущего запуска:

```powershell
docker build -f Dockerfile.cdxgen-worker -t sbom-creator-cdxgen-worker:13.4.0 .
docker build -t sbom-creator:source-first .
$env:SBOM_LOCAL_SERVICE_IMAGE = 'sbom-creator:source-first'
$env:SBOM_CDXGEN_IMAGE = docker image inspect sbom-creator-cdxgen-worker:13.4.0 --format '{{.Id}}'
$env:SBOM_BITBUCKET_HOSTS = 'github.com,bitbucket.org'
$env:SBOM_DOCKER_SOCKET_GID = '0'
docker compose --env-file .env.local-mvp -f compose.local.yaml -f compose.source.yaml up -d api
```

Проверенный ранее локальный worker имел ID
`sha256:11e944f4291e284eca333b829e840ce8fac56613744880aff87a9a730fe0d36a`
и cdxgen `13.4.0`, Node `24.22.0`, Maven `3.9.16`, Java `17`. Новая сборка может
иметь другой image ID: используйте фактически собранный ID. Без override переменной
compose использует tag `sbom-creator-cdxgen-worker:13.4.0`; перед каждым job сервис
разрешает выбранный локальный образ в immutable image ID и сохраняет его в
provenance. Образ worker должен быть доступен локально: jobs используют
`--pull=never`.

Значение GID `0` проверено для локального Docker Desktop socket
`0660 root:root`. На другом Docker host задайте его фактический GID, полученный
через `stat -c %g /var/run/docker.sock` на этом host. API остаётся UID `10001`,
добавляется только supplementary group. Не переносите значение `0` на другой host
без проверки.

Параметры override:

| Переменная | По умолчанию | Назначение |
|---|---:|---|
| `SBOM_BUILD_TIMEOUT` | `900` | Максимальное время одного source worker, секунд |
| `SBOM_SOURCE_IMAGE_WAIT_TIMEOUT` | `3600` | Ограниченное ожидание назначенного образа, секунд |
| `SBOM_SOURCE_IMAGE_POLL_INTERVAL` | `30` | Интервал проверки готовности образа, секунд |
| `SBOM_SOURCE_IMAGE_PROBE_TIMEOUT` | `15` | Тайм-аут отдельной проверки registry, секунд |
| `SBOM_WORKERS` | `1` | Один worker image pipeline; source executor также имеет один worker |

Repository hosts разрешаются через `SBOM_BITBUCKET_HOSTS` (историческое имя
настройки применяется также к GitHub), registry hosts — через
`SBOM_REGISTRY_HOSTS`. URL не должен содержать credentials, query или fragment;
commit должен содержать все 40 или 64 hex-символа. Credentials для private
checkout остаются в coordinator и не передаются build job.

## Создать source-анализ

Пример для PowerShell не печатает API token:

```powershell
$base = 'http://127.0.0.1:18082'
$token = (Get-Content -LiteralPath secrets/local-mvp/api-token -Raw).Trim()
$headers = @{ Authorization = "Bearer $token" }
$output = Join-Path $PWD 'workspace/source-first-example'
New-Item -ItemType Directory -Path $output -Force | Out-Null
$body = @{
    repository_url = 'https://github.com/expressjs/express.git'
    commit = '1faf228935aa0a13111f92c28ee795be64ce3f0f'
} | ConvertTo-Json
$job = Invoke-RestMethod -Uri "$base/v1/source-analyses" -Method Post -Headers $headers -ContentType 'application/json' -Body $body
$job
```

Ответ `202` содержит `id` и `status_url`. Проверяйте состояние через
`GET /v1/source-analyses/{id}`. Фазы показываются раздельно:

| Поле | Состояния |
|---|---|
| `source_status` | `queued`, `running`, `succeeded`, `failed` |
| `image_status` | `not_requested`, `waiting`, `running`, `succeeded`, `failed` |
| `comparison_status` | `not_ready`, `running`, `succeeded`, `failed`, `skipped` |

Source SBOM доступен при `source_status: succeeded`, даже если image-фаза ещё
ожидает образ или завершилась ошибкой. Общее поле `status` не заменяет состояния
этих независимых фаз.

```powershell
$status = Invoke-RestMethod -Uri "$base/v1/source-analyses/$($job.id)" -Headers $headers
$status
Invoke-WebRequest -Uri "$base/v1/source-analyses/$($job.id)/artifacts/source.cdx.json" -Headers $headers -OutFile (Join-Path $output 'source.cdx.json')
Invoke-WebRequest -Uri "$base/v1/source-analyses/$($job.id)/artifacts/source-provenance.json" -Headers $headers -OutFile (Join-Path $output 'source-provenance.json')
Invoke-WebRequest -Uri "$base/v1/source-analyses/$($job.id)/artifacts/source-summary.json" -Headers $headers -OutFile (Join-Path $output 'source-summary.json')
```

До публикации source-артефактов download возвращает `409`.
`source-summary.json` явно сохраняет scope source model,
`original_build_reproduced: false` и `image_presence_verified: false`;
provenance связывает commit, source tar, SBOM SHA256 и engine image ID.
Source-first запрос не принимает reference SBOM или caller proof.

## Образ ещё не готов

Поле `image` можно добавить в исходный source-first запрос:

```json
{
  "repository_url": "https://github.com/expressjs/express.git",
  "commit": "1faf228935aa0a13111f92c28ee795be64ce3f0f",
  "image": "registry.example.com/team/app:pending-build"
}
```

Registry должен быть разрешён в настройках. Source-анализ не ждёт появления этого
tag для публикации своего результата. Поле `image` в status сохраняет
`attempt`, `requested_image`, `deadline_utc` и `next_probe_utc`.
Ожидание registry ограничено настройками;
это не бесконечный retry. Когда образ найден, сервис фиксирует digest и создаёт
отдельный image job. Последующее перемещение tag не должно менять уже назначенный
анализируемый digest.

Если ожидание истекло или образ назначается позднее, используйте attach:

```powershell
$imageBody = @{ image = 'registry.example.com/team/app@sha256:REPLACE_WITH_64_HEX_DIGEST' } | ConvertTo-Json
Invoke-RestMethod -Uri "$base/v1/source-analyses/$($job.id)/image" -Method Post -Headers $headers -ContentType 'application/json' -Body $imageBody
```

Замените placeholder настоящим digest. Attach также принимает явный tag.
Повторное назначение после завершившегося неуспешного ожидания не пересобирает
source SBOM. Следите за отдельным image status; одновременные назначения не должны
запускать дублирующий анализ.

## Image SBOM и сравнение

Source status содержит `image.job_id` и `image.status_url` созданного image job.
Его состояние и
артефакты доступны через обычный image API:

```powershell
$status = Invoke-RestMethod -Uri "$base/v1/source-analyses/$($job.id)" -Headers $headers
$imageJobId = $status.image.job_id
Invoke-RestMethod -Uri "$base/v1/analyses/$imageJobId" -Headers $headers
Invoke-WebRequest -Uri "$base/v1/analyses/$imageJobId/artifacts/final.cdx.json" -Headers $headers -OutFile (Join-Path $output 'image-final.cdx.json')
Invoke-WebRequest -Uri "$base/v1/analyses/$imageJobId/artifacts/os.cdx.json" -Headers $headers -OutFile (Join-Path $output 'image-os.cdx.json')
Invoke-WebRequest -Uri "$base/v1/analyses/$imageJobId/artifacts/full.cdx.json" -Headers $headers -OutFile (Join-Path $output 'image-full.cdx.json')
Invoke-RestMethod -Uri "$base/v1/source-analyses/$($job.id)/comparison" -Headers $headers
```

Активный image attempt нельзя назначить повторно: attach вернёт `409`. После
терминального результата можно назначить новый attempt; старые source-артефакты и
файлы предыдущих image attempts сохраняются. При рестарте сервиса выполнявшийся
source job не пересобирается автоматически и отмечается как interrupted; уже
опубликованный source SBOM сохраняется.

Comparison появляется только после успешной публикации обоих SBOM, иначе endpoint
возвращает `409`. Сопоставление использует точные Maven/npm PURL, включая version,
qualifiers и subpath, из source SBOM и image `full.cdx.json`; другие ecosystems и
неразрешённые identity учитываются отдельно. Это agreement составов, а не
precision/recall по внешнему эталону. Платформенные npm-компоненты из полного
image inventory не скрываются. Ошибки
checkout, cdxgen, registry или image-анализа показываются отдельно; они не являются
доказательством отсутствия зависимостей. Source SBOM и image SBOM сохраняют разные
scope и provenance. Прямые/транзитивные связи source-модели не подставляются в image
SBOM как доказанные связи оригинальной CI-сборки.

Дополнительная `coordinate_agreement` показывает совпадения по ecosystem,
namespace, name и точной version. Это отдельная проекция: qualifiers и subpath
не становятся доказанно одинаковыми. Полные исходные PURL обеих сторон сохраняются
в деталях вариантов, а строгое сравнение остаётся рядом. Например, Maven PURL
с `?type=jar` и без него совпадут по координатам, но останутся различными в строгом
сравнении. Такое различие не является автоматическим доказательством ошибки SBOM.

R&D, локальные результаты прогонов и test reports хранятся вне Git; product-код,
проверки и инструкции остаются в репозитории.
