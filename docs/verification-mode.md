# Production и verification

Production принимает image и необязательную пару repository_url+commit. Reference
не требуется и не принимается. Обычный image-only запрос не ожидает пересборки проекта.

Verification сначала выполняет тот же анализ, затем отдельный evaluator читает
готовые final.cdx.json и direct-dependencies.json и формирует evaluation.json.
Reference никогда не передаётся сканеру, identity rules или payload gate.
Поддерживается CycloneDX1.6 до8MiB serialized JSON; заявленная runtime scope нужна
для метрик. Неизвестные owner/profile/scope остаются UNKNOWN.

```json
{
  "image": "registry.example.com/team/app@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "run_mode": "verification",
  "reference_scope": "runtime",
  "reference_sbom": {"bomFormat":"CycloneDX","specVersion":"1.6","version":1}
}
```

Минимальный reference выше показывает расположение поля; для содержательного
сравнения передайте полный валидный build SBOM с root и dependency graph.
Caller assertion о commit/build identity не является проверенной attestation.
Разные build/runtime/platform scopes требуют отдельной оценки.

Метрики содержат TP/FP/FN, precision/recall/F1, версии, counts и UNKNOWN. Известный
reference компонент с UNKNOWN считается FN. Пустые/неподдержанные выборки не дают
100% точности. Равенство counts не означает совпадение имён/версий. Direct edges
оцениваются отдельно: inventory и ownership не превращаются в зависимости библиотек.

Генератор сравнения не исполняет проект и не меняет состав SBOM по reference.
R&D replays, fixtures, accuracy reports и XML test logs хранятся локально.

## Проверить source SBOM без образа

Сначала создайте обычный source-анализ через `POST /v1/source-analyses` с
repository URL и полным commit. Reference не передаётся этому запросу, checkout
или cdxgen. Дождитесь `source_status: succeeded`; image может отсутствовать.

Затем отправьте отдельный запрос:

```http
POST /v1/source-analyses/{source_id}/evaluations
Authorization: Bearer <token>
Content-Type: application/json
```

```json
{
  "reference_scope": "build",
  "reference_commit": "0123456789abcdef0123456789abcdef01234567",
  "reference_sbom": {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "version": 1
  }
}
```

Здесь reference — только пример формы запроса. Для измерения нужен непустой
реальный эталон с компонентами, версиями и, для прямых связей, владельцами и
dependency graph. `reference_commit`, если передан, должен совпадать с commit
опубликованного source SBOM. Утверждение клиента о происхождении reference
сохраняется как `caller_asserted_not_attested`, а не как build attestation.

Ответ `201` содержит ID оценки и `evaluation_url`. Получите JSON по этому URL
с тем же Bearer token. Каждый запрос создаёт отдельную неизменяемую оценку;
source SBOM и предыдущие оценки сохраняются. При незавершённом source-анализе
endpoint возвращает `409`, при некорректном reference — `422`.

Evaluator перечитывает готовые source-файлы и проверяет schema, producer,
commit/provenance и SHA256. Он не вызывает сканеры, сборку, registry или image
pipeline. Можно проверять один source SBOM по нескольким версиям эталона без
повторного анализа репозитория.

Метрики source-модели измеряются для явно указанной `build` scope. Runtime
эталон не подтверждает полный source graph: зависимости сборки могут не входить
в поставку. При `runtime` или `unknown` scope результат остаётся `UNKNOWN`.
И даже `build` scope требует сопоставимой конфигурации: profiles, dependency
scopes, dev dependencies и разрешённые версии могут отличаться от исходной CI.

Отчёт показывает два независимых вида сопоставления:

- `components.exact_purl` сохраняет version, qualifiers и subpath полностью;
- `components.coordinates` сравнивает ecosystem, namespace, name и точную version,
  явно сохраняя различия полных PURL. Это не доказательство одинаковых variants.

Для PURL без namespace пустой `group` и отсутствующий `group` обозначают одно
состояние. Неверный непустой group или противоречие со scoped PURL остаются UNKNOWN.

В каждом виде доступны TP/FP/FN, precision/recall/F1, count delta, пропуски и
лишние записи, coverage и UNKNOWN. Условная точность версий среди найденных имён
и `exact_version_coverage` по эталону показываются отдельно. Высокая точность
версий среди найденного не компенсирует низкий recall. Owner/direct graph
проверяется отдельно; наличие компонента не объявляет его прямой зависимостью.
Пустые или неразмеченные области не получают 100% точности.
