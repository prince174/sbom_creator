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
