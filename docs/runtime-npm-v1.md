# R9: интеграция npm H2.1 в сервис 0.6.0, 2026-10-13

Подтверждённый R8 npm-профиль включён в publication pipeline. Production-модуль
не импортирует benchmarks. Репозиторий/commit/образ остаются единственными
обязательными входами; Node, npm, Docker, LLM и эталон runtime не нужны.
Развёрнутые сервисы не изменялись.

Корневой package.json читается ограниченно (1 MiB, до 5000 деклараций на карту),
без следования symlink, с проверкой типов/дубликатов JSON. Невалидный или
неподдерживаемый источник даёт UNKNOWN, отсутствие package.json — not-applicable.
Без source manifest при старом catalog replay профиль не оценивается.
URL/git specs заменяются на <unsupported> в новом публичном отчёте, чтобы не
копировать возможные credentials. Полный package.json не публикуется.

Связи добавляются только между package-компонентами, уже принятыми inventory
policy. Если owner или dependency не экспортированы, direct-статус понижается
до UNKNOWN. Связь идёт от package приложения, не от container metadata subject.
CycloneDX component properties direct-owner/direct-scope сопровождают связи;
новый direct-dependencies.json содержит причины и SHA256 исходного манифеста.
Старые компоненты и связи не удаляются; graph_complete остаётся false.
Неотмеченные пакеты нельзя автоматически считать transitive.

## Проверка

[Результат replay](runtime-npm-v1.json): шесть ранее построенных пар прошли через
настоящие reconcile, Syft convert, export и schema validation. Предсказания
производственного модуля сравниваются с неизменённым экспериментальным H2.1.

| Пара | DIRECT | UNKNOWN | Состав final / OS / full |
|---|---:|---:|---|
| Express | 31 | 0 | 267 / 89 / 356 |
| Axios | 3 | 0 | 214 / 89 / 303 |
| isarray | 0 | 0 | 199 / 89 / 288 |
| Koa | 18 | 0 | 234 / 89 / 323 |
| Fastify | 14 | 1 | 250 / 89 / 339 |
| Hapi | 18 | 0 | 231 / 89 / 320 |

Все компоненты и прежние graph edges сохранены; 18 SBOM валидны; новые direct
edges присутствуют в final/full. OS остаётся отдельно. Это regression replay,
не новая независимая выборка. [Независимый R8](npm-h2-control-v2.md): 50 TP,
0 FP, 1 FN, precision 100%, recall 98.04%, F1 99.01% на 3 npm-проектах.
Остальные языки, модули, dev/build/peer-only и runtime reachability не оценены.

Полный suite: 208 passed, один прежний skip; дополнительный тест реального
symlink на Windows пропущен из-за отсутствия прав создания ссылки. Защиты
malformed/oversized/duplicate/non-file и недопущение credentials в отчёт проверены.
Первый запуск тестов выявил слишком длинный автоматически созданный ID oversized
фикстуры на Windows; ID исправлен, повтор suite успешен. Ruff passed.

```powershell
python -m pytest -q
python benchmarks/verify_runtime_npm.py --run-id fresh-check
```

Replay требует сохранённых .work каталогов; run-id должен быть новым, чтобы не
перезаписать evidence. Сканирования/сборки для replay не нужны.

Следующий этап: независимые development-fixtures для остальных npm-форматов и
выбор следующего языка с парным эталоном. Union pino не исправлен по раскрытому
контролю. Поддержка прямых связей не превращает присутствие в образе в факт
использования при сборке и не сокращает SBOM ради метрики.
