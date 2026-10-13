# R8: независимый npm-контроль H2.1, 2026-10-13

Три дополнительных проекта выбраны до чтения манифестов, точные commit закреплены
в [протоколе R7](../benchmarks/npm-control-v2.json). H1.1, H2.1, matcher и протокол
проверяются по ранее опубликованным SHA256. Правила не менялись после раскрытия.
Это малая выборка Node server frameworks, не репрезентативная оценка всех языков.

## Построение эталонов

Для каждого commit создан чистый checkout; npm install с dev-инструментами
(install scripts disabled), build при наличии, иначе npm pack; затем prune dev
и CycloneDX npm 6.0.1 для production-графа. Одинаковый каталог приложения передан
runtime-stage. Контролируемая упаковка не равна production release pipeline автора;
build/test scopes отдельно не размечены и не оцениваются.

Сверены деревья builder/runtime, image config/OCI binding, Syft input hashes,
схемы трёх SBOM. Корневые рёбра CycloneDX сверены с literal dependencies, lockfile
и установленными package.json. Для scoped npm используется group/name. Эталон не
передаётся ни H1, ни H2. Docker используется только во внешнем benchmark builder;
production runtime не меняется и Docker не требует.

## Воспроизведение

Первоначальное создание (завершённые receipts запрещают перезапись):

```powershell
python benchmarks/paired_express.py --project koa
python benchmarks/paired_express.py --project fastify
python benchmarks/paired_express.py --project hapi --run-id v3
python benchmarks/evaluate_npm_control_v2.py
```

Повтор evaluator использует сохранённые локальные архивы/Syft и опубликованные
компактные эталоны в benchmarks/references/paired-koa-v1, paired-fastify-v1 и paired-hapi-v3. Нужны исходные
локальные .work artifacts; Git содержит references/receipt, а не тяжёлые образы.
Повтор build может разрешить другие версии; receipt фиксирует именно данный запуск.

Fastify впервые остановился на scoped имени в проверяющем коде. Исправлено
сопоставление group/name и добавлен тест; продолжение --resume-built-images
использовало готовые образы. Полное build time Fastify не восстановлено (null).
Peak CPU/RSS не инструментированы; prediction timing не включает сканирование.

Hapi: v1 и v2 завершились без package-lock.json; его .npmrc задаёт save=false.
Для v3 явно заданы --save=true и --package-lock=true при install/prune.
Логи неудачных попыток сохранены в локальных .work/paired-hapi-v1 и v2.
Это изменение build-профиля тестового эталона, не исходного analyzer input.

## Результат замороженного контроля

| Проект | H1 TP/FP/FN | H2 TP/FP/FN | H2 precision | H2 recall / coverage | H2 F1 |
|---|---|---|---|---|---|
| Koa | 3/0/15 | 18/0/0 | 100% | 100% | 100% |
| Fastify | 0/0/15 | 14/0/1 | 100% | 93.33% | 96.55% |
| Hapi | 0/0/18 | 18/0/0 | 100% | 100% | 100% |
| Micro, 3/3 проектов | 3/0/48 | 50/0/1 | 100% | 98.04% | 99.01% |

H1 micro precision=100%, recall=5.88%, F1=11.11%; H2 precision не снизилась,
recall вырос. UNKNOWN H1=48, H2=1; UNKNOWN засчитан в FN, не скрыт из знаменателя.
Все 50 предсказанных версий/корневых рёбер совпали с эталоном. Единственный
UNKNOWN — pino у Fastify: ^9.14.0 || ^10.1.0, union не поддерживается.
Правила после просмотра результата не менялись. Это не ошибка inventory B0:
он не классифицирует direct, его точность не подменяется метрикой H1.

[Полный JSON](npm-h2-control-v2.json) содержит отдельные рёбра, baseline, SHA и
время prediction. Схемы всех 9 SBOM проверены. 74 unit/regression tests и Ruff
прошли. Production и набор inventory не изменены; сохранён эксперимент с
доказательством выигрыша для узкого npm-профиля. Нулевых проектов нет.

Следующий этап — аккуратная интеграция подтверждённого npm-профиля в сервис
с отдельным признаком direct/UNKNOWN и regression/schema/security проверками,
не сокращая inventory и не объявляя direct-признак фактом загрузки кода.
Не расширять union-правила по этому раскрытому контролю; для расширения нужны
development-tests и новый независимый этап. Остальные языки пока не оценены H2.
