# R19 — интеграция Python P1, версия0.7.0

2026-10-13. Исходный commit b68f33b, чистое дерево, benchmark-процессов нет.
Python evidence добавлен в production publication path, без новых обязательных
входов, Docker/LLM/Node или исполнения анализируемого проекта. Deploy не выполнялся.

## Поведение

После checkout автоматически читается корневой pyproject.toml. Loader ограничен
1МиБ, отвергает невалидный TOML, дубликаты, nonregular/reparse/symlink и ошибки
чтения. Пустое отсутствие manifest — not-applicable; невалидность — UNKNOWN.
Проекция полей P1 ограничена250000узлами/16Ми символов/глубиной64. Полный Syft
output до JSON parsing ограничивает общий runner (R18,64МиБ stdout+stderr).
Ни один из этих лимитов не является точным лимитом RAM; peak RAM не измерена.

Frozen P1 переносится без изменения правил: статическое безусловное requirement
должно совпасть с Requires-Dist установленного корня, а ровно один целевой пакет
в том же окружении — удовлетворять версии. Dynamic root version допускается,
но версия из source не выдумывается. Markers/extras/URL/dynamic dependencies,
неоднозначные установки, prerelease остаются UNKNOWN. Build/test/optional не
повышаются до runtime direct. Общая связь commit↔образ по имени не доказывается.

Публикация добавляет только рёбра между однозначными компонентами уже выбранного
inventory. Если owner/target отсутствует или неоднозначен — UNKNOWN, без создания
компонента. Существующие рёбра сохраняются. Все три SBOM остаются: final/nonOS,
os, full. Npm-only direct report сохраняет прежний формат; для совместного
корня npm+Python добавлены profiles и объединённый список edges. При UNKNOWN
всего профиля unknown_count=null; это не нулевая неопределённость.

Добавлена runtime-библиотека packaging>=26.3,<27 для PEP508/PEP440; проверено
на26.3. Генераторы CycloneDX и эталоны остаются только в benchmark. Python
контроль не использовался для подбора новых правил.

## Результаты на неизменяемых парных сборках

| Проект | DIRECT | UNKNOWN | TP/FP/FN контроля | Точные версии |
|---|---:|---:|---|---|
| Jinja development | 1 | 0 | не holdout | 1/1 |
| Flask | 5 | 1 | 5/0/0 | 5/5 |
| Packaging | 0 | 0 | 0/0/0; метрики null | нет прямых |
| HTTPX | 4 | 0 | 4/0/0 | 4/4 |

Flask+HTTPX: precision/recall/F1=100% на9рёбрах двух проектов. Flask declaration
coverage83.33%: importlib-metadata conditional неактивна в Python3.12, но
классификатор оставляет UNKNOWN. Корневые версии Jinja/Packaging/HTTPX в reference
отсутствуют — их точность UNKNOWN. Выборка мала и не гарантированно слепая.

В0.6.0 Python direct classifier отсутствовал: baseline precision не определена,
не объявляется0%. Интеграция добавляет подтверждённую Python coverage. По сравнению
с experimental P1 предсказания полностью совпадают, accuracy правил не выросла.

Шесть npm пар: Express31, Axios3, isarray0, Koa18, Fastify14+UNKNOWN1, Hapi18 —
без регрессии. Проверены name/status/version относительно frozen classifier,
наличие рёбер в final/full, сохранение component refs/прежних рёбер и три схемы
для всех10пар. Реальный Syft convert, сохранённые каталоги; новых сборок/сканов нет.
Не подтверждает новые corporate registry/Bitbucket соединения.

Проверки: полный pytest272passed/3skipped/1known warning, Ruff passed, malformed/oversized/source URL redaction,
неоднозначные ID/окружения, отсутствие выбранного компонента, неизменность входов,
автоматическое чтение Python manifest из analyze_local, смешанный отчёт.
Windows symlink creation пропускается при отсутствии прав, это не passed check.
Машинные результаты: [Python](runtime-python-r19.json), [npm](runtime-npm-r19.json).

```powershell
.venv/Scripts/python.exe -m pytest -q
.venv/Scripts/ruff.exe check src tests
.venv/Scripts/python.exe -X utf8 benchmarks/verify_runtime_python.py --run-id NEW_UNIQUE_ID
.venv/Scripts/python.exe -X utf8 benchmarks/verify_runtime_npm_r19.py --run-id NEW_UNIQUE_ID
```

Следующее: новые сложные Python профили (multi-environment/monorepo/активные
markers) оценивать отдельно с UNKNOWN; продолжить парные референсы и direct
evidence для Java/Rust/Go/Ruby. Не считать10повторных экспортов покрытием60пар.
