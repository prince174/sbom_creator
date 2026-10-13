# R17 — ограничение полей, используемых P1

2026-10-13, исходное состояние main72c9774, чистое дерево, benchmark-процессов нет.
Runtime0.6.0, frozen P1 и guard неизменны. Эксперимент продолжает отрицательный R16.

Гипотеза: бюджет полного Syft дерева неприменим к маленькому классификатору,
но тот же бюджет для читаемых полей позволяет сохранить его результаты.
Использованы прежние лимиты250000узлов/16Ми символов/глубина64 без увеличения.

Проекция оставляет source project.name/version/dynamic/dependencies; для всех
artifacts сохраняет id/type/metadataType, для Python также name/version,
requiresDist и path/accessPath всех locations. Не отбирает кандидатов по имени,
не удаляет дубликаты, не фильтрует неоднозначные установки. Сохраняются ID даже
пакетов других языков: коллизия по-прежнему UNKNOWN у guard. Неиспользуемые
files/source/config/license описания в копию классификатора не входят.
Полный исходный каталог и inventory не меняются.

Бюджет расходуется последовательно по проекции каждого artifact; превышение
отклоняет анализ целиком, без частичного DIRECT. Размер artifacts и locations
проверяется перед обходом. Это бюджет узлов/символов, не точный лимит RAM;
копия одного ограниченного artifact создаётся перед списанием его бюджета.
Общий контракт размера входного Syft JSON до разбора ещё НЕ реализован.

| Сборка | DIRECT | UNKNOWN рёбер | TP / FP / FN контроля |
|---|---:|---:|---|
| Jinja development | 1 | 0 | не переоценивается как holdout |
| Flask | 5 | 1 | 5 / 0 / 0 |
| Packaging | 0 | 0 | 0 / 0 / 0; метрики не определены |
| HTTPX | 4 | 0 | 4 / 0 / 0 |

Предсказания целиком равны исходному guarded P1, включая версии, причины и ID.
Flask сохраняет83.33% coverage деклараций; условный importlib-metadata UNKNOWN.
По сравнению с отклонённым R16 восстановлены9 контрольных рёбер. По сравнению
с исходным P1 accuracy НЕ выросла. Это regression replay раскрытого контроля,
не новая слепая выборка и не доказательство общей точности Python.

57tests passed,1skip (Windows symlink creation), Ruff passed. Проверены
некорректные типы/ID, другая установка, дублирование между языками, большие
неиспользуемые поля, превышение полезного бюджета, неизменность входов.
На четырёх парах подтверждены hash inputs/receipt и эквивалентность loader;
Flask/Packaging/HTTPX также повторно проверены tree/OCI/metadata/3схемы.
Новых сборок нет. В отчёте время projection+P1, не pipeline/build; peak RAM неизвестна.

```powershell
.venv/Scripts/python.exe -X utf8 benchmarks/verify_python_p1_projection.py
.venv/Scripts/python.exe -m pytest benchmarks/test_python_p1_projection.py benchmarks/test_python_p1_boundary.py benchmarks/test_python_p1_guard.py benchmarks/test_python_direct_p1.py -q
```

[Данные](python-p1-projection-v1.json). Сохранено только в benchmarks.
Следующее: проверить существующие acquisition/parser ограничения размера
полного Syft JSON и сформировать явный контракт; затем интеграция Python
evidence с полным regression/schema/security replay, без сокращения inventory.
