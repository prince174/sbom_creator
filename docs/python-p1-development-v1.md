# R12: Python P1.0, development, 2026-10-13

Отдельный экспериментальный классификатор, не runtime. Входы: исходный pyproject
и Syft image JSON. Эталон загружается evaluator только после prediction.

| Выборка | TP | FP | FN | Precision / Recall / F1 | UNKNOWN |
|---|---:|---:|---:|---|---:|
| Jinja, development, одно прямое ребро | 1 | 0 | 0 | 100% / 100% / 100% | 0 |
| Python holdout | — | — | — | не измерены | — |

MarkupSafe 3.0.4 совпал с CycloneDX по имени и версии. Coverage 1/1 относится
только к безусловной runtime-декларации одного проекта, а не ко всем Python
компонентам/проектам. Корневая версия Jinja в reference отсутствует, её accuracy
остаётся null. Источник version dynamic не превращается в утверждение о версии:
в отчёте отдельно version из источника (null) и установленная version (3.1.5).
[Полный отчёт, SHA и предсказание](python-p1-development-v1.json).

## Правило P1

1. Static project.dependencies; dynamic dependencies даёт UNKNOWN.
2. Единственная установленная distribution с именем проекта и METADATA-location.
   Если source version статическая, проверяется её совпадение.
3. Требование источника должно совпасть с безусловным Requires-Dist установленного
   корня. Не достаточно совпадения имени пакета в inventory.
4. Зависимость должна быть единственной в том же site-packages/dist-packages,
   её стабильная версия должна удовлетворять спецификатору.

Пути берутся из location.path/accessPath. В Windows-скане поле Syft
sitePackagesRootPath содержит обратные слеши даже для Linux-образа; оно не
используется для определения владельца. Требования URL, extras, markers,
неоднозначные установки, conflicting versions и prerelease остаются UNKNOWN.
Build-system, optional-dependencies и dependency-groups не включены в профиль.
setup.py и код проектов не исполняются. Никаких host marker evaluation.

[PyPA Requires-Dist](https://packaging.python.org/en/latest/specifications/core-metadata/#requires-dist-multiple-use)
и [packaging specifiers](https://packaging.pypa.io/en/stable/specifiers.html)
использованы для семантики метаданных и версий. Development dependency
packaging==26.3 зафиксирована в отчёте; production requirements не менялись.

Имя корня и совпадение декларации не доказывают source commit/image binding
в общем случае. Для Jinja это независимо проверено R11. Поддержка лишь
METADATA-установок и одного окружения ограничивает coverage; это не полный resolver.
Необработанные экзотические/некорректные структуры входов ещё требуют hardening
перед возможной интеграцией. Production не готов на основании одного TP.

11 тестов: чужое venv, неоднозначность, отсутствие Requires-Dist, version conflict,
markers/extras/URL, static root mismatch, symlink accessPath, dynamic dependencies,
неизменность входов. Ruff passed. R11 hashes/trees/versions/3 schemas перепроверены.
Время prediction около 0.05 с с парсингом входа, не end-to-end; peak RSS не измерен.

```powershell
python benchmarks/verify_paired_jinja.py
python -m pytest benchmarks/test_python_direct_p1.py -q
python benchmarks/evaluate_python_p1.py
```

Следующее: замороженный P1.0 (SHA в отчёте) проверить на парных Flask и Packaging
из исходного holdout. Перед этим подготовить соответствующие wheel/venv/reference
сборки с зафиксированными профилями, без настройки P1 по их содержимому. Если
markers останутся UNKNOWN, честно учесть это в FN/coverage. Старый split не слепой
(обзор R1/R2 до фиксации уже раскрыт), не называть эту проверку слепой.
