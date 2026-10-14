# R42 — G2 selected-main static imports

2026-10-14. Один Hey development repo и один synthetic derivative.
Source index дополнен imports через standard Go AST. Обход начинается от
entry path из binary, следует только root-module package imports, внешние
modules отмечаются без обхода их imports. Другой main/test исключены.
Внешний module выбран по longest binary-module path prefix, версия из binary.

| Выборка | G1 лишние candidates для selected main | G2 лишние | G2 пропуски native main |
|---|---:|---:|---:|
| Hey |0|0|0|
| Multimain derivative |1|0|0|

Оба G2 дают только x/net с точной версией. Обойдены ./requester и root.
Это воспроизводимое улучшение экспериментального selected-main графа, но
не основной module-root/CDX метрики: в synthetic CDXrootdirect содержит
x/net+x/text, G2 пропускает1module-declared edge по своему более узкому scope.
Поле module_root_edges_without_g2_candidate явно сохраняет это расхождение.
Не внедрять G2 как замену project/module direct graph без согласованной области.

Prediction не получает reference. Native packages.json и CDX читаются после
его получения, SHA проверены. Binary entry и deps читаются из image payload R41,
binary SHA также проверен по paired receipt. Runtime0.7.0 unchanged.

Go toolchain parser точно совпадает с binaryGo1.24.13. CGO/custom tags/CPUlevel
отличный отv1/instrumentation/replaces/workspace unsupported. Для прочих
валидных данных prototypeUNKNOWN, runner выводит ошибку unsupported context,
не возвращает пустой успешный graph. Unmapped imports или localpackages UNKNOWN.
Standard library imports пока предполагаются по форме path (безdot), поэтому
общая корректность не доказана. Бюджеты parser прежние R40, guard дляruntimeнет.

3 unit tests покрывают unreachablemain/transitive exclusion, missinglocal/
unmappedexternal UNKNOWN, longestmoduleprefix и cycle. Realparser build,
два replay и Ruff passed. No new project build. Direct P/R/F1 null: пока нет
независимого контроля и единой области module/main.

```powershell
.venv/Scripts/python.exe -X utf8 -m pytest benchmarks/test_go_g2_imports.py -q
.venv/Scripts/python.exe -X utf8 benchmarks/evaluate_go_g2.py
```

Следующее: заморозить G2 до нового paired control, отдельно оценивать
module declarations и main imports. Расширить корпуса следующих языков;
не продолжать тюнинг на Hey вместо контрольной проверки.
[Машинный отчёт](go-g2-imports-v1.json).
