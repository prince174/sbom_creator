# R32 — отрицательная проверка простого фильтра Syft

2026-10-14. Syft1.51.1, windows/amd64, source scan трёх неизменяемых
синтетических проектов R29. Новых Maven-сборок не было; используются
сохранённые CDX/effective POM реальных сборок R29.

| Случай | Raw scope Syft | Build effective scope | Простой фильтр |
|---|---|---|---|
| inherited |отсутствует|provided|оставил кандидата ошибочно для runtime|
| override |runtime|runtime|оставил кандидата|
| profile |отсутствует|test|оставил кандидата ошибочно для runtime|

Во всех случаях GAV commons-lang3:3.17.0 одинаков. Следовательно, совпадение
координат и версии не компенсирует неизвестный scope. R31 adapter, который
исключает только явно отмеченные test/provided/system, отклонён для runtime.
Это отрицательный результат нашего адаптера, не заявление об общей точности
Syft или ошибке инвентаризации. Source scanner не получает активный build profile.

Ранее2/2GAVсовпадения на Gson/Commons Text недостаточны: на этих контролируемых
контрпримерах2не-runtime scope остаются среди кандидатов. Не вычисляем общий
precision по трём специально подобранным случаям. Production не менялся.
J1 не ослабляется до правила «нет scope значит compile».

Catalogs сохранены отдельно в benchmarks/references/syft-scope-counterexamples-v1,
их SHA есть в отчёте. Оригинальные build references R29 неизменны, SHA проверены.
Scan targets содержали только source, не oracle. Raw catalogs сохранены для
аудита; время/пиковые ресурсы не измерялись.

```powershell
.venv/Scripts/python.exe -X utf8 benchmarks/evaluate_syft_scope_counterexamples.py
```

Ruff и повторная сверка R29 прошли. Следующее: приоритет независимому конкуренту
или расширению парной выборки другого языка; Java J1 остаётся экспериментом,
пока неизвестные build settings/profiles не разрешены доказуемо.
[Данные](syft-scope-counterexamples-v1.json).
