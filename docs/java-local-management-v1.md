# R28 — ограниченная обработка local dependencyManagement

2026-10-14. Development Gson, без изменения runtime0.7.0.

Прототип заполняет отсутствующие поля деклараций из локального management.
Явные поля child сохраняются; management сам по себе не создаёт зависимость.
Удалённые parent, наследуемые dependencies, property expressions, BOM import,
необычные type/classifier и профили с потенциальным влиянием дают UNKNOWN.
Это ограниченная статическая модель, не полный Maven effective model.

| Декларация модуля Gson | Версия | Scope | Сверка с effective POM сборки |
|---|---|---|---|
| error_prone_annotations |2.27.0|compile|совпало|
| junit |4.13.2|test|совпало; версия из parent|
| truth |1.4.2|test|совпало; версия из parent|
| guava-testlib |33.1.0-jre|test|совпало|

4/4 строки совпали по GAV/scope. В R27 две версии оставались неизвестными.
Это не precision/recall direct edges: предсказаны поля модели одного известного
development-проекта, а не обобщённая точность сервиса. Все строки остаются
STATIC_MODEL_CANDIDATE. Эффекты settings/CLI/extensions/plugins не доказаны.
Owner здесь — путь модуля; графовые рёбра не создаются. Scope test не теряется
из-за отсутствия соответствующего JAR в runtime image.

Effective POM загружается только после prediction. Source/reference SHA
проверены по immutable receipt R26. Новых сборок/изменений reference нет.
Правила management сверены с
[документацией Maven](https://maven.apache.org/guides/introduction/introduction-to-dependency-mechanism.html).

49 Java tests прошли, включая5новых проверок управления версией/scope,
приоритета явного child, отсутствия phantom edges и UNKNOWN для unsupported
inheritance/import/duplicate. Ruff прошёл.

```powershell
.venv/Scripts/python.exe -X utf8 -m pytest benchmarks/test_java_local_management.py -q
.venv/Scripts/python.exe -X utf8 benchmarks/evaluate_java_local_management.py
```

Следующее: отдельная контролируемая Maven fixture с parent management,
child override и profile-changing-scope; сравнить с реально построенным
effective POM/CDX. До этого не объединять кандидатов с production direct edges.
[Машинный отчёт](java-local-management-v1.json).
