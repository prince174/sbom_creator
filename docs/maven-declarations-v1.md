# R20 — аудит Java/Maven development деклараций

2026-10-13, main d26b9d5, чистое дерево, активных benchmark нет.
Production0.7.0 не менялся. Изучены8development проектов на точных commit;
исходные Java holdout commons-io/commons-lang не читались. Это аудит структуры,
не реализация resolver и не измерение точности прямых зависимостей.

| Проект | Root dependencies | Явный test | Явный provided | Scope не указан | Root edges эталона |
|---|---:|---:|---:|---:|---:|
| Commons Codec | 5 | 5 | 0 | 0 | 0 |
| Commons Text | 8 | 7 | 0 | 1 | 1 |
| Commons CSV | 8 | 6 | 0 | 2 | 2 |
| Commons Compress | 20 | 12 | 1 | 7 | 8 |
| Gson | 0 | 0 | 0 | 0 | 1, модуль gson |
| jsoup | 6 | 5 | 1 | 0 | 1 |
| SLF4J | 0 | 0 | 0 | 0 | 0, модуль slf4j-api |
| Commons CLI | 5 | 5 | 0 | 0 | 0 |

Всего52root declarations:40явных test,2provided,10без scope. У5проектов parent,
у всех8есть profiles; Gson/SLF4J имеют modules. Поэтому рекурсивный поиск всех
`dependency` без владельца недопустим. Скрипт читает только root dependencies,
считает отдельно management/profile/plugin declarations, сохраняет raw scope,
optional/type/classifier/exclusions и флаг `${...}`. Effective scope и resolved
version остаются null, свойства и parent/BOM/profiles не исполняются/не разрешаются.

Maven dependencyManagement задаёт правила версий, а не автоматически прямые
зависимости; provided отсутствует в runtime classpath. Optional может быть
прямой зависимостью самого проекта, даже если не наследуется потребителем.
[Официальная документация Maven](https://maven.apache.org/guides/introduction/introduction-to-dependency-mechanism.html).
Эти различия не означают автоматически ошибок CycloneDX или отсутствия в сборке.

Эталоны R1 прочитаны только для справочного root graph;13рёбер нельзя сравнивать
с52декларациями как TP/FP/FN: разные scopes/owners, непроверенное соответствие
старым образам. precision/recall/version accuracy=null, image_pair_verified=false.
Особенно запрещено считать пустой агрегатор Gson доказательством отсутствия
прямых зависимостей модуля gson. Данные и SHA POM/reference сохранены отдельно.

6tests passed, Ruff passed: structural boundaries, property/scope unresolved,
parent/modules не становятся dependency edges, oversized/DOCTYPE/namespace.
Первый запуск теста большого входа упал в pytest setup из-за огромного test ID
на Windows; добавлены короткие ids, повторный запуск прошёл. Скрипт — bounded
benchmark reader, не production XML loader и не полная XML security проверка.
Новых сборок и изменений immutable references в этом этапе нет.

```powershell
.venv/Scripts/python.exe -X utf8 benchmarks/audit_maven_declarations.py
.venv/Scripts/python.exe -m pytest benchmarks/test_maven_declarations.py -q
```

[Машинный отчёт](maven-declarations-v1.json).
Следующее: paired Commons Text build на том же commit, effective POM и native
Maven graph только в оценщике; CycloneDX root/runtime scope и содержимое image
проверить отдельно. Выбрать owner по координатам модуля, не по имени каталога.
Не передавать effective POM анализатору как новый обязательный вход.
