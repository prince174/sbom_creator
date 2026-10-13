# R26 — парный сборочный эталон Gson

2026-10-14 (Asia/Yekaterinburg). Development, модуль gson.
Commit: 828a97be0f8d58108b140b77df8dc76b657f4a87.

Реальная сборка package и CycloneDX Maven plugin2.9.3 makeBom выполнены
на Maven3.9.16 / Temurin17.0.20.1, linux/amd64. Base image закреплён digest
в сохранённом Dockerfile. Активный профиль JDK17. Тесты скомпилированы,
исполнение пропущено (-DskipTests); javadoc пропущен. Source checkout чистый.

Первая попытка с -Dmaven.test.skip=true завершилась ошибкой: lifecycle Gson
переименовывает тестовый класс перед обфускацией и требует test-classes.
Исправлен только параметр сборки. Неудачные recipe/log сохранены локально
в benchmarks/.work/paired-gson-v1/*failed-test-skip*.

| Проверка | Результат |
|---|---|
| Root | com.google.code.gson:gson:2.11.0 |
| Прямая compile/runtime зависимость | com.google.errorprone:error_prone_annotations:2.27.0 |
| CDX / native tree / effective POM / JAR metadata | Согласованы |
| JAR-дерево builder и конечного образа | Совпадает |
| OCI archive → config → Syft config | Проверено при генерации |
| final / OS / full | 2 / 0 / 2, три схемы валидны |
| Source / image artifacts | 32 / 2 |
| Decisions | INCLUDE2, UNKNOWN30 (15CI,15source-only) |
| Direct precision / recall | Не измерены: Java classifier отсутствует |

Образ scratch содержит только два JAR, без JRE. Это artifact fixture,
не проверка исполнения приложения или использования классов. Docker используется
только внешним benchmark; runtime сервиса не изменён. Сканер получает source и
образ, эталон/effective POM/native tree в анализатор не передаются.

Receipt SHA256: f707ff95692c21942c94d3ce0ac521bc6936a0aac578d7edf660862c32d35798.
Неизменяемые reference files лежат в benchmarks/references/paired-gson-v1.
Локальные tar/scan/log artifacts остаются в benchmarks/.work/paired-gson-v1.
Peak resources не измерены; timings reconciliation не равны времени сборки.

Повторная проверка хешей, tree, OCI binding, Maven/JAR consistency и схем:

```powershell
.venv/Scripts/python.exe -X utf8 benchmarks/verify_paired_gson.py
```

Harness отказывается перезаписывать завершённый receipt. Пять тестов общего
Maven/JAR verifier прошли; Ruff для нового harness/verifier прошёл.
Следующее: проверить J1 owner/GAV и ограниченную обработку локального parent
на этой development паре; не использовать reference как вход, не ослаблять
UNKNOWN по одному положительному примеру. [Результаты](paired-gson-v1.json).
