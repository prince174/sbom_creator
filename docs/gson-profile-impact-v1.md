# R25 — влияние профилей Gson на декларации

2026-10-14 (Asia/Yekaterinburg). Source commit
828a97be0f8d58108b140b77df8dc76b657f4a87, development.

Проверена локальная цепочка gson/pom.xml → pom.xml. Все4 профиля (jdk15,
jdk21+, release, JDK17) не содержат dependencies/dependencyManagement и не
меняют свойства, на которые статически ссылаются эти секции. Два профиля
содержат build. Активация каждого остаётся UNKNOWN.

Гипотеза для следующего этапа: блокировка любого наличия profiles в R23
слишком груба для определения деклараций. Но отсутствие статической ссылки
не доказывает неизменность effective model: settings, CLI, extensions и
действия plugins не моделируются. Runtime-фильтр не ослаблен; direct edges
не добавлены. Улучшение точности/coverage не заявляется.

Аудитор отслеживает также косвенные ссылки свойств между parent/child и
завершает обход при цикле. Объединение альтернативных значений свойств
консервативно; это не Maven interpolation. Источник прочитан через git show
на точном commit, SHA сверены с R24. Эталон и holdout не читались.

Семантика профилей сверена с
[официальной документацией Maven](https://maven.apache.org/guides/introduction/introduction-to-profiles.html).
Активные профили меняют модель, эффекты родительских профилей наследуются;
из наличия профиля нельзя выводить его активацию.

Проверки:4 новых теста (dependencies, management, косвенное свойство с циклом,
build-only без ложного safe-статуса), предыдущие32 Java tests и Ruff.

```powershell
.venv/Scripts/python.exe -X utf8 -m pytest benchmarks/test_java_profile_impact.py -q
.venv/Scripts/python.exe -X utf8 benchmarks/audit_gson_profiles.py
```

Следующее: парная сборка конкретного модуля Gson с CycloneDX и сохранёнными
native tree/effective POM/active profiles, затем проверка ограниченного
наследования declarations/management. Парный Commons Text для этого не подходит.
Существующий R1 Gson не является доказанной парой с образом; не подменять им
парную оценку. [Машинный отчёт](gson-profile-impact-v1.json).
