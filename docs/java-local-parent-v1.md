# R24 — локальная цепочка parent POM

2026-10-13. Эксперимент, runtime 0.7.0 не изменён.

Прототип читает только обычные Git blobs на зафиксированном commit, без исполнения
Maven или чтения checkout по relativePath. Переход допускается только при точном
совпадении буквальных groupId/artifactId/version. Пустой relativePath отключает
локальный поиск; значения со свойствами, абсолютные/Windows пути и выход за корень
дают UNKNOWN. Циклы и глубина более16 запрещены. POM ограничен1MiB; аудит —256POM
и16MiB на проект. Symlink/submodule blobs исключены.

Это проверка идентичности цепочки, не слияние effective model. Унаследованные
group/version, свойства и профили ещё не разрешаются. XML parser не является
общим production Maven parser. Аудит выбирает файлы с именем pom.xml; нестандартные
имена POM не охвачены. Реальной новой сборки на этом этапе не было.

| Результат на8 development проектах | POM |
|---|---:|
| Локальная цепочка найдена |10|
| Требуемый путь вне репозитория |5|
| Неопределённая или несовпавшая идентичность |14|

Из10 найденных цепочек7 содержат переход к parent, а3 — только исходный POM без
parent. В выборку входят example/test POM: это не coverage активных модулей и не
метрика прямых зависимостей. Commons Text по-прежнему требует внешний parent;
этот этап не устраняет его UNKNOWN. Эталоны не подавались анализатору, holdout не
читался. Direct precision/recall и точность версий остаются неизмеренными.

Семантика inheritance/relativePath сверена с
[Maven POM Reference](https://maven.apache.org/pom.html#Inheritance).
Проверки:14 unit cases, Ruff; сохранены commit/SHA каждого POM.

```powershell
.venv/Scripts/python.exe -X utf8 -m pytest benchmarks/test_java_local_parent.py -q
.venv/Scripts/python.exe -X utf8 benchmarks/audit_java_local_parent.py
```

Следующее: на development Gson проверить ограниченное слияние локальных
деклараций/management и влияние профилей; затем получить парный сборочный эталон
для конкретного модуля. Не считать identity_only доказанным effective scope.

[Машинный отчёт](java-local-parent-v1.json).
