# R34 — Trivy0.75.0 source POM comparison

2026-10-14. Две paired Java development выборки,3synthetic scope cases.
Windows/amd64 официальный release archive, SHA256 проверен по checksums.
Version и binary/archive hashes сохранены в provenance.json.

| Реальный проект | TP | FP | FN | Совпали версии |
|---|---:|---:|---:|---:|
| Gson |1|0|0|1/1|
| Commons Text |1|0|0|1/1|

P/R/F1=100% только на2положительных рёбрах этих development-проектов. Не общий
рейтинг и не доказательство точности на6языках. Owner выбран по исходному POM;
wrapper filesystem/pom.xml не принят за модуль. Reference только для сравнения
после source scans. Изображение Trivy не передавалось, image pairing самих
эталонов подтверждён R21/R26. Scope привязан к выбранному build profile.

Source POM scan разрешает получение metadata из Maven repository. Это более
широкий сетевой режим, чем локальные Syft/J1. Системный Maven не установлен,
build tools benchmark не запускал. Не заявляем сетевую изоляцию инструмента.
Format cyclonedx отключает vulnerability scanning; skip-db-update и
skip-java-db-update применены. Состав ОС и уязвимости не оценивались.

Синтетические случаи: inherited provided исключён, child runtime включён,
profile test исключён. Последний не доказывает правильную активацию switch:
неактивный исходный provided также исключался бы. Контроль holdout не читался.

Выход1.7, официальные схемы взяты из
[CycloneDX specification1.7](https://github.com/CycloneDX/specification/tree/1.7/schema),
все5SBOM прошли jsonschema validation. Схемы сохранены с выводами.
Graph evaluator unit и Ruff passed. Runtime0.7.0 не менялся.

Команды scan (для каждого target, output отдельно):

```powershell
trivy.exe fs --format cyclonedx --skip-db-update --skip-java-db-update --disable-telemetry --timeout 3m --cache-dir <benchmark-cache> --output <output.json> <source-dir>
.venv/Scripts/python.exe -X utf8 benchmarks/evaluate_trivy_java.py
```

Первый Gson scan был выполнен без disable-telemetry; это отмечается для точности
протокола. Данные source и oracle ему передавались в таком же объёме, что
остальным source scans. Outputs сохранены в benchmarks/references/trivy-java-source-v1.
Raw elapsed/peakresources не измерялись. UUID/timestamp делают будущие байты
вывода отличными; сравнивать граф/координаты, сохранять новые output snapshots.

[Документация POM/scopes](https://trivy.dev/docs/latest/coverage/language/java/).
Следующее: отрицательный профильный случай, где baseline runtime меняется на
test, затем независимая контрольная Java-пара до вывода о superiority.
[Машинный отчёт](trivy-java-source-v1.json).
