# R29 — реальные сборки синтетических scope-контрпримеров

2026-10-14. Три synthetic development fixtures, не новые реальные проекты.
Maven3.9.16 / Temurin17.0.20.1, linux/amd64, base image pinned digest.
Для каждой выполнены package, CycloneDX2.9.3 makeBom, effective-pom3.5.1.
Prediction получен до сборки и чтения reference. Исходники синтетические,
сохранены побайтово с SHA в receipt; это не upstream repository commit.

| Случай | Effective scope сборки | Предсказание |
|---|---|---|
| Parent management |provided|provided, static candidate|
| Явный child override |runtime|runtime, static candidate|
| Профиль switch, включён -Pswitch |test|UNKNOWN, profile_declaration_impact|

Во всех случаях прямая зависимость commons-lang3:3.17.0 присутствует в CDX.
Генератор запущен с includeTestScope=true. Одинаковое ребро не доказывает
одинаковый scope; scope оценён по effective POM. Прототип правильно воздержался
от вывода для профиля. Это2совпадения static model и1UNKNOWN, не direct precision.

Для каждой fixture скомпилирован App.java и создан JAR. Тестовых исходников нет.
Runtime image/Syft replay не выполнялись, image pairing=false. Нет утверждения
об использовании commons-lang3 кодом или исполнении приложения. Docker только
во внешнем benchmark, сервис не менялся.

Все POM, source, CDX, effective POM, recipe, версии среды, результаты и SHA
сохранены в benchmarks/references/maven-scope-fixture-v1. Build image ID
и base commit harness сохранены в receipt. Lifecycle plugin versions видны
в effective POM; recipe не фиксирует их отдельно, поэтому новая сборка в будущей
среде требует проверки этих версий. Старые evidence не перезаписываются.

Повторный verifier проверяет SHA, scopes, поведение UNKNOWN, root graph и
схему всех3CDX. Ruff прошёл.

```powershell
.venv/Scripts/python.exe -X utf8 benchmarks/verify_maven_scope_fixture.py
```

Следующее: заморозить экспериментальный J1 end-to-end candidate pipeline и
измерить coverage/UNKNOWN на двух paired development Java проектах, сохраняя
границы неподдерживаемых профилей/remote parent. Контроль не использовать для
подбора правил. [Результат](maven-scope-fixture-v1.json).
