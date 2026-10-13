# R21 — парная Commons Text сборка и эталон

2026-10-13, исходное состояние main f0e0310, чистое дерево, benchmark-процессов нет.
Runtime0.7.0 неизменен. Только development Java; holdout не читался.

Собран Commons Text **1.13.0** из commit
`9430a2848a2593ee3bce32750305c28c549cabf8`. Maven3.9.16/Temurin17.0.20.1,
linux/amd64; базовый Maven image закреплён digest в recipe. Tests skipped,
checkstyle/RAT/javadoc/spotless выключены явными параметрами. Активные профили
и effective POM сохранены; это конкретный профиль, не все варианты сборки.

CycloneDX2.9.3 generated sbom.json, native dependency tree3.8.1 и effective POM
согласованы: root `org.apache.commons:commons-text:1.13.0` имеет одно прямое
compile/runtime ребро `org.apache.commons:commons-lang3:3.17.0`. JAR pom.properties
подтверждают обе координаты и версии. Для fixture сравниваются GAV; расширенный
classifier/type resolver и shaded JAR в этом проверяющем скрипте не поддерживаются.

Образ содержит только2JAR в /application, скопированные из того же builder.
Это artifact-only scratch image без JRE и ОС, не запуск приложения. Сравнение
деревьев build/runtime (содержимое/пути/режимы), OCIindex→manifest→config, сырая
Syft config и hashes проверены. Исходник анализатора — чистый clone, а не build
workspace. Effective POM, native graph и CycloneDX не передаются анализатору.

Результат сервиса: **final2 / OS0 / full2**, все3схемы валидны. Source27,
image2, INCLUDE2, UNKNOWN25 (CI13,source-only6,ambiguous identity6). UNKNOWN
деклараций не превращён в ошибки direct classifier. Java direct classifier
отсутствует: precision/recall/version accuracy по direct остаются null. Нельзя
выдать проверенное эталонное ребро за правильно предсказанное сервисом.

Первая сборка успешно прошла Maven, но exporter искал target/sbom.json.
Parent/project config задаёт target/commons-text-1.13.0-bom.json; путь исправлен.
Failed recipe/log сохранены локально, выполнена повторная сборка. Lifecycle
также вызывает CycloneDX2.9.0 из проекта, затем явный2.9.3 перезаписывает BOM;
в сохранённом эталоне проверена версия2.9.3. Исходный POM не менялся.

5проверок оценщика passed, Ruff, повторная валидация hashes/tree/OCI/JAR/native/
effective POM/3схем passed. Новых runtime-тестов не требовалось: src не менялся.
Peak resources не измерены; reconciliation time не является временем сборки.
Остальные плагины наследуются из проекта/parent; effective POM фиксирует их,
но не утверждается полная побайтовая воспроизводимость будущей сетевой сборки.

```powershell
.venv/Scripts/python.exe -X utf8 benchmarks/verify_paired_commons_text.py
.venv/Scripts/python.exe -m pytest benchmarks/test_paired_commons_text.py -q
```

Immutable references: `benchmarks/references/paired-commons-text-v1`.
Локальные archive/tree/scan/logs: `benchmarks/.work/paired-commons-text-v1`.
Harness `paired_commons_text.py` отказывается перезаписывать завершённый receipt.
[Машинная проверка](paired-commons-text-v1.json).
[Официальный Maven dependency:tree](https://maven.apache.org/plugins/maven-dependency-plugin/tree-mojo.html)
описывает JSON output и scope filter; в recipe закреплена3.8.1, не latest.

Следующее: исследовать Syft Java metadata и raw/embedded POM на development
Commons Text; сформулировать консервативный J1 без parent/profile execution.
Effective POM остаётся только oracle; версии/owners с недостаточными данными UNKNOWN.
