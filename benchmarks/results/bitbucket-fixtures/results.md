# Дополнительные Bitbucket fixtures

Эти integration fixtures учитываются отдельно от основной матрицы 60 кодовых проектов. Статус checkout/source_scanned/build_complete не означает завершённый тест системы.

Образы собираются отдельным benchmark-процессом из закреплённых checkout. Это контролируемые сборки, а не образы production pipeline. GitHub не подтверждает доступ к Bitbucket. Режим rules не подтверждает качество LLM. FP/FN без независимой полной разметки не рассчитываются.

Image ID в таблице сокращён; полное значение и его тип сохранены в CSV/JSON. INCLUDE/UNKNOWN считают идентичности, а Source/Image/Final — записи пакетов: дубликаты расположений могут давать разные числа. `partial` означает наличие UNKNOWN. Bitbucket fixture без объявленных runtime-зависимостей проверяет доступ и корректность потока, но не полноту поиска реальных зависимостей приложения.

`App image/final` проверяет одну закреплённую release-идентичность основного пакета по точному PURL name/version/ecosystem. Это отдельная ограниченная проверка, не FP/FN всех зависимостей; `false` может означать, что локальная сборка не сохранила release version. `—` означает, что точная ожидаемая идентичность неприменима.

| Язык | Завершено | Ошибка | Прочее |
|---|---:|---:|---:|
| Java | 1 | 0 | 4 |
| JavaScript | 3 | 0 | 0 |
| Python | 3 | 0 | 0 |
| Rust | 0 | 0 | 0 |
| Go | 0 | 0 | 0 |
| Ruby | 0 | 0 | 0 |

| Репозиторий | Язык | Commit | Image ID | Source | Image | INCLUDE / EXCLUDE / UNKNOWN | Final | App image/final | CDX | Сек. | Режим | Coverage | Статус |
|---|---|---|---|---:|---:|---|---:|---|---|---:|---|---|---|
| [artifact_graph/java-maven-api](https://bitbucket.org/artifact_graph/java-maven-api) | Java | 33181ac8fd00 | sha256:d4600d698ec9 | 1 | 151 | 146/0/5 | 146 | True/True | True | 130.0 | rules | partial; fixture without declared runtime deps; no application source code | completed_rules |
| [artifact_graph/java-gradle-worker](https://bitbucket.org/artifact_graph/java-gradle-worker) | Java | 98772093571e | — | 0 | — | —/—/— | — | —/— | — | 0.4 | — | not measured; fixture without declared runtime deps; no application source code | source_scanned |
| [artifact_graph/java-maven-orders](https://bitbucket.org/artifact_graph/java-maven-orders) | Java | 6c1064a74596 | — | 1 | — | —/—/— | — | —/— | — | 4.9 | — | not measured; fixture without declared runtime deps; no application source code | source_scanned |
| [artifact_graph/java-gradle-billing](https://bitbucket.org/artifact_graph/java-gradle-billing) | Java | f162358c264d | — | 0 | — | —/—/— | — | —/— | — | 5.2 | — | not measured; fixture without declared runtime deps; no application source code | source_scanned |
| [artifact_graph/lab-maven](https://bitbucket.org/artifact_graph/lab-maven) | Java | beede5f2c6db | — | 1 | — | —/—/— | — | —/— | — | 4.7 | — | not measured; fixture without declared runtime deps | source_scanned |
| [artifact_graph/npm-frontend](https://bitbucket.org/artifact_graph/npm-frontend) | JavaScript | 56e0ef7c4b26 | sha256:6e0c3dcdda83 | 0 | 292 | 277/0/4 | 288 | True/True | True | 41.3 | rules | partial; fixture without declared runtime deps; no application source code | completed_rules |
| [artifact_graph/npm-admin](https://bitbucket.org/artifact_graph/npm-admin) | JavaScript | b0bc039a3532 | sha256:c5e69ba52751 | 0 | 292 | 277/0/4 | 288 | True/True | True | 28.8 | rules | partial; fixture without declared runtime deps; no application source code | completed_rules |
| [artifact_graph/lab-npm](https://bitbucket.org/artifact_graph/lab-npm) | JavaScript | 8f542c549cc5 | sha256:09bcf5667092 | 0 | 292 | 277/0/4 | 288 | True/True | True | 28.3 | rules | partial; fixture without declared runtime deps | completed_rules |
| [artifact_graph/python-service](https://bitbucket.org/artifact_graph/python-service) | Python | 973b5e3447f9 | sha256:7b3a96cacdc2 | 0 | 120 | 109/0/6 | 114 | True/True | True | 49.2 | rules | partial; fixture without declared runtime deps | completed_rules |
| [artifact_graph/python-jobs](https://bitbucket.org/artifact_graph/python-jobs) | Python | 776eb037886b | sha256:ed9c816f27d0 | 0 | 120 | 109/0/6 | 114 | True/True | True | 40.3 | rules | partial; fixture without declared runtime deps | completed_rules |
| [artifact_graph/lab-python](https://bitbucket.org/artifact_graph/lab-python) | Python | 93428e3aabeb | sha256:88a82d9a3868 | 0 | 119 | 108/0/6 | 113 | —/— | True | 31.5 | rules | partial; fixture without declared runtime deps | completed_rules |
