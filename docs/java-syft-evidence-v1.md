# R22 — доступность Java evidence в Syft1.51.1

2026-10-13, mainfb3123e, clean, активных benchmark нет. Runtime0.7.0 неизменен.
Аудит только development Commons Text, без новой сборки и без чтения holdout.

| Данные | Наблюдение |
|---|---|
| Source Syft dependency-of | 13рёбер к Commons Text:12scope=test,1scope не задан |
| Raw root POM dependencies | 8деклараций в R20:7test,1безscope |
| Image Syft dependency-of | 0 |
| Image JavaPomProject | path,parent,groupId,artifactId,version,name,description,url |
| Embedded pom.xml Commons Text | побайтово равен исходному POM |
| Direct accuracy | не измерена |

В source relationship поля parent/child здесь указывают dependency/owner,
а не направление owner→dependency в CycloneDX. Направление подтверждено
сопоставлением ID с именами из каталога; копировать рёбра без преобразования нельзя.

Схема Syft16.1.10 в репозитории и фактический image JSON не содержат dependencies
в JavaPomProject. Нельзя получить аналог Python Requires-Dist простым чтением
этого объекта. MANIFEST Import-Package тоже не означает Maven direct GAV.
Полный embedded POM имеется внутри JAR, но текущий JSON хранит лишь часть полей.

У нетестового commons-lang3 source Syft version3.17.0; raw POM использует
`${commons.lang3.version}`, scope отсутствует. Это кандидат для будущего J1,
не доказанное предсказание runtime direct: inherited dependencyManagement и
активные profiles ещё не обработаны. Effective scope в аудите null. Эталон
R21 подтверждает compile scope только в фиксированном build-профиле, и не может
служить подсказкой анализатору. Embedded/source byte equality подтверждает
совпадение файла, но не все параметры сборки, flags или происхождение image.

Source граф имеет больше рёбер, чем root declarations. Поэтому ни все source
relationships, ни все image packages нельзя объявить прямыми runtime-зависимостями.
Разница не записана как FP: без согласованного scope это было бы неверной метрикой.

Проверены SHA source/image catalogs и root POM из immutable receipt; повторная
R21 проверка tree/OCI/native/effectivePOM/JAR/3схем прошла. Ruff passed.
Аудит read-only, runtime implementation/tests не менялись. Нет оценки peakRAM.
Попытка получить предполагаемый upstream java_archive.go URL дала404; выводы
основаны на сохранённых фактических каталогах и bundled schema, не на этом URL.

```powershell
.venv/Scripts/python.exe -X utf8 benchmarks/audit_java_syft_evidence.py
.venv/Scripts/python.exe -X utf8 benchmarks/verify_paired_commons_text.py
```

[Машинный отчёт](java-syft-evidence-v1.json).
Следующее: J1 как отдельный development-прототип, source relationship + raw POM
owner/declaration + однозначный image GAV. Неопределённые scope/profile/parent
оставлять UNKNOWN; сначала синтетические counterexamples наследования и профилей.
Не добавлять effective POM/CycloneDX к входам сервиса и не исполнять Maven в runtime.
