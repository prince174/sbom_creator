# Проверка реализации

Версия 0.4.0 разделяет основной и системный SBOM. Проверки: [Windows](verification-0.4.0-windows.xml), [Linux](verification-0.4.0-linux.xml), [сквозной API](verification-http-v0.4.json), [разделение 60 сохранённых результатов](verification-inventory-views-v1.json). Принцип и ограничения описаны в [README](../README.md).

Историческая версия 0.3.0 без модели: [изменения и новые проверки](rules-v3.md).
Предыдущий этап: [0.2.0](rules-v2.md).
Ниже сохранены исторические свидетельства версии 0.1.0; описанное требование
модели больше не относится к основному API/CLI.

30 сентября 2026, Asia/Yekaterinburg. Проверка инфраструктуры и правил отбора;
отдельная модель пользователя ещё не настроена, её качество не измерялось.

| Проверка | Результат | Свидетельство |
|---|---|---|
| Windows, Python, полный pytest | 160 passed, 1 skipped | [JUnit](verification-pytest-windows.xml) |
| Linux, установленный пакет в финальном Docker-образе, полный pytest | 161 passed | [JUnit](verification-pytest-linux.xml) |
| Ruff, src/tests/benchmarks/scripts | Passed | `python -m ruff check src tests benchmarks scripts` |
| Linux HTTP API, без внешней сети и модели | Passed | [Статусы и хеши 10 модулей](verification-installed-linux.json) |
| Registry → Syft → rules → CycloneDX в установленном Linux-пакете | Passed; 16 компонентов, 1 UNKNOWN | [Образ, хеши, счётчики](verification-package.json) |
| Wheel: все Python-модули совпадают с src, 4 JSON schemas включены | Passed | [Проверка упаковки](verification-package.json) |
| Bitbucket Cloud, точный commit | Passed | [Свидетельства получения](verification-acquisition.json) |
| 60 репозиториев, по 10 на язык, source/image → rules → CycloneDX | 60 completed_rules | [Все строки](../benchmarks/results/run-20260929/results.md) |
| Независимый аудит финального benchmark, replay текущих правил | 60/60; 0 ошибок, 0 предупреждений | [Аудит](../benchmarks/results/run-20260929/audit-final.json) |
| Запуск бинарников Rust и Go в ограниченном контейнере | 20/20; image IDs совпадают с отчётом | [Runtime smoke](../benchmarks/results/run-20260929/runtime-smoke.json) |
| Локальный ZIP: 60 финальных SBOM и компактные свидетельства | CRC и SHA-256 всех записей проверены | [Хеш архива](benchmark-export.json) |

Windows пропускает проверку escaping symlink из-за прав ОС; эта проверка проходит
в Linux. Предупреждение Starlette о будущей замене транспорта TestClient на httpx2
не является ошибкой тестов.

Linux suite запускался без монтирования `src` и без `PYTHONPATH`: тесты использовали
пакет из `/usr/local/lib/python3.12/site-packages`. Отдельный verifier сверяет
фактические пути и SHA-256 с read-only копией ожидаемых исходников. `/health=200`
не используется как доказательство готовности Git, registry или модели.

Повторение проверки установленного сервиса:

```powershell
docker build -t sbom-creator:0.1.0 .
docker run --rm --network none `
  --mount 'type=bind,source=G:/code/sbom_creator/scripts/verify_linux.py,target=/verify_linux.py,readonly' `
  --mount 'type=bind,source=G:/code/sbom_creator/src,target=/expected-src,readonly' `
  --mount 'type=bind,source=G:/code/sbom_creator/docs,target=/verification' `
  sbom-creator:0.1.0 python /verify_linux.py --expected-root /expected-src `
  --output /verification/verification-installed-linux.json
```

Проверка блокировки результата использует реальный HTTP API и pipeline: без
настроенной модели задание `202 → failed`, артефакт недоступен (`409`), final-файл
отсутствует. Unit/integration tests дополнительно проверяют сбои checkout/scan,
контракт оценок, порог 70, повторные ошибки, schema и ссылки CycloneDX. Отдельно
проверяется сохранение имени, версии, PURL и qualifiers при экспорте; подменённый
кэш не принимается как новый успешный прогон. LLM-транспорт использует тестовые
ответы и не считается испытанием реальной модели.

Registry smoke использует искусственный source fixture и Alpine; он проверяет
транспорт и публикацию, но не связь реального приложения с образом. Файлы лежат
в `workspace/linux-installed-smoke-v3`, отдельно от более ранних диагностических
запусков. Реальные репозитории и контролируемые сборки отражены в
[таблице 60 проектов](../benchmarks/results/run-20260929/results.md).

Счётчики компонентов и ограниченная проверка release-идентичности приложения
не заменяют полную независимую разметку зависимостей. Поэтому FP/FN и качество
LLM не заявляются.

В финальной матрице 57 публичных проектов GitHub и 3 существующих Python fixtures
из Bitbucket; во всех 60 checkout подтверждены реальные исходники соответствующего
языка. Все прогоны используют явный режим `rules`. Их 10 255 финальных записей
соответствуют 10 089 принятым идентичностям: один пакет может иметь несколько
расположений. 2360 идентичностей получили UNKNOWN и не вошли в финальные SBOM,
поэтому coverage всех 60 результатов — `partial`.

Точная release-идентичность основного пакета подтверждена для 54 из 59 применимых
случаев. Четыре Go-сборки содержат реальные pseudo-versions, одна не содержит
module identity; обычный Python script не имеет применимой пакетной идентичности.
Эти ограничения отражены в таблице и не скрываются общим статусом завершения.

Архив `dist/sbom-creator-60-cyclonedx.zip` содержит проверенные `final.cdx.json`,
summary, coverage и provenance каждого проекта, общие отчёты и `SHA256SUMS`.
Он остаётся локальным артефактом; большие checkout, образы, полные каталоги Syft
и decisions сохранены локально в `benchmarks/.work` и Docker. В Git публикуются
код, рецепты, манифесты и компактные отчёты. Финальный аудит привязан к SHA-256
конкретного `results.json`, хеши каждого SBOM проверены при упаковке.
