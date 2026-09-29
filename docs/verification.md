# Проверка реализации

30 сентября 2026, Asia/Yekaterinburg. Проверка инфраструктуры и правил отбора;
отдельная модель пользователя ещё не настроена, её качество не измерялось.

| Проверка | Результат | Свидетельство |
|---|---|---|
| Windows, Python, полный pytest | 136 passed, 1 skipped | [JUnit](verification-pytest-windows.xml) |
| Linux, установленный пакет в финальном Docker-образе, полный pytest | 137 passed | [JUnit](verification-pytest-linux.xml) |
| Ruff, src/tests/benchmarks/scripts | Passed | `python -m ruff check src tests benchmarks scripts` |
| Linux HTTP API, без внешней сети и модели | Passed | [Статусы и хеши 10 модулей](verification-installed-linux.json) |
| Registry → Syft → rules → CycloneDX в установленном Linux-пакете | Passed; 16 компонентов, 1 UNKNOWN | [Образ, хеши, счётчики](verification-package.json) |
| Wheel: все Python-модули совпадают с src, 4 JSON schemas включены | Passed | [Проверка упаковки](verification-package.json) |
| Bitbucket Cloud, точный commit | Passed | [Свидетельства получения](verification-acquisition.json) |

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
контракт оценок, порог 70, повторные ошибки, schema и ссылки CycloneDX.

Registry smoke использует искусственный source fixture и Alpine; он проверяет
транспорт и публикацию, но не связь реального приложения с образом. Файлы лежат
в `workspace/linux-installed-smoke-v2`, отдельно от более ранних диагностических
запусков. Реальные репозитории и контролируемые сборки отражены в
[таблице 60 проектов](../benchmarks/results/run-20260929/results.md).

Счётчики компонентов и ограниченная проверка release-идентичности приложения
не заменяют полную независимую разметку зависимостей. Поэтому FP/FN и качество
LLM не заявляются.
