# R10: Python development declarations, 2026-10-13

Проверены 8 development-проектов по точным Git blob на закреплённых commit.
Исходники и эталоны Flask/Packaging из holdout в этом этапе не читались.
Это аудит готовности входных данных, не классификатор и не измерение точности.

| Группа | Проекты | Результат |
|---|---|---|
| Непустые статические runtime-декларации | Jinja, Werkzeug | По одному MarkupSafe; набор имён совпал с корнем R1 |
| Пустые статические runtime-декларации | Bitbucket service/jobs, ItsDangerous, attrs | Пустой набор совпал с корнем R1; это не 100% precision |
| Нет pyproject.toml на исходном commit | Bitbucket lab, certifi | UNKNOWN для этого подхода; пустой R1 не превращён в отсутствие зависимостей |

Два Bitbucket-проекта имеют одинаковый SHA256 pyproject, а оба положительных
проекта зависят от одной библиотеки. Разнообразие development-выборки ограничено.
Совпадение имён не проверяет версии, markers, extras, происхождение или парность
образа. Все image_pair_verified=false; precision/recall остаются null.
[JSON с commit/hash](python-declarations-v1.json).

## Гипотеза следующего этапа

Для Python сначала связывать статические project.dependencies с корневой
установленной distribution и её окружением в образе. Требования build-system
не переносить в runtime; optional groups и conditional requirements учитывать
только при известном профиле/окружении. Не использовать Python-окружение самого
анализатора как замену целевой платформы. setup.py не исполнять в runtime.
Отсутствующий project или dynamic dependencies оставлять UNKNOWN.

Основание: [PyPA pyproject specification](https://packaging.python.org/en/latest/specifications/pyproject-toml/)
разделяет build-system и project metadata, включая dynamic поля;
[dependency specifiers](https://packaging.python.org/en/latest/specifications/dependency-specifiers/)
определяет extras и environment markers. Версия этой спецификации проверена
2026-10-13; наличие статического префикса рядом с dynamic не доказывает полноту.

Следующий конкретный шаг — новая парная сборка Jinja на commit
877f6e51be8e1765b06d911cfaa9033775f051d1: wheel, установка в отдельное venv,
CycloneDX 7.5.0 из этого окружения, runtime с тем же venv и зафиксированным Python
image digest. Сверить wheel METADATA/Requires-Dist и root graph эталона, оставить
эталон вне входов анализатора. Это development; контрольные пары позже,
после фиксации Python-классификатора. Старый образ не объявлять парным: R2 уже
обнаружил расхождение версии MarkupSafe между R1 и старым образом.

Проверки: 5 тестов различения static/dynamic/empty/build/markers/extras,
Ruff, полный аудит 8 development. Скрипт не исполняет код проектов, читает
pyproject из git show commit:path. URL требований не сохраняются, только счётчики.
Runtime 0.6.0 и прежние SBOM не изменены.

```powershell
python benchmarks/audit_python_declarations.py
python -m pytest benchmarks/test_python_declarations.py -q
```

Для повторения требуется локальная benchmark-выборка и dev-зависимость packaging
(парсер Requirement); новая runtime-зависимость не добавлена.
