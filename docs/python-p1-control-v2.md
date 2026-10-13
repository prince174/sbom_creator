# R15 — дополнительный контроль Python P1: HTTPX

2026-10-13. Исходное состояние main 5c87b9a, чистое дерево; benchmark-процессов нет.
Рабочий runtime **0.6.0 не менялся**. Это расширение проверки прототипа, не
улучшение алгоритма. P1 и guard сверены с SHA, сохранёнными до чтения исходника
в этом этапе, и не изменялись.

| Проект | TP | FP | FN | Precision | Recall | F1 | Точные версии | UNKNOWN | Покрытие деклараций |
|---|---:|---:|---:|---:|---:|---:|---|---:|---:|
| HTTPX 0.28.1 | 4 | 0 | 0 | 100% | 100% | 100% | 4/4 | 0 | 100% |

Прямые зависимости: **anyio 4.15.1**, **certifi 2026.7.22**,
**httpcore 1.0.9**, **idna 3.20**. Версии совпадают между предсказанием,
CycloneDX root graph и установленными METADATA. Транзитивные зависимости
не добавлены в прямые. Extras не выбраны. Build dependencies не являются
runtime direct. Владельцем четырёх рёбер выступает корневой pyproject.toml.

Версия самого HTTPX в CycloneDX отсутствует (dynamic version): её точность
относительно эталона UNKNOWN. Установленная версия 0.28.1 отдельно сохранена.
P1 с guard выдаёт полностью то же предсказание, что исходный P1.

## Воспроизводимость и ограничения

- [Выбор проекта](../benchmarks/python-control-v2.json): commit
  `26d48e0634e6ee9cdc0533996db289ce4b430177`, вне исходных 60 проектов.
  HTTPX выбран целенаправленно как HTTP client до просмотра source в этом этапе.
  При clone обнаружен существующий cache и прежний source Syft scan: checkout
  проверен чистым, используется его отдельный clean clone для парной сборки.
  Строго слепой контроль не заявляется; прежняя доступность исходников раскрыта.
- Hatchling 1.27.0, hatch-fancy-pypi-readme 24.1.0, CycloneDX 7.5.0;
  CPython 3.12.15 Linux/amd64 без extras. Base image закреплён digest.
  Исходная [конфигурация сборки](https://github.com/encode/httpx/blob/26d48e0634e6ee9cdc0533996db289ce4b430177/pyproject.toml)
  использована без изменений. Backend работает только во внешней benchmark-сборке.
- Первая попытка указала несуществующий readme plugin 24.2.0 и завершилась
  ошибкой resolver. Исправлен только pin на существующий 24.1.0; исходный
  Dockerfile и журнал ошибки сохранены локально с суффиксом failed-readme-version.
- Wheel собран реально. Builder и runtime /project равны по дереву файлов;
  OCI/config и hashes проверены. Generator/reference не передаются анализатору.
  Три CycloneDX schema validation passed: final21 / OS106 / full127.
- Версии зависимостей разрешены при сборке, hashes wheel и pip inspect сохранены;
  fresh network rebuild может выбрать другие версии. Повторная оценка использует
  сохранённые `.work/paired-httpx-v1` артефакты. Peak resources не измерены;
  prediction time и reconciliation time в JSON не являются полным build time.
- 34 unit tests, Ruff, actual build, revalidation passed. Runtime files неизменны;
  full runtime suite не повторялся. Старые immutable references не изменены.

Вместе с R13 контроль содержит 9 совпавших прямых рёбер на двух положительных
проектах и один пустой проект. Это малая целевая выборка, не общая Python accuracy.
Flask UNKNOWN1 и declaration coverage83.33% сохраняются; HTTPX их не отменяет.

```powershell
.venv/Scripts/python.exe -X utf8 benchmarks/evaluate_python_control_v2.py
.venv/Scripts/python.exe -m pytest benchmarks/test_paired_python.py benchmarks/test_python_p1_guard.py benchmarks/test_python_direct_p1.py -q
```

[Результат](python-p1-control-v2.json),
[эталон](../benchmarks/references/paired-httpx-v1/sbom.json).
Следующий этап: bounded pyproject loader, общий бюджет входов и проверка
интеграции Python evidence без изменения inventory и трёх выходных SBOM.
