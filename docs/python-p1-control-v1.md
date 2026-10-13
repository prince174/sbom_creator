# R13: Python P1.0 — контрольные парные сборки

Дата: 2026-10-13. Runtime остаётся **0.6.0**, Python P1 ещё не интегрирован.
Это проверка замороженного прототипа, а не улучшение рабочего алгоритма.

| Проект | TP | FP | FN | Precision / recall / F1 | Совпавшие версии прямых зависимостей | UNKNOWN | Покрытие деклараций |
|---|---:|---:|---:|---|---:|---:|---:|
| Flask 3.1.0 | 5 | 0 | 0 | 100% / 100% / 100% | 5/5 | 1 | 5/6, 83.33% |
| Packaging 24.2 | 0 | 0 | 0 | не определены | нет прямых зависимостей | 0 | не определено |

Flask: Werkzeug **3.1.9**, Jinja2 **3.1.6**, itsdangerous **2.2.0**,
click **8.5.0**, blinker **1.9.0**. Все пять версий совпадают с CycloneDX
и установленными METADATA. MarkupSafe — транзитивный, не добавлен в прямые.
Корневая версия Flask 3.1.0 тоже совпадает. Корневая версия Packaging в
CycloneDX отсутствует: UNKNOWN, хотя установленный пакет имеет версию 24.2.

`importlib-metadata>=3.6; python_version < '3.10'` остаётся UNKNOWN у P1.
В зафиксированном профиле CPython 3.12.15 Linux/amd64 без extras она неактивна;
это не FN активного графа. Покрытие исходных деклараций отдельно показывает
ограничение: 83.33%, а не 100%. Extras и build-system не выдаются за runtime direct.

## Протокол и границы результата

- P1 SHA256 `060f4d381c5c1fb332fcec598789caca960f6514c174a131d04f95fc1c9d214f`
  неизменен после development Jinja; packaging evaluator 26.3. Исходный split
  также проверен по SHA. Flask/Packaging — исходный holdout, но не слепой:
  R1/R2 были просмотрены до разделения выборки. Правила по контролю не менялись.
- Каждый wheel собран из чистого checkout exact commit; flit_core 3.12.0,
  CycloneDX 7.5.0, базовый образ закреплён digest. Одинаковый /project перенесён
  из builder в runtime; сравнение деревьев, OCI/config binding и три схемы passed.
- Зависимости разрешены при сборке; wheel hashes, pip inspect, версии генератора
  и builder сохранены. Повторное разрешение из сети не гарантирует те же версии:
  для повторения оценки используются сохранённые образы/артефакты, а не новая
  установка latest. Wheel bytes остаются в локальном builder, не публикуются.
- Предсказание получает только source pyproject и image Syft JSON. Эталон,
  installed tar, native marker environment используются затем только оценщиком.
  Никакого исполнения проекта/marker на хосте сервиса не добавлено.
- Docker используется только внешним benchmark harness. Runtime сервиса неизменен.
- Один положительный контроль с пятью рёбрами недостаточен для общей Python
  accuracy. Пустой Packaging не увеличивает precision/recall. Пиковые ресурсы
  не измерены. В JSON отдельно время чистого P1 и reconciliation; это не время сборки.
- 16 unit tests passed; Ruff passed; обе реальные сборки и повторная проверка
  hashes/tree/metadata/OCI/трёх схем passed. Полный runtime suite не повторялся:
  production files не менялись.

Воспроизведение на сохранённых артефактах:

```powershell
.venv/Scripts/python.exe -X utf8 benchmarks/evaluate_python_control.py
.venv/Scripts/python.exe -m pytest benchmarks/test_paired_python.py benchmarks/test_python_direct_p1.py -q
```

Новые сборки выполняет `paired_python.py --project flask|packaging`;
существующий immutable receipt запрещает перезапись. Локальные входы:
`benchmarks/.work/paired-flask-v1` и `benchmarks/.work/paired-packaging-v1`.
Публикуемые эталоны: `benchmarks/references/paired-{flask,packaging}-v1`.

Следующий этап: усилить обработку недоверенных Python manifest/Syft данных,
проверить ограничения на новом независимом положительном контроле и только
затем решать вопрос интеграции P1. Не подбирать правила на Flask/Packaging.

[Машинный отчёт](python-p1-control-v1.json).
