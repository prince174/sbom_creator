# R14 — проверка недоверенных входов Python P1

2026-10-13. Начало: 2ca56a1, чистое дерево; активных benchmark/pytest процессов нет.
Рабочий runtime 0.6.0 не менялся. Frozen P1 SHA сохранён. Guard существует
только в benchmarks и не является готовой production-интеграцией.

Гипотеза: передача некорректных типов/ID в P1 может привести к исключению
или невалидному ребру. 17 синтетических случаев: один валидный и 16 мутаций.
Исходный P1: 11 исключений, 2 DIRECT с null/повторным artifact ID, 3 UNKNOWN.
Это аудит robustness, не измерение precision и не доказательство достижимости
в реальном pipeline. Syft JSON здесь намеренно изменён; эксплуатация не проверялась.

Experimental guard проверяет типы используемых полей, уникальность непустых ID,
ограничения строк/списков. Некорректный вход целиком возвращает UNKNOWN с
coverage=null, без эха исходных значений. Не пропускает испорченный artifact:
его удаление могло бы скрыть неоднозначность и породить ложный DIRECT.
После guard: 0 исключений и 0 DIRECT на 16 некорректных входах.

Сохранённые Jinja/Flask/Packaging: предсказания guard и frozen P1 равны полностью,
включая версии, artifact ID, причины, UNKNOWN. Проверены hashes входов/receipt;
на Flask/Packaging повторены tree/OCI/native metadata/три схемы. Jinja в этом
этапе проверен по hashes входов, без повторной полной tree/schema проверки.
Контроль Flask: TP5 FP0 FN0, UNKNOWN1, declaration coverage 83.33%; Packaging
пустой, метрики null. Jinja development DIRECT1 UNKNOWN0. Рост accuracy не заявлен.

29 unit tests, Ruff, реальный replay прошли. Новые сборки не запускались.
Время/пиковые ресурсы и большие входы на границах лимитов полностью не измерены.
Guard не полная валидация PyPA/Syft schemas и не защита JSON/TOML-парсера до
получения объектов. Для runtime ещё нужны ограниченный loader, проверка файлов,
общий бюджет входа/строк и независимая положительная выборка до интеграции.

Типы project.name/version/dependencies сверены с официальной
[спецификацией PyPA](https://packaging.python.org/en/latest/specifications/pyproject-toml/).
Ограничения размера — экспериментальные локальные решения, не требования PyPA.

```powershell
.venv/Scripts/python.exe -X utf8 benchmarks/audit_python_p1_inputs.py
.venv/Scripts/python.exe -X utf8 benchmarks/verify_python_p1_guard.py
.venv/Scripts/python.exe -m pytest benchmarks/test_python_p1_guard.py benchmarks/test_python_direct_p1.py -q
```

[Исходный аудит](python-p1-input-audit-v1.json), [сравнение](python-p1-guard-v1.json).
Следующее: независимый положительный Python-контроль, без подбора правил на
раскрытых Flask/Packaging; затем ограниченный manifest loader и интеграционные
проверки. Ранжирование конкурентов не меняется.
