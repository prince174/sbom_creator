# R31 — самостоятельный source graph Syft1.51.1

2026-10-14. Повторный разбор неизменяемых source catalogs двух paired development
проектов. Новый scan не запускался. Owner выбран по module location и pomProject
до чтения reference; image и J1 model resolver не используются.

| Проект | Raw edges | Совпали GAV с runtime reference | Остальные GAV | После фильтра explicit scopes |
|---|---:|---:|---:|---:|
| Gson |4|1|3|1совпадение|
| Commons Text |13|1|12|1совпадение|

Все15прочих связей имеют raw test scope. Это не15ошибок Syft: runtime reference
не включает тестовые зависимости. В отдельном экспериментальном адаптере
исключаются только explicit test/provided/system. Оставшиеся2GAV совпадают
с2эталонными рёбрами, версии совпадают2/2, но raw scope обоих отсутствует.
Пустой scope не превращён в доказанный compile. Direct precision/recall null.

R30 J1 оставлял1кандидата из2из-за неразрешённого parent Commons Text.
Простой adapter даёт2/2совпадения, но не проверяет effective model и scope.
Это не честное доказательство превосходства: сила утверждений различается.
Нужен парный отрицательный пример с inherited provided/profile before acceptance.
Контроль не использовался, runtime не изменён, места не присвоены.

Raw и filtered результаты разделены: фильтр принадлежит этому benchmark,
а не является заявленной гарантией Syft. Общие возможности Syft описаны в
[официальной документации](https://oss.anchore.com/docs/guides/sbom/);
числа получены из сохранённых каталогов1.51.1 и SHA-проверенных references.

Один unit test покрывает извлечение, сохранение unspecified/effective UNKNOWN,
test filtering и duplicate IDs; Ruff passed. Это ограниченный исследовательский
адаптер валидных каталогов, не production parser malformed input.

```powershell
.venv/Scripts/python.exe -X utf8 benchmarks/evaluate_syft_java_source_baseline.py
.venv/Scripts/python.exe -X utf8 -m pytest benchmarks/test_syft_java_source_baseline.py -q
```

Следующее: прогнать Syft source на R29 synthetic inherited/override/profile
cases и сравнить сохранение scope с реальной сборкой. Это проверит конкретный
риск простого adapter до расширения J1. [Данные](syft-java-source-baseline-v1.json).
