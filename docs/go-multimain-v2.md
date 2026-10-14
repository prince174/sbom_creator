# R39 — чистая повторная Go multimain сборка

2026-10-14. Тот же synthetic commit fdd5b9f1f43b4a549a1eb3e2da2fd7fe664a462c,
новый namespace, предыдущие R38 outputs неизменны.

Checkout создан без автоматического CRLF-преобразования; в Linux builder
сохранён git status, выполнен reset к HEAD с core.autocrlf=false и проверен
пустой status. Бинарник подтверждает exact revision и vcs.modified=false.
Два изменения условий применены вместе; причина R38 dirty не изолирована.

| Вид связи | Эталон | G1 кандидаты |
|---|---|---|
| Direct declarations корня модуля |x/net, x/text|оба совпали|
| Direct package imports выбранного main |x/net|x/text лишний для этой цели|

CDX app root graph согласуется с декларациями всего модуля, native go list
-deps выбранного main подтверждает только x/net. Другой main импортирует x/text
прямо; в выбранном binary x/text присутствует транзитивно. Таким образом,
manifest non-indirect + compiled presence + exact commit недостаточны для
прямоты выбранного приложения. Это целевой counterexample G1, не общий precision.

G1 сохраняет direct_edge_proven=false. Его нельзя внедрять как классификатор
selected-main direct dependencies. Для module-declared цели совпадение2/2
полезно, но область должна быть обозначена явно. Runtime0.7.0 не менялся.

Builder/runtime trees, OCI/config/Syft binding, reference и final/OS/full
schema прошли; inventory4/0/4. Runtime binary не исполнялся. SHA receipt:
a4668847e13d8205a2bfe4d8d4e6d6e5eb21361f43ba0d3583b78d3c60a2922a.
Source/main import graph/reference read после candidate prediction.

```powershell
.venv/Scripts/python.exe -X utf8 benchmarks/verify_go_multimain_clean.py
```

Следующее: G2 должен извлекать imports и учитывать binary build settings
GOOS/GOARCH/tags, различать владельца module/main. Неподдерживаемые условия
UNKNOWN. Начать со статического subset без исполнения проекта, после —
сравнить Hey и этот counterexample, затем независимую control пару.
[Машинный отчёт](go-multimain-v2.json).
