# R37 — Go G1 declared/binary candidates

2026-10-14. Один paired development hey, runtime0.7.0 неизменён.

Source Syft go.mod catalog содержит только x/net и x/text, без module owner и
dependency graph. Image Syft указывает оба как dependency-of hey и также stdlib.
Поэтому все image edges нельзя автоматически считать прямыми зависимостями.

Прототип читает ограниченный literal go.mod и исключает require // indirect.
Требует единственный root buildinfo owner, matching mainModule и exact
vcs.revision, vcs.modified=false; target должен иметь ту же binary location,
mainModule и версию. Это corroboration source declaration/compiled membership.
Commit metadata не криптографическая аттестация; произвольный binary metadata
может быть подделан. Отсутствие indirect не доказывает прямое использование
именно данным main package, scope/build tags/import graph остаются неизвестными.

Hey: кандидат x/net версии v0.0.0-20181017193950-04a2e542c03f совпал с одним
CDX direct edge. x/text v0.3.0 помечен indirect и исключён. Кандидатов1,
лишних0, отсутствующих reference candidates0. Не direct accuracy: prediction
имеет direct_edge_proven=false, один development sample не control.

replace/exclude/toolchain/неподдерживаемый синтаксис, неоднозначный владелец,
wrong/dirtycommit дают UNKNOWN. Это узкий experimental parser валидных
каталогов, не production input guard и не полный Go grammar. Workspace вне
go.mod ещё не проверяется; не применять G1 к workspace без отдельной проверки.

10tests и Ruff passed: positive candidate,6binary/commit/owner/version negatives,
3unsupported directives. Reference читается после prediction, hashes inputs
и reference проверены. Runtime/эталоны не менялись.

```powershell
.venv/Scripts/python.exe -X utf8 -m pytest benchmarks/test_go_g1_candidates.py -q
.venv/Scripts/python.exe -X utf8 benchmarks/evaluate_go_g1.py
```

Семантика indirect сверена с [Go modules reference](https://go.dev/ref/mod#go-mod-file-require).
Следующее: контролируемый случай, где non-indirect модуль связан с другим
main/test/build tag, а в binary остаётся транзитивно. Проверить FP до принятия
source/binary presence за прямоту. [Данные](go-g1-candidates-v1.json).
