# R38 — отрицательный результат multimain эксперимента

2026-10-14. Синтетический derivative hey: добавлен cmd/other, напрямую
импортирующий x/text/unicode/norm; у x/text убран indirect. Основное приложение
и его imports не менялись. Отдельный локальный fixture commit сохранён в report.
Это не второй upstream проект.

| Проверка | Результат |
|---|---|
| Native imports выбранного main . | x/net direct |
| Binary module list | x/net и x/text |
| CDX app root module edges | x/net и x/text |
| Binary VCS metadata | vcs.modified=true |
| G1 | UNKNOWN/unconfirmed_commit |

Два ограничения делают прогон непригодным для direct accuracy.
Во-первых, CDX root-module declarations отличаются от прямых импортов
выбранного приложения. Ранее hey R36 давал совпадение, но этот случай показывает,
что оно не является общей гарантией generator app graph. Присутствие компонента
в binary и module-root edge не устанавливает связь с конкретным main.

Во-вторых, host checkout чистый, но build binary сообщает modified=true.
Причина пока не установлена; Git line endings/index внутри Linux builder
требуют проверки. Не объявлять binary чистым по host git status. G1 воздержался,
поэтому реальный FP классификатора этим прогоном не доказан.

Immutable outputs не заменялись после обнаружения. Audit report явно ставит
eligible_for_direct_accuracy=false. R36 reference по-прежнему прошёл revalidation.
Builder/runtime binary trees и image binding прошли стандартный pair harness,
final4/OS0/full4. Это pairing присутствия, не пригодность direct labels.
Ruff и hashes аудит прошли; runtime0.7.0 не менялся.

```powershell
.venv/Scripts/python.exe -X utf8 benchmarks/audit_go_multimain.py
```

Следующее: новый namespace clean fixture с Linux checkout перед сборкой;
сохранить git status перед go build. Затем отдельно размечать module direct
и selected-main import direct, не подменять один другим. До этого G1 остаётся
кандидатным фильтром.
[Прогон](go-multimain-v1.json), [аудит пригодности](go-multimain-audit-v1.json).
