# R36 — первая paired Go development выборка

2026-10-14. Hey v0.1.4, commit af177063f85bd935c55f1f2ee59c2898d9654f82.
Чистый checkout из development partition. Реальный go build с Go1.24.13,
linux/amd64, CGO_ENABLED=0, buildvcs=true, GOMAXPROCS=2, без специальных tags.
Base golang1.24-bookworm закреплён digest. CycloneDX-gomod1.12.0 официальный
linux binary проверен по release SHA256, generator archive/binary hashes сохранены.

| Группа | Компонент | Версия |
|---|---|---|
| Root |github.com/rakyll/hey|v0.1.4|
| Прямая зависимость |golang.org/x/net|v0.0.0-20181017193950-04a2e542c03f|
| Транзитивная зависимость |golang.org/x/text|v0.3.0|

Native go list -deps graph: imports всех пакетов главного модуля указывают
на x/net. Build binary metadata содержит x/net и x/text. CDX root edges и
components согласованы с этими отдельными проверками. Наличие x/text в бинарнике
не превращает его в direct dependency.

Первая попытка исключала .git: приложение собралось, но generator не смог
определить main version. В повторной попытке .git передан только builder,
buildvcs включён; failed recipe/log сохранены локально. Source не изменялся.

Builder/runtime binary trees совпадают; OCI index/config/Syft config проверены.
Scratch image содержит тот же бинарник без OS packages. Его исполнение не
проверялось. Генератор и reference не копируются в runtime. Анализатор получает
source и image archive, reference/native evidence не передаются ему.

Service inventory: source2/image4, final4/OS0/full4, INCLUDE4, UNKNOWN0.
Это presence inventory, не4direct dependencies и не доказанная полнота direct.
Go direct classifier отсутствует, precision/recall null. Runtime0.7.0 unchanged.

Receipt SHA256:7728bc4edc335b883542f0eab319638a709a073ae2b7e9edfa747ce6da6b2161.
Immutable refs в benchmarks/references/paired-hey-v1. Local binary/image tar,
logs и scans в benchmarks/.work/paired-hey-v1. Peak/time сборки не измерены.

Повторная проверка SHA, native imports, binary module coordinates, OCI binding
и трёх схем прошла; Ruff прошёл.

```powershell
.venv/Scripts/python.exe -X utf8 benchmarks/verify_paired_hey.py
```

Для нового прогона нужны clean checkout того же commit, generator1.12.0
по provenance и сохранённый Dockerfile. Docker build отдельно для targets
build/runtime с iidfiles build.id/runtime.id, затем paired_hey.py экспортирует
и анализирует их. Завершённый receipt не перезаписывается.

Семантика generator app mode: build constraints должны совпадать с go build;
см. [официальную документацию](https://github.com/CycloneDX/cyclonedx-gomod).
Следующее: Go G1 по root go.mod/import evidence и installed binary metadata,
с UNKNOWN для build tags/replaces/workspaces и неоднозначных владельцев.
[Машинный результат](paired-hey-v1.json).
