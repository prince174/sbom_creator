# R43 — первый fixed Go control G2

2026-10-14. Httprobe v0.2, commit7e8abdb4096ab224f21616478b699b4dfda9d409.
Проект из fixed holdout; G2 SHA проверены до чтения/сборки, правила не менялись.
Selection сохранён в benchmarks/go-control-g2-v1.json. Это не blind test:
R1/R2 данные ранее просматривались до разбиения. Новая парная сборка независима
от development Hey и synthetic derivative.

Go1.24.13 pinned image, linux/amd64 CGO0, buildvcs true, Linuxcleancheckout.
CycloneDX-gomod1.12.0 app, native go list и binary metadata сохранены.
Binary builder/runtime совпадают, OCI/config/Syft binding проверен.

У проекта нет внешних modules: native main graph0, CDXdirect0. G2 тоже0,
FP0. Precision/recall=null: пустая выборка проверяет отсутствие выдуманных
рёбер, но не увеличивает число подтверждённых positive direct dependencies.
Service inventory2/OS0/full2 включает application+stdlib, это не2direct deps.

Первый pair harness упал на отсутствии components в валидном emptyCDX.
Исправлен только benchmark helper: default components=[]; frozen G2 не менялся.
Повторная обработка завершена, original Hey verifier тоже проверяется отдельно.
Runtime0.7.0 и production tests не затронуты.

4schema/hash/tree/OCI/freeze/empty-result checks и Ruff прошли.
Receipt5b58b66cb5b13c0771223376d4f1bc6893bc077fb91065e332be53ae2a3697eb.
Inputs analyzer — source+runtime image, native/CDX не передаются в prediction.
Binary entry изruntimeexported payload, modules=None корректно трактуется как
пустой dependency list в benchmark harness, не новая heuristic G2.

```powershell
.venv/Scripts/python.exe -X utf8 benchmarks/verify_go_control_httprobe.py
```

Следующее: positive Go control до принятия G2, либо расширение Rust/Ruby paired
корпуса. Не подбирать правила по holdout; unsupportedcontext сохранять как отказ.
[Результаты](go-control-httprobe-v1.json).
