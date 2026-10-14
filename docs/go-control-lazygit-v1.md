# R44 — положительный fixed Go control G2

2026-10-14. Lazygit v0.44.1, commit611fabde11d24d9acc71ee26077b9a1101f59f27.
Fixed holdout; selection и6SHA G2 сохранены до изучения содержимого.
Правила не менялись. Разбиение не blind: R1/R2 материалы ранее просматривались.

| Область | Результат |
|---|---|
| Native selected-main direct imports |33modules|
| Frozen G2 candidates |33точных совпадения,FP0,FN0|
| Версии этих33modules |33/33|
| CycloneDX module-root direct |34modules|
| CDX module edge безG2maincandidate |github.com/xo/terminfo|

Candidate P/R=100% относится только к native selected-main graph одного
положительного control проекта. Это не100% основного project/moduleCDX графа:
там остаётся1scope difference. Не считать его автоматически scanner FN или
ошибкой reference. Production0.7.0 не изменён, G2 не интегрирован.

Реальная сборка Go1.24.13 pinned image, linux/amd64,CGO0,buildvcs true,
безcustomtags. Source чистый и нормализован вLinux builder. Vendor mode
сохранён. Package/native/CDX выполнены с теми же настройками; binary clean
revision matches. CycloneDX-gomod1.12.0 officialbinary SHAverified изR36.

Первая попытка остановилась после успешных build/CDX на go list -m all:
Go запрещает all в vendor режиме. Только этот дополнительный отчёт заменён
на main-module listing; полный состав выбранной сборки сохранён packages.json
и binary metadata. Source и classifier rules не менялись. Failed logs/recipe
сохранены локально. modules.json здесь содержит только main module.

Runtime source/image scans: source93,image63, INCLUDE63/UNKNOWN30,
final63/OS0/full63. Это inventory, не63прямых зависимости.
Builder/runtime binarytrees,OCI/config/Syftbinding подтверждены; приложение
не запускалось. Nativegraph иCDX использованы только после prediction.

Повторный verifier пересчитал sourceimports, сравнил с nativegraph, проверил
binarySHA/cleancommit/receipt/OCI/4schemas/freeze. Сравнение Python tuple vs JSON
list нормализовано только в verifier; classifier неизменен.13Go tests иRuff passed.

Receipt018ddd199db86d14b849178c82eb7bce1175a39f0723c81acab638ccef0b6153.
Immutable refs в benchmarks/references/paired-lazygit-v1. Сборочный полный
package graph сохранён для owner/version аудита; peakresources не измерены.

```powershell
.venv/Scripts/python.exe -X utf8 benchmarks/verify_go_control_lazygit.py
```

Следующее: оценить требования к безопасному production подключению G2
(guard/многослойные образы/доставка parser helper) и раздельным module/main
связям. Не выдавать ещё experimental maingraph за production direct output.
Параллельно расширение Rust/Ruby должно идти без тюнинга на Go control.
[Машинный отчёт](go-control-lazygit-v1.json).
