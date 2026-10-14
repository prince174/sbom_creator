# R45 — Syft content bridge для Go binary

2026-10-15 (Asia/Yekaterinburg). Внешний эксперимент, runtime0.7.0 unchanged.

У production scanner уже есть ограниченный private file-content scan Syft
и SyftFiles reader, но globs охватывают RECORD/package.json/JAR, не произвольные
Go binaries. Эксперимент добавляет ровно один доверенно сформированный exact
path в отдельный config и читает его final/squashed содержимое тем же Syft.
Никаких Docker/socket/privileges в сервис не добавлено; Docker только fixtures.

| Pair | Payload bytes | Private Syft JSON bytes | Проверка |
|---|---:|---:|---|
| Hey |11718317|15637265|SHA совпал, inventory/graph unchanged|
| Lazygit |29263807|39096258|SHA совпал, inventory/graph unchanged|

Дополнительный synthetic image содержит2layers: сначала old Hey binary,
затем new multimain binary по тому же path. Syft вернул только final new bytes,
inventory/graph unchanged. [Overlay результат](syft-go-overlay-v1.json).
Это проверка overwrite, не whiteout/delete или произвольного overlayFS.

Raw contents остаются private в памяти и не публикуются в SBOM/отчётах.
Декодер требует regularfile, size/base64 correspondence,32MiB limit; runner
ограничивает JSON64MiB. Один exact path из ограниченного алфавита, без '..'
и glob metacharacters. Большие или отсутствующие contents дают отказ, не пустой
успешный graph. Сканированная identity проверяется production _image_identity,
config digest сравнивается с предыдущим scan перед decoding. Package artifacts
и relationships сверены побайтово как JSON structures до/после content option.

Тестировался archive backend, хотя extraction выполняет Syft, а не наш tar
single-layer reader R41. Registry/auth/two-pass tag pinning, deletedbinary,
aggregatebudget нескольких binaries и production malformed-input guard ещё
требуют отдельных проверок. Не выдавать этот протокол за полную безопасность
registry deployment. Image identities/contents не криптографическая аттестация
достоверности Go metadata внутри binary.

Все3реальных scan comparisons и Ruff passed. Новых project builds нет;
overlayimage build содержит уже готовые binaries и не исполнялся. Точность
direct deps не меняется: это acquisition compatibility, не classifier.

```powershell
.venv/Scripts/python.exe -X utf8 benchmarks/syft_go_payload_bridge.py
.venv/Scripts/python.exe -X utf8 benchmarks/check_go_payload_overlay.py
```

Следующее: закрыть deletion/oversize/registry identity cases и описать безопасную
доставку parser helper до runtime интеграции. Frozen G2 rules не менять поcontrol.
[Основной результат](syft-go-payload-v1.json).
