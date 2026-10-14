# R41 — entry package из image binary

2026-10-14. External experimental helper, runtime0.7.0 неизменён.

Из единственного OCI-слоя двух пар прочитан regular binary по location Syft.
Проверены OCI index/manifest/config, layer size/SHA, limit128MiB layer,
10000entries,64MiB binary. Archive paths не извлекаются на filesystem как пути
из tar: выбранные bytes записываются в заранее определённый benchmark файл.
Reader поддерживает только эти single-layer fixtures; multi-layer/whiteouts,
symlinks/hardlinks и malformed catalog generalization ещё не реализованы.

Go debug/buildinfo.ReadFile читает Path входного пакета и Main.Path модуля,
не исполняя бинарник. Оба target binaries дают:

| Pair | Entry Path | Main.Path | Source dir |
|---|---|---|---|
| HeyR36 |github.com/rakyll/hey|github.com/rakyll/hey|.|
| MultimainR39 |github.com/rakyll/hey|github.com/rakyll/hey|.|

Это снимает неоднозначность двух main directories R40 для конкретного image
без reference main path. Commit и cleanflag проверены; metadata не является
криптографическим доказательством происхождения. Сам extracted entry также
ещё не direct dependency graph. Direct metrics null, pipeline не интегрирован.

Reference receipt используется после extraction только для pairing check,
не как подсказка entry path. Read inputs — image archive и Syft image catalog.
Build-info.txt эталона не читается. SHA binary/helper/source сохранены в report.
Обе пары прошли extraction и Ruff; invalidbinary helper отвергнул.

```powershell
.venv/Scripts/python.exe -X utf8 benchmarks/audit_go_binary_entry.py
```

Предусловие: go_binary_info.go собран Windows/amd64 Go1.24.13 в info.exe
в benchmarks/.work/go-binary-info-r41. Builder base digest изR36, отдельный
helper build не запускает код проекта. Никаких runtimeGo/Docker requirements
в сервис не добавлено.

API: [ReadFile](https://pkg.go.dev/debug/buildinfo#ReadFile),
[BuildInfo Path](https://pkg.go.dev/runtime/debug#BuildInfo).
Следующее: связать entry с platform-selected source AST imports; рекурсивно
обойти только пакеты root module, внешние модули сопоставить по binary list.
Test/другой main не включать; unsupported flags/workspace/replaces UNKNOWN.
[Машинный результат](go-binary-entry-v1.json).
