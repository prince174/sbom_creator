# R40 — main selection stage G2

2026-10-14. Experimental external helper, service0.7.0 не меняется.

Image Syft go-module-buildinfo-entry хранит mainModule, но не import path
входного main package. Поэтому module identity недостаточна в multimain repo.
Индекс через standard go/parser + go/build.MatchFile строится только по source,
GOOS/GOARCH/CGO из binary metadata, без исполнения проекта или go list.

| Выборка | Main directories | Вывод |
|---|---|---|
| Hey R36 | . | UNIQUE_SOURCE_CANDIDATE |
| Multimain R39 | ., cmd/other | UNKNOWN/ambiguous_main |

Это не новый direct classifier и не рост accuracy. Даже единственный main
пока кандидат: binary entry path не извлечён. На multimain этапе нет output
edges; такая потеря coverage должна учитываться явно и не принимается молча.

Helper собран Go1.24.13, той же версией, что binaries: иначе release tags
не могут считаться сопоставимыми. Custom tags и CGO!=0 не поддерживаются.
Vendor/.git/hidden dirs и nested modules исключены. Symlinks отвергаются.
Бюджет10000Go files,1MiB/file,16MiB суммарно; внешний timeout30s.
Тестовые файлы исключаются, OS filename/build constraints учитывает go/build;
import C при CGO0 исключается. Это ограниченный development subset, не полный
workspace/toolchain/fuzz/test-main resolver. Нужен отдельный guard перед runtime.

Fixture проверила comments, inactive _windows.go, _test.go и import C:
сохранился единственный ожидаемый main. Actual source parser/helper build,
fixture и Ruff прошли. SHAhelper/source сохранены. Build helper только внешний
benchmark, в сервис Go/toolchain не добавляется.

Для воспроизведения собрать go_source_index.go как Windows/amd64 helper
на pinned Go1.24.13 image R36, сохранить index.exe в
benchmarks/.work/go-source-index-r40, затем:

```powershell
.venv/Scripts/python.exe -X utf8 benchmarks/audit_go_main_selection.py
```

Источники: [MatchFile](https://pkg.go.dev/go/build#Context.MatchFile),
[ParseFile](https://pkg.go.dev/go/parser#ParseFile).
Следующее: извлекать debug/buildinfo.Path из binary payload, который уже
находится в image. Это часть существующего image input; reference build-info
использовать только для оценки. После связывания main — source import graph.
[Машинный отчёт](go-main-selection-v1.json).
