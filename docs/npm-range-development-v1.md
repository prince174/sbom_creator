# R6: независимая проверка npm ranges, 2026-10-13

Экспериментальный Python-модуль `benchmarks/npm_range_h2.py` поддерживает только
стабильные полные x.y.z, ~x.y.z и ^x.y.z. H1.1 и production не изменены.
Это проверка функции совместимости версий, не прямых зависимостей или SBOM.

| Проверка | Результат |
|---|---:|
| Синтетические комбинации | 12 288 |
| True / False у node-semver | 666 / 11 622 |
| Расхождения кандидата | 0 |
| UNKNOWN H1.1 / кандидата на этом наборе | 4 096 / 0 |
| Unit и прежние H1.1 тесты | 56 passed |
| Precision/recall прямых зависимостей | не измерены |

Все комбинации version/lower-bound с major, minor, patch из {0,1,2,3},
для exact/tilde/caret. Нет чтения проектов, reference SBOM или holdout.
Оракул — официальный npm `semver@7.7.2`, Node v22.23.1; lock с integrity сохранён.
[Определение caret](https://github.com/npm/node-semver/tree/v7.7.2#caret-ranges-123-025-004)
использовано для отдельной реализации; проверка выполняет сам upstream-пакет.

Кандидат не является полным resolver: prerelease, build metadata, partial versions,
comparators, unions, aliases, whitespace и workspace/git specs остаются UNKNOWN.
Ограничены размер строки и числовые компоненты (не более 2^53-2), чтобы не
аппроксимировать небезопасные для npm границы. Граничные unit-тесты включают
^0.0.0, ^0.0.patch, ^0.minor.patch, Unicode digits и oversized input.
Сетка не доказывает корректность всех возможных входов.

## Воспроизведение

Восстановить закреплённый oracle в ignored workspace:

```powershell
New-Item -ItemType Directory -Force benchmarks/.work/semver-oracle-v1
Copy-Item benchmarks/references/npm-range-oracle-v1/package*.json benchmarks/.work/semver-oracle-v1/
npm.cmd ci --prefix benchmarks/.work/semver-oracle-v1 --ignore-scripts --no-audit --no-fund
python benchmarks/evaluate_npm_ranges.py
python -m pytest benchmarks/test_npm_range_h2.py benchmarks/test_npm_direct_h1.py -q
```

[Машиночитаемый отчёт](npm-range-development-v1.json) фиксирует SHA256 кандидата,
H1.1 и lock. Node/npm нужны исключительно внешней проверке, не runtime сервиса.
Новые сборки и Syft-сканы не запускались; три production SBOM не затрагивались.
Следующий этап — заранее закрепить новый независимый npm-контроль, затем подключить
matcher к отдельному H2-классификатору и проверить прежние development/раскрытые
regression-пары. Новую контрольную выборку не использовать для настройки.
