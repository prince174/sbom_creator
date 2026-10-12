# R4: эксперимент H1.1 на Express, 2026-10-13

Это проверенный экспериментальный модуль в benchmarks, не изменение runtime.
Промышленный B0 не классифицирует прямые рёбра; сравнительный выигрыш на holdout
ещё не установлен. Встраивать H1.1 в сервис пока рано.

| Выборка | TP | FP | FN | Precision | Recall | F1 | UNKNOWN / деклараций |
|---|---:|---:|---:|---:|---:|---:|---:|
| Express R3, development, root production, имя + версия + владелец package.json | 31 | 0 | 0 | 100% | 100% | 100% | 0 / 31 |
| Holdout | — | — | — | не измерена | не измерена | не измерена | — |

[JSON с рёбрами и SHA256](npm-h1-development-v1.json) фиксирует исходники
классификатора, входы, receipt и split. Все 31 предсказанные версии совпали с
эталоном. Coverage 100% относится только к 31 production-декларации Express,
не к dev/peer, всем компонентам образа или шести языкам.

## Проверяемый принцип

Чистая функция получает исходный package.json и Syft JSON образа. Находит
единственный root package.json вне node_modules по имени/версии приложения;
для каждой dependencies ищет пакет именно в его локальном node_modules.
Поддерживает стабильные x.y.z и ~x.y.z; сравнивает наблюдаемую версию с декларацией.
Не выполняет команды, не читает файлы, не получает эталон или созданный при сборке
lockfile. Отдельный evaluator сверяет результат с CycloneDX только после prediction.

Неподдерживаемые диапазоны, optional/peer overlap, workspaces/overrides,
неоднозначный root/installation, несовпадение версии и различающиеся path/accessPath
дают UNKNOWN. Dev и peer-only находятся вне области этого эксперимента.
Совпадение имени/версии корня — ограниченная эвристика идентичности, не доказательство
соответствия commit образу. Syft package.json также не доказывает фактическую загрузку
модуля или использование при сборке. Для экспериментальной пары соответствие
приложения отдельно установлено протоколом R3.

Семантика сверена с [npm package.json](https://docs.npmjs.com/cli/v11/configuring-npm/package-json/)
и [node-semver](https://github.com/npm/node-semver#tilde-ranges-123-12-1).
Полный resolver, монорепозитории, pnpm/Yarn PnP, aliases и сложные диапазоны пока
не реализованы; их нельзя считать успешно покрытыми.

## Воспроизведение и проверки

Из корня проекта с установленными зависимостями и сохранёнными R3 artifacts:

```powershell
python benchmarks/verify_paired_express.py
python -m pytest benchmarks/test_npm_direct_h1.py benchmarks/test_paired_express.py -q
python benchmarks/evaluate_npm_h1.py
ruff check benchmarks/npm_direct_h1.py benchmarks/test_npm_direct_h1.py benchmarks/evaluate_npm_h1.py
```

21 тест H1 проверяет границы диапазонов, неоднозначность, dev/transitive/base-image
исключения и неизменность входов. R3 повторно проверяет receipt, исходные деревья,
образ и схемы всех трёх прежних SBOM. Основной inventory не сокращён и не изменён.
Время prediction с чтением JSON около 0.09 с на текущем хосте; это не end-to-end
скан и не гарантированный performance показатель. Peak RSS не измерен.

Следующий этап: зафиксированный H1.1 проверить без настройки правил на двух
JavaScript holdout-проектах после подготовки соответствующих парных сборок.
Недостаток coverage считать результатом, не подгонять диапазоны по holdout.
Для расширения синтаксиса использовать новые development-fixtures и новую версию.
