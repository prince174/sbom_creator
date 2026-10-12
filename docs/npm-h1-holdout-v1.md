# R5: контрольная проверка H1.1, 2026-10-13

**H1.1 не принят для runtime: покрытие положительной контрольной выборки 0%.**
Классификатор из R4 не изменён, SHA256 проверяется evaluator перед запуском.
Два проекта взяты из ранее закреплённого holdout, без замены неудобных случаев.

| Проект | Прямых рёбер эталона | TP | FP | FN | Precision | Recall / F1 | UNKNOWN | Coverage |
|---|---:|---:|---:|---:|---|---|---:|---|
| Axios | 3 | 0 | 0 | 3 | не определена | 0% / 0% | 3 | 0% |
| isarray | 0 | 0 | 0 | 0 | не определена | не определены | 0 | не определено |

UNKNOWN считается пропуском при оценке recall, поэтому он не скрывает FN.
У Axios неподдерживаемые диапазоны ^1.15.6, ^4.0.0, ^1.1.0. Версии в эталоне
сверены с build lock и установленными package.json; H1.1 не предсказал ни одной
версии, поэтому его точность версий здесь не определена. isarray проверяет
отсутствие ложных рёбер, но не создаёт положительных примеров для precision/recall.
Единственный владелец в обеих парах — корневой package.json; модульная точность
не измерена. Scope — production после удаления dev-зависимостей.

## Парность и воспроизведение

Обе пары построены из закреплённых manifest commit. Общий рецепт фиксирует
Node image digest, linux/amd64 и CycloneDX npm 6.0.1. Axios прошёл штатный
`npm run build` (Rollup); isarray, у которого build отсутствует, — `npm pack`.
Установка build/dev-зависимостей выполняется только во внешнем builder;
после build/pack выполнен prune dev и CycloneDX production SBOM. Runtime получает
тот же каталог приложения: сравнены пути, типы, режимы, содержимое файлов и ссылки.
Генератор и эталон отсутствуют в runtime. Build scripts этого тестового процесса
не являются возможностью production-сервиса.

Эталон относится к установленному production-графу после сборки, а не ко всем
build/test инструментам. Наличие компонента не доказывает выполнение его кода.
Рецепт общий, но зависимости без точного lock могут разрешиться иначе в будущем;
неизменяемые lock, SBOM, receipt и image identity фиксируют именно этот запуск.

- [Axios reference](../benchmarks/references/paired-axios-v2/receipt.json)
- [isarray reference](../benchmarks/references/paired-isarray-v1/receipt.json)
- [Предсказания и метрики](npm-h1-holdout-v1.json)

```powershell
# Только для первоначальной сборки: завершённый receipt запрещает перезапись.
python benchmarks/paired_express.py --project axios --run-id v2
python benchmarks/paired_express.py --project isarray
# Повторная проверка сохранённых артефактов без сборки/сканирования:
python benchmarks/evaluate_npm_holdout.py
python -m pytest benchmarks/test_paired_express.py benchmarks/test_npm_direct_h1.py -q
```

Локальные архивы и исходные Syft outputs находятся в соответствующих
`benchmarks/.work/paired-*/`; компактные эталоны сохранены в Git. Evaluator
проверяет хеши, OCI binding, совпадение Syft config, деревья приложения, схемы всех
трёх SBOM и независимые версии. Эталон не передаётся classify.
B0 inventory: Axios 214 final / 89 OS / 303 full; isarray 199 / 89 / 288.
Изменений production-алгоритма нет. 27 unit-тестов и Ruff прошли;
старый парный Express повторно проверен без изменения его evidence.

## Отрицательные попытки и ограничения

1. Axios v1 не собрался: npm pack запустил prepare/Husky при отсутствующих dev deps.
   Лог сохранён локально; v2 использует настоящий build с dev-инструментами и prune.
   Пара v1 не оценивается. [npm pack](https://docs.npmjs.com/cli/v11/commands/npm-pack/)
   описывает packaging; конкретный сбой установлен по build.log, а не по документации.
2. isarray выявил ошибку harness: валидное отсутствие dependsOn в записи корня
   вызвало KeyError. Исправлено чтение пустого графа, добавлен regression-test,
   продолжена валидация уже построенного образа через --resume-built-images.
3. До первой публикации исправлена устаревшая метка runtime_scope в Axios receipt;
   причина и хеш исходной метадаты записаны в receipt, SBOM не изменён.
4. Для isarray полное время build не восстановлено после resume; null.
   Peak CPU/RSS не измерены. Prediction timing не включает сканирование.

Следующий этап: расширить npm semver на независимых development-fixtures,
сопоставляя с официальным node-semver. Эти два проекта теперь раскрыты; повтор
на них будет regression, а не новым независимым holdout. Для следующего решения
о внедрении нужен новый заранее закреплённый контрольный набор.
