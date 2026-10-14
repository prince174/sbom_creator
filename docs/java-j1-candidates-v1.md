# R30 — объединённый эксперимент J1

2026-10-14. Две paired development Java выборки, не контроль.
Объединены локальная статическая модель, module owner, source Syft edge и
уникальные image GAV. Reference читается только после prediction.

| Проект | Рёбра reference | Совпавшие кандидаты | Лишние кандидаты | Без кандидата |
|---|---:|---:|---:|---:|
| Gson |1|1|0|0|
| Commons Text |1|0|0|1|

Покрытие эталонных рёбер кандидатами1/2=50%. Единственная версия кандидата
совпала с эталоном. Это не direct precision/recall: кандидаты не получили
статус доказанных прямых зависимостей, а оба проекта использовались для разработки.
У Commons Text не разрешён внешний parent; unknown_count=null обозначает
неполную модель, а не0неизвестных. Три Gson test declarations остаются в
статической модели, но не продвигаются в runtime candidates.

Production0.7.0 не изменён. Нет достаточных оснований принимать J1: effects
settings/CLI/plugins неизвестны, remote parent и inherited declarations не
поддержаны. Новый полный SBOM не создавался, immutable reference не менялся.
Шесть SHA исходников экспериментального pipeline сохранены в JSON — snapshot
для последующих сравнений, не автоматическая гарантия неизменности.

51Java test passed, Ruff passed. Новые проверки покрывают соединение стадий,
отсутствие image evidence, whole-model UNKNOWN и исключение test из runtime
candidates. Пустые candidate lists не считаются успехом.

```powershell
.venv/Scripts/python.exe -X utf8 benchmarks/evaluate_java_j1_candidates.py
.venv/Scripts/python.exe -X utf8 -m pytest benchmarks/test_java_j1_candidates.py -q
```

Следующее: до расширения Java resolver проверить независимый development
случай с унаследованными declarations и реальные возможности source-only
конкурента на тех же2парах. Не тратить контроль на подбор правил и не снижать
UNKNOWN без доказательства. [Данные](java-j1-candidates-v1.json).
