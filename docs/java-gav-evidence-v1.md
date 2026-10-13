# R27 — owner/GAV corroboration

2026-10-14. Только development Gson, runtime0.7.0 не изменён.

Сопоставление использует координаты Maven group/artifact/version из декларации,
локально подтверждённый parent для координат владельца, source Syft и image Syft.
Source owner и dependency должны иметь единственную location выбранного POM.
Ориентация dependency-of проверяется: parent=dependency, child=owner.
В образе требуется единственный компонент каждой координаты. Дубликаты IDs/GAV,
конфликты metadata/version, отсутствующие или обратные связи дают UNKNOWN.

Результат: Gson2.11.0 → error_prone_annotations2.27.0 получил только статус
CORROBORATED_CANDIDATE. Это подтверждение идентичности, не доказательство
effective scope/directness/использования при сборке. Три test-декларации остаются
UNKNOWN на этом этапе: две без literal version, одна отсутствует в образе.
Их отсутствие не считается FN runtime-графа. Direct метрики и version accuracy
не вычисляются для незавершённого классификатора.

Reference graph не читался. Receipt используется только для проверки хешей
входов после предсказания. Saved reference и holdout неизменны. Новых сборок нет.
Проверка рассчитана на валидные Syft-структуры; общий guard malformed inputs,
другие схемы упаковки, classifiers и shaded JAR ещё не реализованы.

Восемь unit cases: positive candidate без direct assertion, duplicate ID/GAV,
version mismatch, другой модуль, reverse edge, конфликт metadata, конфликт
artifact/metadata version. Повторная R26 revalidation проверяет парный эталон.

```powershell
.venv/Scripts/python.exe -X utf8 -m pytest benchmarks/test_java_gav_evidence.py -q
.venv/Scripts/python.exe -X utf8 benchmarks/evaluate_java_gav_evidence.py
.venv/Scripts/python.exe -X utf8 benchmarks/verify_paired_gson.py
```

Следующее: ограниченное слияние dependencyManagement и declarations локальной
цепочки, сравнение scope/owner с парным эталоном только после предсказания.
UNKNOWN нельзя снимать только по совпадению GAV.
[Результат](java-gav-evidence-v1.json).
