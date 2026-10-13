# R18 — контракт размера Syft JSON и исправление гонки

2026-10-13, исходный main0f18bee, дерево чистое, benchmark-процессов нет.
Это исправление проверки ресурсов в runtime, не улучшение dependency accuracy.
P1/guard/projection не интегрированы и не изменены; deployed service не менялся.

`Settings.max_sbom_bytes` уже равен64МиБ. `_syft()` получает stdout через
`acquire.run_command`, затем вызывает `scanner._json()`. Значит лимит должен
сработать до json.loads. Он учитывает суммарные stdout+stderr команды, а не
размер файла после сериализации или память Python объектов. Для Syft version
используется отдельный max_output_bytes4МиБ.

Найдена гонка: размер проверялся перед process.poll(); процесс мог дописать
последний вывод и завершиться между проверкой и poll. Затем stdout целиком
читался read_text. Детерминированный mock воспроизвёл два обхода: stdout33bytes
и stderr33bytes при лимите32. Оба теста падали; ровно32bytes принимались.

Исправление:
- повторная суммарная проверка stdout+stderr после завершения процесса;
- binary read(max_output_bytes+1) вместо неограниченного read_text;
- проверка прочитанного размера плюс stderr перед decode и JSON parser.

Ошибки сохраняют redacted сообщение, без вывода содержимого. Нет изменений
правил, входного API, inventory, экспорта или трёх SBOM. Проверка лимита не
выдаёт усечённый каталог за успешный результат — команда завершается ошибкой.

Проверки:211passed,2skipped,1существующий Starlette/httpx deprecation warning;
Ruff passed; настоящий Syft version через обновлённый runner вернул1.51.1.
128сохранённых source/image JSON (60исходных проектов +4Python пары): максимум
8904584bytes,0превышений64МиБ. Это проверка размеров, не повторный полный scan
и не remeasurement precision/recall; stderr этих исторических запусков отдельно
не включён. Тесты содержат scanner/schema/integration/security regression.

Ограничения: polling50ms допускает временное превышение дискового размера;
64МиБ raw output не означает64МиБ RAM после декодирования/JSON parsing. Peak RAM
не измерена. Это не защита от произвольного дерева дочерних процессов после
выхода родителя. Python P1 budgets относятся к уже разобранным объектам.

```powershell
.venv/Scripts/python.exe -m pytest -q
.venv/Scripts/ruff.exe check src/sbom_creator/acquire.py tests/test_acquire.py
```

Следующее: интеграция bounded pyproject/P1 projection в отдельном этапе,
с обязательной проверкой Python и npm direct evidence, сохранением inventory,
UNKNOWN и трёх SBOM. Контрольные результаты не использовать для подбора правил.
