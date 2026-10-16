# Publication failures — R113

Исторический R106 Chalk завершился `AnalysisError`, общий этап
`reconcile_convert_validate`, исходный тип `PermissionError`. Traceback, filename,
errno/winerror и конкретная операция не сохранялись. Поздний успешный replay не
объясняет этот отказ и не доказывает исправление locking или antivirus interference.
Старые inputs, failure и успешный diagnostic replay остаются неизменными.

R113 добавляет checkpoints публикации, сохраняя общий совместимый stage. В CLI,
API status/log и failure.json передаются только фиксированные внутренние значения:

- `publication_operation`: validation, reconcile, convert, запись конкретного
  известного artifact, commit directory либо cleanup; это checkpoint, не traceback.
- `publication_error_code`: permission, output conflict, missing path, I/O,
  invalid data или иной operation failure.
- `publication_os_error`: ограниченный enum, включая Windows sharing/lock violation,
  access denied, no space и read-only. Никаких message/filename из exception.
- `publication_artifact`: только известное имя SBOM/audit файла, без произвольного пути.
- `publication_committed`: собственный успешный atomic commit, не проверка exists.
- `diagnostics_status`: complete/partial/unavailable; относится к сохранению
  failure metadata/input catalogs, не к успешности анализа.

Необязательные `cleanup_error_code`, `diagnostics_error_code` и
`workspace_cleanup_error_code` сохраняют вторичные ошибки отдельно. Первая ошибка
не подменяется отказом diagnostics или очистки workspace при её распространении.
Произвольные поля/свойства внешнего exception не используются как status protocol.

## Atomic output и ошибочная очистка

Публикуется целая staging directory. Windows rename и Linux
`renameat2(RENAME_NOREPLACE)` не заменяют даже появившийся пустой чужой output.
Unsupported platform/filesystem даёт отказ. Это atomic visibility, не fsync,
power-loss durability или защита от недоверенного concurrent writer.

Если cleanup staging отказал после commit, `publication_committed=true` и
`failure.json.final_published=true` честно отражают существующий полный результат.
Job всё равно failed; API блокирует скачивание с409, CLI возвращает1 и сообщение
`Analysis failed; output blocked`. Наличие файлов не превращает отказ в success.
Обычный успешный анализ требует exit0/API succeeded. Не удаляйте старый output
для повторного запроса: новый job/path сохраняет первоначальные доказательства.

Для JSON replacement сохранены прежние20 bounded попыток/25ms между отказами.
Новых автоматических повторов scanner, converter или всего анализа нет.
Verification failure имеет stage `verification`, а не acquisition fallback;
ошибка сравнения не объявляется ошибкой image inventory.

## Область изменения

Reconciliation, payload/identity rules, references и точность компонентов не
настраиваются. Это проверка диагностики и сохранности публикации. Исходный Chalk
cause остаётся UNKNOWN; это не повод для бесконечных unchanged rescans или новых
чужих build recipes. Исторические Java/JS метрики сохраняются с прежними scopes.
