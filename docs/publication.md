# Ошибки и атомарная публикация

Публикация сохраняет fixed internal operation/artifact/error/OS-reason enums вместо
raw exception messages/paths. Ошибки diagnostics или secondary cleanup не подменяют
первую ошибку. Arbitrary exception fields не являются доверенным status protocol.

В API status/log и failure.json могут быть publication_operation,
publication_error_code, publication_os_error, publication_artifact,
publication_committed, diagnostics_status и отдельные secondary error codes.
Значения ограничены известными операциями и именами артефактов.

Публикуется целая validated staging directory. Windows rename и Linux
renameat2(RENAME_NOREPLACE) не заменяют существующий, даже пустой, чужой output.
Unsupported OS/filesystem даёт отказ. Это atomic visibility, не fsync/power-loss
или защита от недоверенного concurrent writer.

Если cleanup staging отказал после commit, committed/final_published остаются true.
Job всё равно failed; API blocks downloads409, CLI возвращает1. Наличие файлов не
превращает отказ в success. Выбирайте новый output для каждого повторного анализа.

JSON replacement имеет bounded20attempts/25ms policy. Scanner/converter/full analysis
не повторяются скрыто. Verification failure сохраняет stage verification. Failed
artifacts и диагностика могут содержать приватные сведения проекта: храните их в
защищённом workspace, не публикуйте raw child stderr или credentials.
