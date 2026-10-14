# R46 — deletion/size failures Syft Go payload bridge

2026-10-15. Продолжение внешнего R45, runtime0.7.0 unchanged.

| Случай | Проверенный результат |
|---|---|
| Binary удалён в верхнем слое |final filesystem не содержит path; payload unavailable|
| Несуществующий path |payload unavailable|
| Regular file32MiB+1 |metadata size подтверждён, contents не возвращены|

Для удаления image сначала содержит реальный Hey binary, затем доверенный
fixture helper удаляет /application/app при Docker build. В saved archive
проверен application/.wh.app. Syft squashed scan не возвращает старые bytes.
Fixture helper запускается только при внешней тестовой сборке; это не
исполнение пользовательского приложения или изменение deployed services.

Все3случая дают ValueError Binary unavailable within content budget. Отказ
должен превращаться будущим G2adapter в UNKNOWN, а не в успешный пустой граф.
Production G2adapter ещё не реализован. Никакого роста accuracy здесь нет.

Реальный target32MiB+1 — размерный boundary case, а не Go executable. Проверяет
исключительно правила file-content acquisition до binary parsing. Образы
имеют immutable config digests в отчёте; Dockerfile/source/logs/tar находятся
в benchmarks/.work/go-payload-failures-r46. Повторная проверка whiteout и
трёх отказов прошла; Ruff passed. Для запроса contents используется тот же
bridge R45, production scanner config не менялся.

```powershell
.venv/Scripts/python.exe -X utf8 benchmarks/check_go_payload_failures.py
```

Остаются registry/auth/two-pass digest pinning и aggregate budget нескольких
binary targets, parser helper delivery/version policy, malformed input guard.
До этого G2 не переносится в runtime. Frozen control rules не менялись.
[Машинный результат](syft-go-payload-failures-v1.json).
