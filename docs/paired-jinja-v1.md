# R11: парная Python-сборка Jinja, 2026-10-13

Подготовлена development-пара на commit 877f6e51be8e1765b06d911cfaa9033775f051d1.
Wheel Jinja2 3.1.5 построен flit_core 3.12.0. MarkupSafe 3.0.4 зафиксирован явно;
оба wheel установлены офлайн в /project. Python base image закреплён digest,
платформа linux/amd64, версия Python и tool freeze сохранены. CycloneDX 7.5.0
работал из отдельного /generator над установленным окружением /project.

| Проверка | Результат |
|---|---|
| Прямая runtime-зависимость без extras | MarkupSafe 3.0.4 |
| Source declaration / installed METADATA / reference edge | Согласованы |
| Версия установленного корневого пакета | Jinja2 3.1.5 |
| Версия корня в CycloneDX reference | **Отсутствует, UNKNOWN** |
| Conditional extra | Babel>=2.7 при extra=i18n; в текущем профиле не включён |
| SBOM сервиса final / OS / full | 16 / 106 / 122 компонента |
| Direct precision/recall Python | Не измерены, классификатор пока отсутствует |

У pyproject динамическая version; generator оставил metadata.component.version
пустой. Эталон не дополнялся выведенной версией. Установленная версия известна
из METADATA, но не объявляется совпадением с отсутствующим полем reference.
Root graph MarkupSafe подтверждён независимо декларацией и METADATA; полный
components reference не использован как список прямых зависимостей.

Проверены совпадение деревьев venv builder/runtime, OCI image binding, Syft config,
хеши reference/output, installed versions и три CycloneDX schema. Генератор и
reference не попали в runtime. В окружении остаются bootstrap pip/base packages;
они не объявляются прямыми зависимостями Jinja. Время полного запуска и peak
CPU/RSS не измерены. Reconciliation time в summary не является полным временем.

[Receipt и хеши](../benchmarks/references/paired-jinja-v1/receipt.json),
[неизменённый SBOM](../benchmarks/references/paired-jinja-v1/sbom.json),
[машиночитаемая проверка](paired-jinja-v1.json).

```powershell
# Только первоначальная сборка; завершённый receipt запрещает повтор.
python benchmarks/paired_jinja.py
# Повторная проверка сохранённой пары без сборки/скана:
python benchmarks/verify_paired_jinja.py
python -m pytest benchmarks/test_paired_jinja.py benchmarks/test_paired_express.py -q
```

11 тестов и Ruff прошли. Первая попытка анализа остановилась на отсутствующем
registry allowlist в harness; исправлено, --resume-built-images использовал те же
образы без повторной сборки. Диагностика сохранена локально. Дополнительная
проверка обнаружила отсутствующую root version: результат отмечен UNKNOWN.
Runtime 0.6.0 не менялся, Docker применялся только внешним benchmark harness.

Следующий этап: исследовать, какие сведения installed distribution/Requires-Dist
сохраняет Syft, и подготовить отдельный Python-прототип для статических безусловных
project.dependencies. Не исполнять setup.py в runtime, не брать markers с host,
динамическую версию корня не угадывать. Flask/Packaging holdout не использовался.
