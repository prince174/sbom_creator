# Прямой Syft без Docker — 0.5.0

6 октября 2026. Docker CLI удалён из образа сервиса, Docker socket — из Compose.
Сервис не использует Docker SDK, Engine, containerd socket или privileged-контейнер.
Внешние тестовые harness по-прежнему могут собирать, экспортировать и запускать
контролируемые fixture через Docker хоста; анализатору этот доступ не передаётся.

## Получение и проверка

`syft scan registry:<reference> --platform <platform> --scope squashed -o syft-json`.
Одна загрузка/скан фиксирует конечный состав. Сервис проверяет raw manifest/config
SHA-256, config digest, платформу, layer diff IDs и соответствие запрошенного digest
platform manifest либо repoDigests multi-arch индекса. Контейнер приложения не запускается.
TLS обязателен, credentials передаются через изолированное окружение процесса Syft;
argv, публичные ошибки и артефакты их не содержат. Пользовательские Syft-конфиги,
Docker helpers и daemon environment не наследуются.

Syft собирает metadata конечных файлов и ограниченное base64-содержимое RECORD,
package.json и Java-архивов. Прежние Python/npm/Ruby/Java/Go/Rust payload-правила
работают по этим данным. Удалённые файлы нижних слоёв не подтверждают присутствие.
`contents` удаляется перед публикацией; из конфигурации сохраняется только безопасный
список использованных каталогизаторов. Размер одного читаемого файла ограничен
32 MiB; при отсутствии нужного содержимого остаётся UNKNOWN. Превышение общего
лимита вывода/диска/времени блокирует публикацию, а не создаёт неполный успешный SBOM.
Мониторинг диска периодический; Kubernetes resource/volume limits дают внешние ограничения.

Выходной контракт сохраняется: основной `final.cdx.json`, системный `os.cdx.json`,
полный `full.cdx.json`, выбранные/исходные Syft JSON и отчёты. LLM не требуется.

## Проверки

| Проверка | Результат | Свидетельство |
|---|---|---|
| Windows unit/integration | 197 passed, 1 skipped (права на symlink) | [JUnit](verification-0.5.0-windows.xml) |
| Linux, установленный пакет, без src mount | 198 passed | [JUnit](verification-0.5.0-linux.xml) |
| Установленные модули и fail-closed HTTP | Хеши исходников совпали, ошибки не публикуют SBOM | [Receipt](verification-installed-v0.5.json) |
| Реальные Bitbucket + приватный HTTPS registry + API | UID 10001, read-only root, cap-drop ALL, без Docker/socket; 11 артефактов | [Receipt](verification-http-auth-v0.5.json) |
| Неверный registry password / недоверенный CA | Оба запроса отклонены | [Receipt](verification-http-auth-v0.5.json) |
| Registry digest / multi-arch | Parent index, platform manifest, amd64 и arm64 прошли | [Receipt](verification-registry-platforms-v0.5.json) |
| 60 прежних тестовых образов | Новый scan через Syft с файловым содержимым; решения и состав совпали 60/60 | [Все строки](verification-direct-syft-60.json) |
| Дополнительное сравнение | Совпадают выбранные artifact IDs и payload evidence; raw contents не опубликовано | [Аудит](verification-direct-syft-audit.json) |
| Размеченные fixture шести языков | 13 TP, 0 FP, 0 FN в ограниченной размеченной группе | [Receipt](native-golden-syft-v0.5.json) |
| Ruff / схемы / Compose | Проверки прошли; draw.io IDs/edges валидны | Репозиторий и сохранённые результаты |

На 60 образах осталось **4165 записей вне ОС + 6090 пакетов ОС = 10 255**;
2360 неопределённых идентичностей остаются UNKNOWN. Исходные каталоги репозиториев
переиспользованы; образы повторно сканировались из архивов, экспортированных внешним
harness. Это не новые сборки и не 60 проверок registry-аутентификации. Прямое registry
получение проверено отдельно, включая реальный сквозной API. Native fixture повторно
сканировались; smoke execution в их отчёте относится к исходной контрольной сборке.

Во время разработки обнаружены и исправлены: пустые summary OS/architecture у
архивного источника Syft (проверяется хешированная config), смешение Docker-local ID
и config digest в benchmark, повторное добавление digest в ссылку native fixture.
Старые попытки сохранены локально, исторические benchmark-отчёты не перезаписаны.

## Развёртывание и совместимость

- Образ запускается от UID/GID 10001; workspace и секреты должны быть доступны этому UID.
- Compose включает read-only root, cap-drop ALL, no-new-privileges и отдельный tmpfs.
- [Kubernetes example](../deploy/kubernetes.yaml): без hostPath и service-account token,
  runAsNonRoot, readOnlyRootFilesystem, allowPrivilegeEscalation=false, RuntimeDefault seccomp.
  Kustomize разобрал YAML. Проверка в настоящем кластере **не выполнялась**; image,
  hosts, Secret и PVC нужно настроить под окружение. `/health` — liveness, не readiness внешних систем.
- `SBOM_PULL_IMAGE` и `SBOM_DOCKER_BINARY` больше не принимаются. Офлайн CLI использует
  `SBOM_IMAGE_ARCHIVE`; HTTP API отклоняет такую настройку. Формат `docker-archive` —
  формат входного файла Syft, он не требует daemon.
- `image_id` теперь всегда config digest Syft; registry/platform digests записываются отдельно.
  `archive_sha256` для registry больше не создаётся: отдельного Docker-export архива нет.

Граница результата прежняя: присутствие компонента не доказывает использование при
сборке или выполнении; библиотеки базового образа могут остаться в основном SBOM.
Устранён доступ сервиса к Docker Engine; это не заявление о полной безопасности
любого Kubernetes-развёртывания или об отсутствии уязвимостей в зависимостях.

## Источники реализации

[Syft scan targets](https://oss.anchore.com/docs/guides/sbom/scan-targets/),
[registry auth закреплённого Syft 1.51.1](https://github.com/anchore/syft/blob/v1.51.1/cmd/syft/internal/options/registry.go),
[bounded file content cataloger](https://github.com/anchore/syft/blob/v1.51.1/syft/file/cataloger/filecontent/cataloger.go).
