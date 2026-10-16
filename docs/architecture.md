# Архитектура сервиса

Image-only pipeline принимает container image на разрешённом registry host. Syft
получает конечный inventory, сервис проверяет manifest/config/platform/DiffID binding.
Для Java Crane получает внутренний Docker archive, Trivy уточняет identity, bounded
reader проверяет class/resource или полный archive presence. Эти факты не заменяют
друг друга и не доказывают execution/directness.

Policy gate принимает только подтверждённые image observations. PURL/versions не
угадываются; raw inventories и original identities сохраняются. Неподдержанный
архив, неоднозначность и лимит дают UNKNOWN/partial, не доказанное отсутствие.
Системные пакеты выделяются в os.cdx.json, полный состав остаётся в full.cdx.json.

Repository HTTPS URL + exact commit — дополнительные входы. Checkout фиксируется
по Git object identity, hooks/config redirects/submodules/LFS не запускаются скрыто.
Source declaration сама по себе не добавляет компонент в image SBOM. Optional
cdxgen model-resolution выполняется в отдельном ограниченном job без host mounts,
service secrets или Docker socket. Успех не доказывает воспроизведение исходной CI.

API использует bounded queue, persistent statuses и один процесс на workspace.
Публикация целой validated staging directory атомарна. Source/image/verification
scopes должны оставаться раздельными; эталон доступен только post-analysis evaluator.

Image pipeline не требует Docker Engine/socket. При включении build-enabled backend
доверенный coordinator управляет внешними worker containers; проект не получает
доступа к engine или credentials сервиса. LLM не нужен обычному API.

Оператор отвечает за HTTPS boundary, secret files, registry/repository allowlists,
workspace capacity/retention и отдельную оценку concurrent workloads. Commit и image
фиксируются независимо: build attestation не заменяется caller assertion или label.
