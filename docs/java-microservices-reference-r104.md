# R104: Petclinic Microservices — референс и граф исходников

2026-10-16. Новая завершённая пара: `spring-petclinic-microservices`, точный commit
`1d76b00d683e86b62867a6bf59530f8ab301244f`, development partition.
Это реальная контролируемая Maven-сборка,9 per-module CycloneDX SBOM и8 поставляемых
JAR-владельцев. Все100 compile/runtime прямых GAV-рёбер согласованы между effective
model, native Maven graph и CycloneDX. Агрегированный список компонентов не используется
как список прямых зависимостей. Профили, версия Maven/JDK и команды записаны в recipe.
Tests скомпилированы, но не исполнены; это artifact fixture, не запущенная система
микросервисов и не проверка application health.

[Неизменяемый receipt](../benchmarks/references/paired-petclinic-microservices-r104/receipt.json)
содержит хеши всех референсов и привязку к образу:

| Сущность | Digest |
|---|---|
| OCI index | `sha256:27cdb4fadf5ba9f4f4d04b0d9df969436271dd6ddec0e4c28d5b55e5d7a0e5d8` |
| Platform manifest | `sha256:0baa31188e29b4df33890b7664c46c6e8fd4c9a4ca53731db83ad05e6cb6ad95` |
| Image config | `sha256:9363d3f231875f937c5a8904a1bb4d86e9d8ac0730eaf9d9f8d064e9cb848a8a` |

Primary JAR SHA256 и деревья build/final согласованы; исходники восстановлены из
точных Git blobs, дерево исходного commit проверено. Завершённая пара не пересоздавалась.
Основной корпус теперь16 Java +12 JavaScript, отдельно DBCP:29 реальных пар.
В расширении8 готовы,12 пока PINNED_NOT_BUILT (4 Java,8 JavaScript).

После завершения двух прогнозов evaluator открыл module labels:

| Техника / область | TP / FP / FN прямых рёбер с точной версией | Precision | Recall |
|---|---:|---:|---:|
| Trivy0.75.0, пассивная POM projection,9 владельцев |76 /0 /24|100%|76%|
| cdxgen13.4.0 + native Maven, raw граф9 владельцев |100 /8 /0|92.59%|100%|
| Тот же cdxgen,8 поставляемых JAR-владельцев отдельно |100 /0 /0|100%|100%|

Восемь лишних root-рёбер cdxgen — включение модулей reactor в raw dependency graph;
они сохранены как FP при оценке всего графа. Это не измерение image-компонентов.
Пассивный resolver завершил7 из9 owner graphs,2 UNKNOWN; время160.812s.
Native cdxgen в изолированном job с fresh cache завершился за322.704s.
Worker не получает секреты сервиса или Docker socket; project tooling разрешено
пользователем. [Raw native run](../benchmarks/results/java-runtime-direct-r104-control-v1/cdxgen/run.json),
[post-only оценка и каждый модуль](../benchmarks/results/java-runtime-direct-r104-control-v1/evaluation.json).

Референс не передавался прогнозам. Native Maven устанавливает граф доступной analysis
configuration, а не доказывает воспроизведение неизвестной TeamCity-сборки. GAV-метрики
не доказывают classifier/type-qualified accuracy или исполнение каждой зависимости.
Последующие изменения source adapters не объявляются проверенными этим сохранённым
прогнозом. Сбой source/backend не должен блокировать SBOM готового образа.

Эта development-пара не является новым независимым глобальным acceptance после её
раскрытия для настройки. Оценка actual image-only сервиса ведётся отдельно в
[отчёте точности](java-js-service-accuracy.md); результаты source-графа не подменяют final SBOM.

Воспроизведение оценки завершённых прогнозов: `python benchmarks/evaluate_java_source_r104.py`.
Существующий `evaluation.json` скрипт намеренно не перезаписывает.
