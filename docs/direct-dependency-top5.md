# Сравнение решений: топ-5 по прямым зависимостям

Расширенная выборка: [27 собранных пар и выявленные ограничения](java-js-expanded-results-v1.md). Новые Spring Boot/TypeScript приложения показаны отдельно; рейтинг старой выборки не переносится автоматически.

2026-10-15: актуальные режимы и результаты — [сравнение Java/JavaScript](java-js-top3.md), [cdxgen с Maven](cdxgen-build-enabled-v1.md), [сервис без JS lockfile](java-js-no-lock-v1.md). Старые staged-метрики ниже относятся к историческим выборкам.
Java ещё не проходит порог в production; новый optional/fingerprint supplement
остаётся экспериментом до независимой проверки и интеграции. Общие места не назначены.

R66 уточнение scope: после исключения dev-only деклараций по входному манифесту
Trivy51/0/0, H2.1 50/0/1, cdxgen51/3/0 на трёх раскрытых npm-проектах.
Это exploratory adapter, не независимый новый control. [Подробности](npm-competitor-scopes-v1.md).

**Приоритет с 2026-10-15: Java и JavaScript.** Новый запрос пользователя:
референсные образы и три наиболее близкие техники, сначала прямые зависимости.
[Текущее сравнение трёх техник](java-js-top3.md); общий рейтинг ещё не установлен.

R65, 2026-10-15: на трёх npm image-manifest/lock парах предварительно H2.1
50/0/1, Trivy51/4/0, cdxgen51/52/0 (TP/FP/FN относительно production reference).
Это сравнение фиксированных режимов; scope различия требуют отдельной проверки,
Java не ранжирована. [Таблица и ограничения](java-js-top3.md).

Стартовая оценка: **13 октября 2026**. Основной критерий — точность прямых
зависимостей корня проекта/модулей относительно `sbom.json`, созданного CycloneDX
при сборке того же commit. Полный список `components` эталона не равен списку
прямых зависимостей: нужны связи корня/модулей, согласованные scope и версии.

## Таблица решений

Обновление 2026-10-13: пять подходов в сравнении, но рейтинг не установлен.
Измеренного победителя по прямым зависимостям пока нет; полный сравнительный прогон по6языкам
не завершён. Обзор документации не является проверкой точности.

| Место | Решение | Precision / Recall / F1 прямых зависимостей | Плюсы | Минусы | Статус |
|---|---|---|---|---|---|
| — | B0: SBOM Creator 0.5.0, commit `20f287b60d358692c843526704cd44e71ed4012f` | Не измерены | Syft source/image; точные версии и payload evidence; ОС отдельно; runtime без Docker socket | Определяет наличие в образе, не принадлежность к прямым зависимостям проекта; базовые библиотеки могут попадать в основной SBOM; граф неполон | Стартовая версия, 6 языков, 60 тестовых проектов |
| — | SBOM Creator 0.7.0: npm H2.1 + Python P1, [R19](runtime-python-r19.md) | npm control: TP50 FP0 FN1, P100% / R98.04% / F199.01%; Python control: TP9 FP0 FN0, P/R/F1=100% на2положительных проектах | Владелец/декларация + установленный пакет; три inventory сохранены, без исполнения проекта | Python markers/extras/dynamic dependencies UNKNOWN; малая nonblind выборка; Java/Rust/Go/Ruby direct не измерены | JavaScript/Python интегрированы; [npm](runtime-npm-r19.json), [Python](runtime-python-r19.json); 2026-10-13 |
| — | [Syft 1.51.1](https://github.com/anchore/syft), самостоятельный source/image baseline | Не измерены | Уже используемый каталогизатор; единый формат и scanner relationships | Сам по себе не гарантирует полноту графа direct/transitive; file ownership не равно dependency edge | 6 языков инвентаризируются в B0; [R31](syft-java-source-baseline-v1.md): source graph2Java development, filtered GAV2/2; effective scope UNKNOWN, direct accuracy не измерена |
| — | [cdxgen](https://github.com/cdxgen/cdxgen/tree/b84786dec587a20deb605192087388fc0604b12d), HEAD обзора `b84786d` | Не измерены | CycloneDX из исходников и образов, несколько экосистем | Перед прогоном необходимо закрепить режим и проверить, какие внешние команды и установки он выполняет; нельзя молча дать ему больше входных данных | Кандидат; [R33](cdxgen-prebuild-v1.md):2Java pre-build запуска остановлены ChildProcess denied; accuracy не измерена, build-enabled режим не проверен |
| — | [Trivy0.75.0](https://github.com/aquasecurity/trivy/releases/tag/v0.75.0), [R34](trivy-java-source-v1.md) | Java development: TP2 FP0 FN0, P/R/F1=100%, версии2/2; только2рёбра | POM graph, разрешение local/remote Maven metadata; inherited provided исключён | Сеть к Maven repositories; [R35](trivy-profile-v1.md):1лишний runtime edge при active profile test; малая development выборка | 2Java пары +3synthetic cases,5SBOM schema1.7 valid; другие языки и holdout ещё не сравнивались |

Источники ограничений: [Syft cataloger capabilities](https://oss.anchore.com/docs/contributing/syft/),
[Trivy Node.js](https://www.trivy.dev/docs/latest/guide/coverage/language/nodejs/),
[Trivy Java](https://www.trivy.dev/docs/latest/coverage/language/java/).
Версии HEAD приведены для фиксации обзора, это не результаты запуска этих версий.

[R2: диагностика сопоставимости 60 пар](reference-pairing-audit-v1.md): из 389
рёбер R1 365 имеют ту же координату в старом образе, четыре — другую версию,
20 не обнаружены. Это не precision/recall. Новые ранги или улучшение B0 не заявляются.

[R3: парный Express](paired-express-v1.md) устраняет неопределённость сборки для
одного development-проекта: 31 прямое ребро сверено с декларациями и установленными
версиями, все 31 координата присутствуют в final B0, но его `dependencies` пуст.
Это не direct precision/recall и не holdout-результат. H1.1 отдельно проверен на development Express ([R4](npm-h1-development-v1.md));
[48/12 split](../benchmarks/direct-evaluation-split-v1.json) закреплён до настройки правил.

## Измеренные показатели baseline B0

[Машиночитаемый отчёт](baseline-accuracy-20261013.json).
После фиксации B0 подготовлен набор R1: [60 сборочных SBOM](build-references-v1.md),
по 10 на язык. Графы: 50 от CycloneDX, 10 отдельными native-свидетельствами Ruby;
один Python-проект использует добавленную тестовую упаковку. Это подготовка эталонов,
а не новый результат precision/recall: парность со старыми образами B0 ещё не проверена.

Числа пересчитаны по сохранённым артефактам с проверкой хешей; новых сканов и сборок
в первоначальной оценке B0 не выполнялось. Производственные проекты не проверялись.

| Показатель | Значение | Что означает |
|---|---:|---|
| Парные CycloneDX-эталоны сборки, использованные для прямых зависимостей | 0 | Процент точности прямых зависимостей пока неизвестен, не 0% и не 100% |
| Наличие компонентов: TP / FP / FN / TN | 13 / 0 / 0 / 18 | Только 31 явно размеченный случай в 6 контролируемых fixture |
| Precision / Recall / F1 наличия на размеченной части | 100% / 100% / 100% | Не метрика прямых зависимостей и не всего SBOM |
| Неразмеченные итоговые идентичности в этих 6 fixture | 276 | Их правильность не проверена этими 31 меткой |
| Тестовые проекты | 60: по 10 на Java, JavaScript, Python, Rust, Go, Ruby | Полной независимой разметки всех компонентов нет |
| INCLUDE / UNKNOWN | 10 089 / 2360 | Решения по 12 449 объединённым идентичностям source/image |
| Доля INCLUDE | 81,04% | Покрытие решений; это **не accuracy** |
| Записи основного / ОС / полного SBOM | 4165 / 6090 / 10 255 | Число записей, не число решений или уникальных библиотек |
| Пустой массив `dependencies` | 38/60 | Во всех 60 subject — container; это не доказанный граф прямых зависимостей проекта |
| Совпадение после перехода на прямой Syft | 60/60 | Регрессия состава/решений/свидетельств, а не доказательство точности |

Проверки текущего кода: `dependency_scope=not_established`,
`dependency_graph_complete=False`; существующие scanner relationships сохраняются,
но отдельной доказанной классификации direct/transitive нет. Поэтому текущая
система — baseline инвентаризации, а не уже измеренный победитель по прямым зависимостям.

## Условия сравнения и принятия улучшений

1. Зафиксировать commit, образ, платформу, профиль сборки, версию CycloneDX-плагина,
   эталонный SBOM и его хеш; отделить эталон от входов анализатора.
2. Выделить прямые рёбра проекта/модулей и разделить build/test/runtime scopes.
   Неполный граф или неподтверждённый scope пометить, не угадывать.
3. Измерять TP/FP/FN, precision/recall/F1 прямых зависимостей, точность версий,
   UNKNOWN и coverage по языкам на фиксированной контрольной выборке.
4. Ранжировать только сравнимые проверенные подходы. Precision приоритетна,
   но сокращение вывода с потерей recall/coverage не считается безусловным улучшением.
5. Сохранять отрицательные результаты в [журнале](direct-dependency-experiments.md).
   Коммит улучшения алгоритма — только после воспроизводимого выигрыша и регрессии.

R5: контрольная проверка H1.1 выявила недостаточное покрытие диапазонов ^.
[Отрицательный результат](npm-h1-holdout-v1.md) сохранён без изменения правил;
ранги не назначены, production B0 остаётся прежним. Дата проверки: 2026-10-13.

R6, 2026-10-13: для семейства H1/H2 проверен отдельный range matcher: 12 288
синтетических сравнений с node-semver@7.7.2, расхождений 0 ([протокол](npm-range-development-v1.md)).
Это не метрики прямых зависимостей; результаты R5 и отсутствие рейтинга сохраняются.

R7, 2026-10-13: H2.1 на раскрытых regression-парах даёт Express 31/0/0,
Axios 3/0/0, isarray 0/0/0 (TP/FP/FN). [Отчёт](npm-h2-regression-v1.md).
Новый контроль Koa/Fastify/Hapi закреплён, но ещё не оценён; ранг и принятие
в production не назначены. Старый отрицательный результат H1.1 сохраняется.

R8, 2026-10-13: **H2.1 на новом закреплённом npm-контроле** (Koa/Fastify/Hapi,
3/3 пар) — TP=50 FP=0 FN=1, precision=100%, recall=98.04%, F1=99.01%, UNKNOWN=1.
H1 на тех же парах: TP=3 FP=0 FN=48. [Воспроизводимый отчёт](npm-h2-control-v2.md)
и [версия/SHA/рёбра](npm-h2-control-v2.json). Выигрыш подтверждён для этого
npm-профиля; H2 ещё не интегрирован в production. Общий ранг среди пяти подходов
не назначен: Syft/cdxgen/Trivy на этих прямых рёбрах не сравнивались.

R9, 2026-10-13: npm H2.1 интегрирован в **SBOM Creator 0.6.0**.
[Шесть pipeline replay и ограничения](runtime-npm-v1.md): inventory не сокращён,
18 схем валидны. Метрики прямых зависимостей относятся только к R8 npm-контролю
(50/0/1); общий рейтинг инструментов и точность шести языков не установлены.

R10, 2026-10-13: Python-расширение декларационного подхода остаётся неоценённым.
[Аудит 8 development](python-declarations-v1.md): 6 static, 2 UNKNOWN, только
2 непустых проекта с одной библиотекой. Это не метрики direct accuracy; runtime
0.6.0 и позиции кандидатов не меняются. Следующая парная сборка — Jinja.

R11, 2026-10-13: Python-ветка получила первую подтверждённую development-пару
[Jinja](paired-jinja-v1.md): MarkupSafe 3.0.4 согласован source/installed/reference,
но root version отсутствует в reference. Python accuracy по-прежнему не измерена;
новые ранги/проценты не назначаются. Runtime 0.6.0 не менялся.

R12, 2026-10-13: Python P1.0 декларационного подхода реализован только как
эксперимент. [Jinja development](python-p1-development-v1.md): TP=1 FP=0 FN=0,
1/1 версий совпала; holdout ещё не оценён, root-version accuracy null.
Это не новая общая оценка сервиса и не основание повысить ранг среди 5 решений.

### 2026-10-13 — Python P1, R13

У статического подхода P1.0 появились контрольные парные Flask/Packaging:
TP5 FP0 FN0, точные версии 5/5 на Flask; Packaging пустой, метрики null.
UNKNOWN1 (неактивный Python marker), declaration coverage Flask 83.33%.
Это замороженный прототип с исходным nonblind holdout, не новая версия runtime
и не основание менять глобальные места. Остальные кандидаты не переоценивались.
[Протокол и ограничения](python-p1-control-v1.md), [метрики](python-p1-control-v1.json).

### 2026-10-13 — P1 robustness, R14

Выявлены 11 исключений и 2 DIRECT с некорректными ID на синтетических входах P1.
Experimental guard устраняет их в этой выборке; predictions на трёх парных
Python-проектах неизменны. Accuracy и места не меняются; runtime не обновлён.
[Ограничения готовности и воспроизводимый аудит](python-p1-guard-v1.md).

### 2026-10-13 — дополнительный P1 контроль, R15

HTTPX0.28.1: TP4 FP0 FN0, versions4/4, UNKNOWN0, declaration coverage100%.
Frozen P1+guard совпадает с P1. С R13: девять положительных контрольных рёбер
на двух проектах плюс пустой Packaging; не общая Python accuracy. Source cache
HTTPX существовал заранее, строго слепая выборка не заявлена. Runtime0.6.0
неизменен; глобальные места не меняются.
[Протокол](python-p1-control-v2.md), [данные](python-p1-control-v2.json).

### 2026-10-13 — R16, отрицательный результат

Общий бюджет полного Syft графа250000узлов отклонён: теряет все9 прямых
контрольных рёбер Flask/HTTPX. Frozen P1/guard/runtime неизменны, прежние оценки
не заменяются метриками эксперимента. Места не меняются.
[Регрессия и следующий шаг](python-p1-boundary-v1.md).

### 2026-10-13 — R17, бюджет только читаемых полей

Проекция сохраняет все результаты guarded P1 на4парах; контроль TP9 FP0 FN0,
FlaskUNKNOWN1. Регрессия R16 устранена без увеличения лимита. Accuracy исходного
P1 и глобальные места неизменны. Только benchmark, preparse contract ещё открыт.
[Протокол](python-p1-projection-v1.md), [данные](python-p1-projection-v1.json).

### 2026-10-13 — R18, ресурсный контракт runtime

Закрыта гонка проверки размера stdout/stderr перед JSON parsing. Dependency
accuracy не переоценивалась, места и правила неизменны; Python P1 ещё benchmark.
[Проверки и ограничения](syft-input-limit-r18.md).

### 2026-10-13 — R19, Python P1 интегрирован в0.7.0

Четыре Python и шесть npm paired replays: production predictions совпадают
с frozen подходами, inventory и3схемы сохранены. Контроль Python TP9 FP0 FN0,
FlaskUNKNOWN1; root versions без эталона не оценены. Baseline0.6.0 Python direct
не определял. Рейтинг между инструментами не установлен, другие три инструмента
не прогонялись; это расширение поддержки сервиса, не глобальный победитель.

### 2026-10-13 — R20, подготовка Maven-профиля

Development audit8Java:52root declarations, из них40test. Gson/SLF4J требуют
module-aware evaluation. Maven direct accuracy остаётся неоценённой; сырые
POM counts не являются TP/FP/FN. Места и runtime0.7.0 не меняются.
[Аудит и ограничения](maven-declarations-v1.md).

### 2026-10-13 — R21, первый парный Java development reference

Commons Text1.13.0 → Commons Lang3.17.0 подтверждён сборкой/CDX/native graph/JAR.
Artifact-only image2JAR, безJRE. Это эталон, не успех Java classifier: direct
метрики null, места неизменны. [Протокол](paired-commons-text-v1.md).

### 2026-10-13 — R22, ограничение Java evidence

На development Commons Text image JavaPomProject не сохраняет dependency list,
image dependency-of0; source13edges включает12test. Для J1 нужен отдельный
owner/scope анализ. Direct метрики не изменились, места не назначены.
[Аудит](java-syft-evidence-v1.md).

### 2026-10-13 — R23, J1 scope gate

Фильтр scope оставил8/8 Commons Text declarations UNKNOWN из-за parent/profiles.
Улучшение точности не доказано, production и места не меняются. Это только первый
этап экспериментального J1, не конкурент с измеренными direct metrics.
[Результат](java-scope-j1.md).

### 2026-10-14 — R26, второй парный Java development reference

Gson2.11.0 → error_prone_annotations2.27.0 подтверждены package/CDX/native/JAR.
Это расширение эталонов; direct accuracy Java ещё не измерена, места неизменны.
[Протокол](paired-gson-v1.md).

### 2026-10-14 — R30, Java J1 candidate baseline

На двух paired development проектах покрыт1из2эталонных рёбер кандидатами;
Commons Text UNKNOWN, лишних кандидатов0. Это не direct accuracy и не основание
для места в рейтинге. Production0.7.0 неизменён.
[Протокол и ограничения](java-j1-candidates-v1.md).

### 2026-10-14 — R32, отрицательный результат Syft scope adapter

На3сборочных synthetic cases фильтр R31 ошибочно сохраняет inherited provided
и profile test как runtime candidates: raw scope absent. Поэтому2/2GAVсовпадения
R31 не подтверждают direct runtime accuracy. Фильтр не принят, места не назначены.
[Контрпримеры](syft-scope-counterexamples-v1.md).

### 2026-10-14 — R42, Go experimental G2

На Hey+synthetic G2 удалил1лишний selected-main candidate относительноG1,
но пропускает1module-declared edge в synthetic CDX из-за более узкого scope.
Primary direct accuracy не заявляется, runtime unchanged. Frozen доcontrol.
[Протокол](go-g2-imports-v1.md).

### 2026-10-14 — R44, frozen Go positive control

G2 на fixedholdout Lazygit: native selected-main TP33FP0FN0,versions33/33.
Это experimental main-import graph; CDXmodule-root34 имеет1scope difference.
Production0.7.0 unchanged, место не назначено. Emptyholdout HttprobeFP0,
его precision/recallnull не добавляются к положительным метрикам.
[Протокол](go-control-lazygit-v1.md).

R83: build-enabled cdxgen13.4 Java is now measured: original10 pairs11/0/0 exact components and direct edges, additional independent DBCP3/0/0. See [mode-specific report](cdxgen-build-enabled-v1.md). Passive Java failure is a permission-mode result; the successful external Maven mode is not a production runtime candidate without changing the no-project-execution contract. No global cross-mode ranking.


R88 expansion update (2026-10-16): [Javalin reactor evidence](java-js-expanded-results-v1.md) adds a real19-project build pair, but production service image scanning fails its64MiB output budget. No expanded-corpus winner or changed ranking is established; preserve this failure in coverage.


R90 (2026-10-16): passive Trivy0.75.0 image mode with frozen Java DB improves exact component recognition on the same Javalin development image:128/0/0 vs Syft109/19/19 across8 scope-agreeing owners;6 owners remain scope UNKNOWN. Boot packaged comparison90/3/2 conservatively includes one packaging UNKNOWN among extras. This is a component-specific result, not a new direct-dependency rank or production acceptance. [Modes, resources and evidence](java-js-top3.md).

R91 (2026-10-16): source+image integration is still experimental. Passive Trivy source owner candidates improve from42/0/13 to49/0/6 shipped direct edges on Javalin through an explicitly traced optional-declaration parser projection; recall89.09% is below target. POM containment extras remain separate, online metadata blocked by429, no runtime change or independent acceptance. [Evidence](java-js-top3.md).

R92 (2026-10-16): passive Trivy source optional projection with public mirror POM metadata gives55/0/0 direct edges across14 shipped Javalin owners, repeated on19 source graphs; one development repository only. All-module72/18/0 and6 component-scope UNKNOWN owners remain visible. No runtime integration or overall rank change; [limitations and evidence](java-js-top3.md).

R93 (2026-10-16): a fresh Petclinic REST reference pair validates frozen passive Trivy candidate21/0/0 direct and104/3/2 packaged components (P97.20%/R98.11%), while unchanged service final remains0/0/106. One positive Boot control is not independent optional/reactor validation or runtime acceptance. [Scope, baseline and evidence](java-js-top3.md).

R96 (2026-10-16): bounded large/nested/resource JAR evidence removes the disclosed Boot payload barrier in an external prototype, but unchanged Syft identities yield only66/26/26 final components, P/R71.74%, despite matching count92. Not accepted or ranked above existing techniques;16 direct edges remain unmatched and runtime is unchanged. [Negative result and integration gate](java-js-top3.md).

R97 (2026-10-16): passive Trivy identities joined strictly to same-image/path/layer and bounded payload produce candidate final Boot89/3/3 (P/R96.74%) and Javalin128/0/0 on8 agreed owners. No rank promotion: both are disclosed development cases,6 Javalin owner scopes and all direct edges remain UNKNOWN; one additional Boot FN versus raw Trivy is explicit. [Evidence, limits and next acceptance gates](java-js-top3.md).

R98 (2026-10-16): an explicitly attributed Trivy-only resource archive with bounded physical evidence restores Boot final90/3/2 (P96.77%/R97.83%), without adding FP or pretending Syft discovered it. Javalin and direct UNKNOWN are unchanged; experimental benchmark registration only, no runtime adoption/rank promotion. [Reproducible evidence and remaining gates](java-js-top3.md).


R99 (2026-10-16): new independent complex Dropwizard pair validates39 module references/34 shipped owners/443 direct edges. Frozen source candidate times out180s; bounded image candidate is stopped for repeated over-budget layer processing. No final score/rank promotion; runtime unchanged. [Control failure and corpus update](java-js-top3.md).


R100 (2026-10-16): separate bounded rejection-cache candidate completes Dropwizard final/os/full in94.11s, but confirms no project payload under the unchanged512MiB layer budget. On16 agreeing owners final0/0/907, recall0;18 owner scopes UNKNOWN and443 direct edges unmatched. Boot/Javalin witness/catalog/evidence regression is exact. [Negative evaluation](../benchmarks/results/cached-dropwizard-evidence-v3/evaluation.json), [resource run](../benchmarks/results/cached-dropwizard-evidence-v3/run.json). Benchmark liveness only, no runtime adoption/rank promotion or new pairs.
