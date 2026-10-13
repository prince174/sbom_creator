# R23: первый этап J1 — фильтр scope

2026-10-13. Только эксперимент, production 0.7.0 не изменён.

Проверяется узкая гипотеза: raw POM позволяет отобрать кандидатов compile/runtime
только при отсутствии неразрешённых parent, profiles, dependencyManagement,
modules и выражений свойств. Это намеренно консервативный фильтр, не Maven resolver.
Даже кандидат не получает direct edge: ещё нужны owner, уникальный GAV и
согласование с source graph/image. Вход — только исходный POM, эталоны не используются.

В Commons Text все 8 деклараций остаются UNKNOWN: parent и profiles не разрешены.
Это включает commons-lang3, который сборочный эталон подтверждает как прямую
зависимость версии 3.17.0. Следовательно, фильтр не даёт улучшения coverage;
его нельзя внедрять как готовый классификатор. Precision/recall/версии не измеряются
для незавершённого этапа. Нулевой список рёбер не считается успешной оценкой.

12 unit cases проверяют scopes, parent, profiles, management, modules и property
expressions. System scope оставлен UNKNOWN: требуется отдельная проверка локального
systemPath; он не приравнивается к test/provided. Правила scopes сверены с
[официальной документацией Maven](https://maven.apache.org/guides/introduction/introduction-to-dependency-mechanism.html).
Это синтетические проверки фильтра, не 12 реальных Maven-сборок.

Повторная проверка парного эталона R21 подтвердила хеши, OCI/JAR/native graph и
три схемы CycloneDX. Эталоны и контрольная выборка не менялись.

Воспроизведение из корня:

```powershell
.venv/Scripts/python.exe -X utf8 -m pytest benchmarks/test_java_scope_j1.py -q
.venv/Scripts/python.exe -X utf8 benchmarks/evaluate_java_scope_j1.py
.venv/Scripts/python.exe -X utf8 benchmarks/verify_paired_commons_text.py
```

Следующий этап: разрешать только локальную цепочку parent POM с ограничениями
путей/циклов/размера; отсутствующий remote parent и неизвестная активация профиля
остаются UNKNOWN. Сначала отдельный development fixture с реальной сборкой,
затем owner/GAV matching. Не использовать effective POM эталона как вход.

[Данные](java-scope-j1.json).
