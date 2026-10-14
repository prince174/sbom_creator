# R35 — профильный контрпример Trivy

2026-10-14. Trivy0.75.0 и реальная синтетическая Maven-сборка.
Исходный POM объявляет commons-lang3:3.17.0 без scope (default compile).
Профиль switch меняет ту же декларацию на test. Build выполняется с -Pswitch.

| Источник результата | Связь |
|---|---|
| Build effective POM | commons-lang3 test |
| Build CDX2.9.3, includeTestScope=false | Runtime direct edges0 |
| Trivy source scan | commons-lang3 direct edge1 |
| J1 | UNKNOWN, profile_declaration_impact |

Получен1лишний runtime edge относительно выбранной сборки. Это ограничение
source scan без знания активного профиля, не общая ошибка инвентаризации Trivy.
R34 P/R/F1=100% остаются результатом двух конкретных положительных Java-пар;
контрпример не превращается в третий реальный проект или общую метрику.
При тех же входных исходниках другой профиль даёт иной build scope, поэтому
неизвестные build settings нужно сохранять как UNKNOWN, а не default compile.

Source scan выполнен до reference build. Тестовый JAR содержит пустой App.java,
не доказывает использование библиотеки. Нет image replay. Docker только
внешний benchmark. Runtime сервиса0.7.0 не изменён.

Maven3.9.16/Temurin17.0.20.1 linux/amd64 base pinned; package + CDX2.9.3 makeBom
+ help3.5.1 effective-pom. Synthetic source/Dockerfile/output/effective POM
и hashes сохранены в benchmarks/references/trivy-profile-v1.
Lifecycle plugins отдельно не pinned, их версии записаны в effective POM.

Повторный verifier проверяет hashes, обе схемы (Trivy1.7/reference1.6),
scope/test, пустой runtime reference, лишнее ребро и сохранение J1UNKNOWN.
Ruff passed. [Результат](trivy-profile-v1.json).

```powershell
.venv/Scripts/python.exe -X utf8 benchmarks/verify_trivy_profile.py
```

Следующее: перейти к независимой парной выборке следующего языка; Java
принятие отложено до доказуемого решения неизвестных профилей. Оба source
адаптера не заменяют build reference при неопределённых настройках сборки.
