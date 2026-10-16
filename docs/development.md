# Разработка и состав репозитория

В Git входят код сервиса, схемы/лицензии зависимостей, тестовый код и небольшие
детерминированные test fixtures, конфигурация сборки/deploy и эксплуатационные docs.

R&D ведётся локально: benchmarks/, research/, rnd/, workspace/, reports/, результаты
сканирования, reference corpora, SBOM exports, JSON/XML test reports, логи и архивы
не входят в release commits. Исторические исследовательские файлы могут оставаться
на диске по прежним путям, но исключены из индекса и защищены .gitignore.

```sh
pytest
ruff check src tests scripts
# Если нужен отчёт — только в локальный ignored workspace:
pytest --junitxml=workspace/test-results/pytest.xml
```

До коммита проверяйте git diff --cached --stat и список paths. Тесты и необходимые
проверки выполняются перед изменением release; в Git добавляются сами тесты, не
их сгенерированные отчёты. Runtime и эксплуатационные изменения коммитьте понятными
отдельными этапами. Не добавляйте secrets, credentials, downloaded tools, caches
или чужие checkout/build inputs. .gitignore не является защитой от явного git add -f.

При работе с локальной историей R&D полный pytest может видеть оставшиеся local-only
harness tests. Product tests должны проходить из чистого checkout без benchmarks.
Новые продуктовые docs размещайте в docs/user/ или добавляйте явное разрешение
конкретного документа в .gitignore. Метрики экспериментов не заменяют контракт API.
