# Сборочные эталоны CycloneDX — B0

Эталоны получены независимо от Syft и правил сервиса, из закреплённых коммитов.
Повторные сборки не доказывают совпадение разрешённых версий со старыми образами B0. Точность B0 пока не пересчитана.

| Язык | Проектов | SBOM получен | Есть граф для прямых зависимостей |
|---|---:|---:|---:|
| Java | 10 | 10 | 10 |
| JavaScript | 10 | 10 | 10 |
| Python | 10 | 10 | 10 |
| Rust | 10 | 10 | 10 |
| Go | 10 | 10 | 10 |
| Ruby | 10 | 10 | 10 |

Граф Ruby — отдельное свидетельство Bundler/gemspec; сам плагин граф не формирует. Для lab-python без метаданных добавлена тестовая упаковка wheel: это отдельный случай с benchmark overlay, а не исходная декларация автора.
Всего 389 прямых рёбер выбранных корней; у 30 проектов их ноль. Такие случаи нельзя превращать в 100% precision/recall или использовать для искусственного завышения средней точности.
Количество прямых рёбер относится к корню выбранного проекта/модуля и указанному профилю сборки, а не к исполнению кода в runtime.

| Проект | Сборка | Компонентов, включая корень | Прямых рёбер | Источник графа |
|---|---|---:|---:|---|
| [java-commons-lang](../benchmarks/references/build-v1/java-commons-lang/sbom.json) | generated | 3 | 1 | CycloneDX plugin |
| [java-commons-io](../benchmarks/references/build-v1/java-commons-io/sbom.json) | generated | 1 | 0 | CycloneDX plugin |
| [java-commons-codec](../benchmarks/references/build-v1/java-commons-codec/sbom.json) | generated | 1 | 0 | CycloneDX plugin |
| [java-commons-text](../benchmarks/references/build-v1/java-commons-text/sbom.json) | generated | 2 | 1 | CycloneDX plugin |
| [java-commons-csv](../benchmarks/references/build-v1/java-commons-csv/sbom.json) | generated | 3 | 2 | CycloneDX plugin |
| [java-commons-compress](../benchmarks/references/build-v1/java-commons-compress/sbom.json) | generated | 9 | 8 | CycloneDX plugin |
| [java-gson](../benchmarks/references/build-v1/java-gson/sbom.json) | generated | 2 | 1 | CycloneDX plugin |
| [java-jsoup](../benchmarks/references/build-v1/java-jsoup/sbom.json) | generated | 2 | 1 | CycloneDX plugin |
| [java-slf4j](../benchmarks/references/build-v1/java-slf4j/sbom.json) | generated | 1 | 0 | CycloneDX plugin |
| [java-commons-cli](../benchmarks/references/build-v1/java-commons-cli/sbom.json) | generated | 1 | 0 | CycloneDX plugin |
| [javascript-lodash](../benchmarks/references/build-v1/javascript-lodash/sbom.json) | generated | 1 | 0 | CycloneDX plugin |
| [javascript-express](../benchmarks/references/build-v1/javascript-express/sbom.json) | generated | 69 | 31 | CycloneDX plugin |
| [javascript-axios](../benchmarks/references/build-v1/javascript-axios/sbom.json) | generated | 9 | 3 | CycloneDX plugin |
| [javascript-debug](../benchmarks/references/build-v1/javascript-debug/sbom.json) | generated | 2 | 1 | CycloneDX plugin |
| [javascript-ms](../benchmarks/references/build-v1/javascript-ms/sbom.json) | generated | 1 | 0 | CycloneDX plugin |
| [javascript-chalk](../benchmarks/references/build-v1/javascript-chalk/sbom.json) | generated | 1 | 0 | CycloneDX plugin |
| [javascript-commander-js](../benchmarks/references/build-v1/javascript-commander-js/sbom.json) | generated | 1 | 0 | CycloneDX plugin |
| [javascript-minimist](../benchmarks/references/build-v1/javascript-minimist/sbom.json) | generated | 1 | 0 | CycloneDX plugin |
| [javascript-is-number](../benchmarks/references/build-v1/javascript-is-number/sbom.json) | generated | 1 | 0 | CycloneDX plugin |
| [javascript-isarray](../benchmarks/references/build-v1/javascript-isarray/sbom.json) | generated | 1 | 0 | CycloneDX plugin |
| [bitbucket-python-service](../benchmarks/references/build-v1/bitbucket-python-service/sbom.json) | generated | 2 | 0 | CycloneDX plugin |
| [bitbucket-python-jobs](../benchmarks/references/build-v1/bitbucket-python-jobs/sbom.json) | generated | 2 | 0 | CycloneDX plugin |
| [bitbucket-lab-python](../benchmarks/references/build-v1/bitbucket-lab-python/sbom.json) | generated | 2 | 0 | CycloneDX plugin |
| [python-flask](../benchmarks/references/build-v1/python-flask/sbom.json) | generated | 8 | 5 | CycloneDX plugin |
| [python-jinja](../benchmarks/references/build-v1/python-jinja/sbom.json) | generated | 3 | 1 | CycloneDX plugin |
| [python-werkzeug](../benchmarks/references/build-v1/python-werkzeug/sbom.json) | generated | 3 | 1 | CycloneDX plugin |
| [python-itsdangerous](../benchmarks/references/build-v1/python-itsdangerous/sbom.json) | generated | 2 | 0 | CycloneDX plugin |
| [python-attrs](../benchmarks/references/build-v1/python-attrs/sbom.json) | generated | 2 | 0 | CycloneDX plugin |
| [python-packaging](../benchmarks/references/build-v1/python-packaging/sbom.json) | generated | 2 | 0 | CycloneDX plugin |
| [python-python-certifi](../benchmarks/references/build-v1/python-python-certifi/sbom.json) | generated | 2 | 0 | CycloneDX plugin |
| [rust-ripgrep](../benchmarks/references/build-v1/rust-ripgrep/sbom.json) | generated | 34 | 9 | CycloneDX plugin |
| [rust-fd](../benchmarks/references/build-v1/rust-fd/sbom.json) | generated | 67 | 22 | CycloneDX plugin |
| [rust-bat](../benchmarks/references/build-v1/rust-bat/sbom.json) | generated | 126 | 34 | CycloneDX plugin |
| [rust-dust](../benchmarks/references/build-v1/rust-dust/sbom.json) | generated | 65 | 18 | CycloneDX plugin |
| [rust-bottom](../benchmarks/references/build-v1/rust-bottom/sbom.json) | generated | 121 | 29 | CycloneDX plugin |
| [rust-tokei](../benchmarks/references/build-v1/rust-tokei/sbom.json) | generated | 110 | 20 | CycloneDX plugin |
| [rust-hyperfine](../benchmarks/references/build-v1/rust-hyperfine/sbom.json) | generated | 108 | 15 | CycloneDX plugin |
| [rust-eza](../benchmarks/references/build-v1/rust-eza/sbom.json) | generated | 125 | 28 | CycloneDX plugin |
| [rust-zoxide](../benchmarks/references/build-v1/rust-zoxide/sbom.json) | generated | 70 | 14 | CycloneDX plugin |
| [rust-delta](../benchmarks/references/build-v1/rust-delta/sbom.json) | generated | 141 | 32 | CycloneDX plugin |
| [go-hey](../benchmarks/references/build-v1/go-hey/sbom.json) | generated | 3 | 1 | CycloneDX plugin |
| [go-assetfinder](../benchmarks/references/build-v1/go-assetfinder/sbom.json) | generated | 1 | 0 | CycloneDX plugin |
| [go-httprobe](../benchmarks/references/build-v1/go-httprobe/sbom.json) | generated | 1 | 0 | CycloneDX plugin |
| [go-waybackurls](../benchmarks/references/build-v1/go-waybackurls/sbom.json) | generated | 1 | 0 | CycloneDX plugin |
| [go-unfurl](../benchmarks/references/build-v1/go-unfurl/sbom.json) | generated | 2 | 1 | CycloneDX plugin |
| [go-yq](../benchmarks/references/build-v1/go-yq/sbom.json) | generated | 21 | 17 | CycloneDX plugin |
| [go-lazygit](../benchmarks/references/build-v1/go-lazygit/sbom.json) | generated | 62 | 34 | CycloneDX plugin |
| [go-glow](../benchmarks/references/build-v1/go-glow/sbom.json) | generated | 60 | 23 | CycloneDX plugin |
| [go-scc](../benchmarks/references/build-v1/go-scc/sbom.json) | generated | 15 | 7 | CycloneDX plugin |
| [go-upterm](../benchmarks/references/build-v1/go-upterm/sbom.json) | generated | 71 | 27 | CycloneDX plugin |
| [ruby-rake](../benchmarks/references/build-v1/ruby-rake/sbom.json) | generated | 1 | 0 | Bundler + built gemspec sidecar |
| [ruby-rack](../benchmarks/references/build-v1/ruby-rack/sbom.json) | generated | 1 | 0 | Bundler + built gemspec sidecar |
| [ruby-psych](../benchmarks/references/build-v1/ruby-psych/sbom.json) | generated | 3 | 2 | Bundler + built gemspec sidecar |
| [ruby-json](../benchmarks/references/build-v1/ruby-json/sbom.json) | generated | 1 | 0 | Bundler + built gemspec sidecar |
| [ruby-rexml](../benchmarks/references/build-v1/ruby-rexml/sbom.json) | generated | 1 | 0 | Bundler + built gemspec sidecar |
| [ruby-csv](../benchmarks/references/build-v1/ruby-csv/sbom.json) | generated | 1 | 0 | Bundler + built gemspec sidecar |
| [ruby-bigdecimal](../benchmarks/references/build-v1/ruby-bigdecimal/sbom.json) | generated | 1 | 0 | Bundler + built gemspec sidecar |
| [ruby-logger](../benchmarks/references/build-v1/ruby-logger/sbom.json) | generated | 1 | 0 | Bundler + built gemspec sidecar |
| [ruby-uri](../benchmarks/references/build-v1/ruby-uri/sbom.json) | generated | 1 | 0 | Bundler + built gemspec sidecar |
| [ruby-stringio](../benchmarks/references/build-v1/ruby-stringio/sbom.json) | generated | 1 | 0 | Bundler + built gemspec sidecar |

Повтор: `python benchmarks/build_references.py`, затем `python benchmarks/publish_references.py`. `--id <id> --retry` повторяет отдельный проект.
Полные логи и resolver dumps остаются локально; в Git сохранены SBOM, рецепты, хеши, версии генераторов и компактные native-свидетельства.
Рецепты используют плавающие теги builder-образов; фактически разрешённые digest сохранены в provenance.json. Новая сборка не обещает побайтовое совпадение без закрепления всего окружения и разрешённых зависимостей.

## Генераторы

- [CycloneDX Maven](https://github.com/CycloneDX/cyclonedx-maven-plugin): 2.9.3, aggregate BOM и отдельные BOM выбранных модулей.
- [CycloneDX npm](https://github.com/CycloneDX/cyclonedx-node-npm): 6.0.1, production dependency tree.
- [CycloneDX Python](https://github.com/CycloneDX/cyclonedx-python): 7.5.0, environment установленного проекта с отдельным окружением генератора.
- [cargo-cyclonedx](https://github.com/CycloneDX/cyclonedx-rust-cargo): 0.5.9, CycloneDX 1.5, те же default features и Linux target.
- [cyclonedx-gomod](https://github.com/CycloneDX/cyclonedx-gomod): 1.12.0, app с тем же main и CGO_ENABLED=0.
- [CycloneDX Ruby, закреплённый commit](https://github.com/CycloneDX/cyclonedx-ruby-gem/tree/7efedd6422cc32d9bdefbb6eddb7b4eaa3857309): JSON; это git-версия, не опубликованный gem 1.1.0.
