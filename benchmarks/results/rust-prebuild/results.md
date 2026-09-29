# Проверка 60 реальных репозиториев

По 10 репозиториев для Java, JavaScript, Python, Rust, Go и Ruby. Статус checkout/source_scanned/build_complete не означает завершённый тест системы.

Образы собираются отдельным benchmark-процессом из закреплённых checkout. Это контролируемые сборки, а не образы production pipeline. GitHub не подтверждает доступ к Bitbucket. Режим rules не подтверждает качество LLM. FP/FN без независимой полной разметки не рассчитываются.

Image ID в таблице сокращён; полное значение и его тип сохранены в CSV/JSON. INCLUDE/UNKNOWN считают идентичности, а Source/Image/Final — записи пакетов: дубликаты расположений могут давать разные числа. `partial` означает наличие UNKNOWN. Bitbucket fixture без объявленных runtime-зависимостей проверяет доступ и корректность потока, но не полноту поиска реальных зависимостей приложения.

`App image/final` проверяет одну закреплённую release-идентичность основного пакета по точному PURL name/version/ecosystem. Это отдельная ограниченная проверка, не FP/FN всех зависимостей; `false` может означать, что локальная сборка не сохранила release version. `—` означает, что точная ожидаемая идентичность неприменима.

| Язык | Завершено | Ошибка | Прочее |
|---|---:|---:|---:|
| Java | 0 | 0 | 10 |
| JavaScript | 0 | 0 | 10 |
| Python | 0 | 0 | 10 |
| Rust | 0 | 0 | 10 |
| Go | 0 | 0 | 10 |
| Ruby | 0 | 0 | 10 |

| Репозиторий | Язык | Commit | Image ID | Source | Image | INCLUDE / EXCLUDE / UNKNOWN | Final | App image/final | CDX | Сек. | Режим | Coverage | Статус |
|---|---|---|---|---:|---:|---|---:|---|---|---:|---|---|---|
| [https://bitbucket.org/artifact_graph/java-maven-api](https://bitbucket.org/artifact_graph/java-maven-api) | Java | 33181ac8fd00 | — | — | — | —/—/— | — | —/— | — | 0.0 | — | not measured; fixture without declared runtime deps | pending |
| [https://bitbucket.org/artifact_graph/java-gradle-worker](https://bitbucket.org/artifact_graph/java-gradle-worker) | Java | 98772093571e | — | — | — | —/—/— | — | —/— | — | 0.0 | — | not measured; fixture without declared runtime deps | pending |
| [https://bitbucket.org/artifact_graph/java-maven-orders](https://bitbucket.org/artifact_graph/java-maven-orders) | Java | 6c1064a74596 | — | — | — | —/—/— | — | —/— | — | 0.0 | — | not measured; fixture without declared runtime deps | pending |
| [https://bitbucket.org/artifact_graph/java-gradle-billing](https://bitbucket.org/artifact_graph/java-gradle-billing) | Java | f162358c264d | — | — | — | —/—/— | — | —/— | — | 0.0 | — | not measured; fixture without declared runtime deps | pending |
| [https://bitbucket.org/artifact_graph/lab-maven](https://bitbucket.org/artifact_graph/lab-maven) | Java | beede5f2c6db | — | — | — | —/—/— | — | —/— | — | 0.0 | — | not measured; fixture without declared runtime deps | pending |
| [apache/commons-compress](https://github.com/apache/commons-compress) | Java | 8de4d85b09a5 | — | — | — | —/—/— | — | —/— | — | 0.0 | — | not measured | pending |
| [google/gson](https://github.com/google/gson) | Java | 828a97be0f8d | — | — | — | —/—/— | — | —/— | — | 0.0 | — | not measured | pending |
| [jhy/jsoup](https://github.com/jhy/jsoup) | Java | 7c56eb26c8cc | — | — | — | —/—/— | — | —/— | — | 0.0 | — | not measured | pending |
| [qos-ch/slf4j](https://github.com/qos-ch/slf4j) | Java | 101086ba359a | — | — | — | —/—/— | — | —/— | — | 0.0 | — | not measured | pending |
| [apache/commons-cli](https://github.com/apache/commons-cli) | Java | 698b238276c0 | — | — | — | —/—/— | — | —/— | — | 0.0 | — | not measured | pending |
| [https://bitbucket.org/artifact_graph/npm-frontend](https://bitbucket.org/artifact_graph/npm-frontend) | JavaScript | 56e0ef7c4b26 | — | — | — | —/—/— | — | —/— | — | 0.0 | — | not measured; fixture without declared runtime deps | pending |
| [https://bitbucket.org/artifact_graph/npm-admin](https://bitbucket.org/artifact_graph/npm-admin) | JavaScript | b0bc039a3532 | — | — | — | —/—/— | — | —/— | — | 0.0 | — | not measured; fixture without declared runtime deps | pending |
| [https://bitbucket.org/artifact_graph/lab-npm](https://bitbucket.org/artifact_graph/lab-npm) | JavaScript | 8f542c549cc5 | — | — | — | —/—/— | — | —/— | — | 0.0 | — | not measured; fixture without declared runtime deps | pending |
| [debug-js/debug](https://github.com/debug-js/debug) | JavaScript | 7e3814cc603b | — | — | — | —/—/— | — | —/— | — | 0.0 | — | not measured | pending |
| [vercel/ms](https://github.com/vercel/ms) | JavaScript | 1c6264b79549 | — | — | — | —/—/— | — | —/— | — | 0.0 | — | not measured | pending |
| [chalk/chalk](https://github.com/chalk/chalk) | JavaScript | 5dbc1e2633f3 | — | — | — | —/—/— | — | —/— | — | 0.0 | — | not measured | pending |
| [tj/commander.js](https://github.com/tj/commander.js) | JavaScript | e6f56c888c96 | — | — | — | —/—/— | — | —/— | — | 0.0 | — | not measured | pending |
| [minimistjs/minimist](https://github.com/minimistjs/minimist) | JavaScript | 6901ee286bc4 | — | — | — | —/—/— | — | —/— | — | 0.0 | — | not measured | pending |
| [jonschlinkert/is-number](https://github.com/jonschlinkert/is-number) | JavaScript | 98e8ff1da1a8 | — | — | — | —/—/— | — | —/— | — | 0.0 | — | not measured | pending |
| [juliangruber/isarray](https://github.com/juliangruber/isarray) | JavaScript | 63ea4ca0a0d6 | — | — | — | —/—/— | — | —/— | — | 0.0 | — | not measured | pending |
| [https://bitbucket.org/artifact_graph/python-service](https://bitbucket.org/artifact_graph/python-service) | Python | 973b5e3447f9 | — | — | — | —/—/— | — | —/— | — | 0.0 | — | not measured; fixture without declared runtime deps | pending |
| [https://bitbucket.org/artifact_graph/python-jobs](https://bitbucket.org/artifact_graph/python-jobs) | Python | 776eb037886b | — | — | — | —/—/— | — | —/— | — | 0.0 | — | not measured; fixture without declared runtime deps | pending |
| [https://bitbucket.org/artifact_graph/lab-python](https://bitbucket.org/artifact_graph/lab-python) | Python | 93428e3aabeb | — | — | — | —/—/— | — | —/— | — | 0.0 | — | not measured; fixture without declared runtime deps | pending |
| [pallets/flask](https://github.com/pallets/flask) | Python | ab8149664182 | — | — | — | —/—/— | — | —/— | — | 0.0 | — | not measured | pending |
| [pallets/jinja](https://github.com/pallets/jinja) | Python | 877f6e51be8e | — | — | — | —/—/— | — | —/— | — | 0.0 | — | not measured | pending |
| [pallets/werkzeug](https://github.com/pallets/werkzeug) | Python | 6389612fd1ee | — | — | — | —/—/— | — | —/— | — | 0.0 | — | not measured | pending |
| [pallets/itsdangerous](https://github.com/pallets/itsdangerous) | Python | 096c8d42545d | — | — | — | —/—/— | — | —/— | — | 0.0 | — | not measured | pending |
| [python-attrs/attrs](https://github.com/python-attrs/attrs) | Python | 598494a61841 | — | — | — | —/—/— | — | —/— | — | 0.0 | — | not measured | pending |
| [pypa/packaging](https://github.com/pypa/packaging) | Python | d8e3b31b7349 | — | — | — | —/—/— | — | —/— | — | 0.0 | — | not measured | pending |
| [certifi/python-certifi](https://github.com/certifi/python-certifi) | Python | 4ba39005afa1 | — | — | — | —/—/— | — | —/— | — | 0.0 | — | not measured | pending |
| [BurntSushi/ripgrep](https://github.com/BurntSushi/ripgrep) | Rust | 4649aa970061 | sha256:6240e6eeb7c5 | 65 | — | —/—/— | — | —/— | — | 145.4 | — | not measured; auditable build | build_complete |
| [sharkdp/fd](https://github.com/sharkdp/fd) | Rust | b19136871310 | sha256:89966e1167bc | 121 | — | —/—/— | — | —/— | — | 81.0 | — | not measured; auditable build | build_complete |
| [sharkdp/bat](https://github.com/sharkdp/bat) | Rust | 25f4f96ea3af | sha256:b60e53378c6e | 245 | — | —/—/— | — | —/— | — | 86.1 | — | not measured; auditable build | build_complete |
| [bootandy/dust](https://github.com/bootandy/dust) | Rust | dbd18f90e7b1 | sha256:1047c47e7fa4 | 128 | — | —/—/— | — | —/— | — | 36.3 | — | not measured; auditable build | build_complete |
| [ClementTsang/bottom](https://github.com/ClementTsang/bottom) | Rust | 2ec1fb56c9db | sha256:286033350077 | 265 | — | —/—/— | — | —/— | — | 151.7 | — | not measured; auditable build | build_complete |
| [XAMPPRocky/tokei](https://github.com/XAMPPRocky/tokei) | Rust | 7e0b30ff4c1f | sha256:f182dd45038d | 162 | — | —/—/— | — | —/— | — | 43.5 | — | not measured; auditable build | build_complete |
| [sharkdp/hyperfine](https://github.com/sharkdp/hyperfine) | Rust | 12fec4209864 | sha256:6ac08b3c4517 | 163 | — | —/—/— | — | —/— | — | 30.2 | — | not measured; auditable build | build_complete |
| [eza-community/eza](https://github.com/eza-community/eza) | Rust | bea5b28591bb | sha256:518448b8a983 | 237 | — | —/—/— | — | —/— | — | 77.5 | — | not measured; auditable build | build_complete |
| [ajeetdsouza/zoxide](https://github.com/ajeetdsouza/zoxide) | Rust | 3d3267b4fd73 | sha256:4f43a047187f | 142 | — | —/—/— | — | —/— | — | 35.1 | — | not measured; auditable build | build_complete |
| [dandavison/delta](https://github.com/dandavison/delta) | Rust | a589ff9debae | sha256:b4060d6b0c01 | 232 | — | —/—/— | — | —/— | — | 74.3 | — | not measured; auditable build | build_complete |
| [rakyll/hey](https://github.com/rakyll/hey) | Go | af177063f85b | — | — | — | —/—/— | — | —/— | — | 0.0 | — | not measured; local main module may report (devel) | pending |
| [tomnomnom/assetfinder](https://github.com/tomnomnom/assetfinder) | Go | 4e95d8701aae | — | — | — | —/—/— | — | —/— | — | 0.0 | — | not measured; GOPATH build without module identity | pending |
| [tomnomnom/httprobe](https://github.com/tomnomnom/httprobe) | Go | 7e8abdb4096a | — | — | — | —/—/— | — | —/— | — | 0.0 | — | not measured; local main module may report (devel) | pending |
| [tomnomnom/waybackurls](https://github.com/tomnomnom/waybackurls) | Go | 86aeb9785270 | — | — | — | —/—/— | — | —/— | — | 0.0 | — | not measured; local main module may report (devel) | pending |
| [tomnomnom/unfurl](https://github.com/tomnomnom/unfurl) | Go | 8f10d050f1b0 | — | — | — | —/—/— | — | —/— | — | 0.0 | — | not measured; local main module may report (devel) | pending |
| [mikefarah/yq](https://github.com/mikefarah/yq) | Go | 4839dbbf8044 | — | — | — | —/—/— | — | —/— | — | 0.0 | — | not measured; local main module may report (devel) | pending |
| [jesseduffield/lazygit](https://github.com/jesseduffield/lazygit) | Go | 611fabde11d2 | — | — | — | —/—/— | — | —/— | — | 0.0 | — | not measured; local main module may report (devel) | pending |
| [charmbracelet/glow](https://github.com/charmbracelet/glow) | Go | 67243bb6fbf6 | — | — | — | —/—/— | — | —/— | — | 0.0 | — | not measured; local main module may report (devel) | pending |
| [boyter/scc](https://github.com/boyter/scc) | Go | 965213f77b51 | — | — | — | —/—/— | — | —/— | — | 0.0 | — | not measured; local main module may report (devel) | pending |
| [owenthereal/upterm](https://github.com/owenthereal/upterm) | Go | 9b63f77cf206 | — | — | — | —/—/— | — | —/— | — | 0.0 | — | not measured; local main module may report (devel) | pending |
| [ruby/rake](https://github.com/ruby/rake) | Ruby | d84f6ef7f354 | — | — | — | —/—/— | — | —/— | — | 0.0 | — | not measured | pending |
| [rack/rack](https://github.com/rack/rack) | Ruby | 0eabeb73b3fb | — | — | — | —/—/— | — | —/— | — | 0.0 | — | not measured | pending |
| [ruby/psych](https://github.com/ruby/psych) | Ruby | 746e1ad24dbb | — | — | — | —/—/— | — | —/— | — | 0.0 | — | not measured | pending |
| [ruby/json](https://github.com/ruby/json) | Ruby | f745ec145ef8 | — | — | — | —/—/— | — | —/— | — | 0.0 | — | not measured | pending |
| [ruby/rexml](https://github.com/ruby/rexml) | Ruby | 38eaa86ac7ab | — | — | — | —/—/— | — | —/— | — | 0.0 | — | not measured | pending |
| [ruby/csv](https://github.com/ruby/csv) | Ruby | eb20531db251 | — | — | — | —/—/— | — | —/— | — | 0.0 | — | not measured | pending |
| [ruby/bigdecimal](https://github.com/ruby/bigdecimal) | Ruby | ae3915ba8831 | — | — | — | —/—/— | — | —/— | — | 0.0 | — | not measured | pending |
| [ruby/logger](https://github.com/ruby/logger) | Ruby | 216cedef7ce2 | — | — | — | —/—/— | — | —/— | — | 0.0 | — | not measured | pending |
| [ruby/uri](https://github.com/ruby/uri) | Ruby | e46960a467f2 | — | — | — | —/—/— | — | —/— | — | 0.0 | — | not measured | pending |
| [ruby/stringio](https://github.com/ruby/stringio) | Ruby | 7cc9fb1bf54d | — | — | — | —/—/— | — | —/— | — | 0.0 | — | not measured | pending |
