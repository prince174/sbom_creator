# Проверка 60 реальных репозиториев

По 10 репозиториев для Java, JavaScript, Python, Rust, Go и Ruby. Статус checkout/source_scanned/build_complete не означает завершённый тест системы.

Образы собираются отдельным benchmark-процессом из закреплённых checkout. Это контролируемые сборки, а не образы production pipeline. GitHub не подтверждает доступ к Bitbucket. Режим rules не подтверждает качество LLM. FP/FN без независимой полной разметки не рассчитываются.

Image ID в таблице сокращён; полное значение и его тип сохранены в CSV/JSON. INCLUDE/UNKNOWN считают идентичности, а Source/Image/Final — записи пакетов: дубликаты расположений могут давать разные числа. `partial` означает наличие UNKNOWN. Bitbucket fixture без объявленных runtime-зависимостей проверяет доступ и корректность потока, но не полноту поиска реальных зависимостей приложения.

`App image/final` проверяет одну закреплённую release-идентичность основного пакета по точному PURL name/version/ecosystem. Это отдельная ограниченная проверка, не FP/FN всех зависимостей; `false` может означать, что локальная сборка не сохранила release version. `—` означает, что точная ожидаемая идентичность неприменима.

`Сек.` — накопленное время зафиксированных попыток этого репозитория: checkout, source scan, сборки, анализ, повторное чтение cache и replay; записанные неуспешные попытки также включены. Прерванные до checkpoint этапы могут не войти в сумму. Это не измерение производительности production API или LLM. Длительность последнего нового вызова сервиса отдельно записана как `last_analysis_seconds` в JSON.

| Язык | Завершено | Ошибка | Прочее |
|---|---:|---:|---:|
| Java | 10 | 0 | 0 |
| JavaScript | 10 | 0 | 0 |
| Python | 10 | 0 | 0 |
| Rust | 10 | 0 | 0 |
| Go | 10 | 0 | 0 |
| Ruby | 10 | 0 | 0 |

| Репозиторий | Язык | Commit | Image ID | Source | Image | INCLUDE / EXCLUDE / UNKNOWN | Final | App image/final | CDX | Сек. | Режим | Coverage | Статус |
|---|---|---|---|---:|---:|---|---:|---|---|---:|---|---|---|
| [apache/commons-lang](https://github.com/apache/commons-lang) | Java | 29ccc7665f3b | sha256:d82f9d087164 | 21 | 151 | 146/0/25 | 146 | True/True | True | 283.4 | rules | partial | completed_rules |
| [apache/commons-io](https://github.com/apache/commons-io) | Java | be0b1eaea246 | sha256:38a1f1f4bd01 | 26 | 151 | 146/0/30 | 146 | True/True | True | 103.7 | rules | partial | completed_rules |
| [apache/commons-codec](https://github.com/apache/commons-codec) | Java | 965109705c52 | sha256:18cb95743305 | 18 | 151 | 146/0/22 | 146 | True/True | True | 92.2 | rules | partial | completed_rules |
| [apache/commons-text](https://github.com/apache/commons-text) | Java | 9430a2848a25 | sha256:fd013f97ed55 | 27 | 152 | 147/0/30 | 147 | True/True | True | 79.8 | rules | partial | completed_rules |
| [apache/commons-csv](https://github.com/apache/commons-csv) | Java | f2f1cffe53cd | sha256:084dca97a0d6 | 29 | 153 | 148/0/31 | 148 | True/True | True | 108.1 | rules | partial | completed_rules |
| [apache/commons-compress](https://github.com/apache/commons-compress) | Java | 8de4d85b09a5 | sha256:9c7f67f35026 | 49 | 158 | 153/0/48 | 153 | True/True | True | 187.3 | rules | partial | completed_rules |
| [google/gson](https://github.com/google/gson) | Java | 828a97be0f8d | sha256:8d6f4532ead0 | 32 | 152 | 147/0/35 | 147 | True/True | True | 131.0 | rules | partial | completed_rules |
| [jhy/jsoup](https://github.com/jhy/jsoup) | Java | 7c56eb26c8cc | sha256:050cafcf2903 | 17 | 151 | 146/0/21 | 146 | True/True | True | 74.7 | rules | partial | completed_rules |
| [qos-ch/slf4j](https://github.com/qos-ch/slf4j) | Java | 101086ba359a | sha256:7e6ab1b3329a | 43 | 151 | 146/0/46 | 146 | True/True | True | 99.2 | rules | partial | completed_rules |
| [apache/commons-cli](https://github.com/apache/commons-cli) | Java | 698b238276c0 | sha256:54f6e9da0218 | 18 | 151 | 146/0/22 | 146 | True/True | True | 59.4 | rules | partial | completed_rules |
| [lodash/lodash](https://github.com/lodash/lodash) | JavaScript | f299b52f3948 | sha256:ffed631fc804 | 544 | 292 | 277/0/547 | 288 | True/True | True | 156.2 | rules | partial | completed_rules |
| [expressjs/express](https://github.com/expressjs/express) | JavaScript | 1faf228935aa | sha256:50595b92bd7d | 9 | 360 | 343/0/13 | 356 | True/True | True | 174.7 | rules | partial | completed_rules |
| [axios/axios](https://github.com/axios/axios) | JavaScript | b2cb45d5a533 | sha256:274b1038a031 | 37 | 307 | 290/0/32 | 303 | True/True | True | 138.2 | rules | partial | completed_rules |
| [debug-js/debug](https://github.com/debug-js/debug) | JavaScript | 7e3814cc603b | sha256:c5e43b337c04 | 0 | 293 | 277/0/4 | 289 | True/True | True | 177.6 | rules | partial | completed_rules |
| [vercel/ms](https://github.com/vercel/ms) | JavaScript | 1c6264b79549 | sha256:eff82a45a7ee | 2 | 292 | 276/0/6 | 288 | True/True | True | 95.5 | rules | partial | completed_rules |
| [chalk/chalk](https://github.com/chalk/chalk) | JavaScript | 5dbc1e2633f3 | sha256:9b14c9d4ef36 | 3 | 292 | 277/0/7 | 288 | True/True | True | 137.4 | rules | partial | completed_rules |
| [tj/commander.js](https://github.com/tj/commander.js) | JavaScript | e6f56c888c96 | sha256:a4e5313626f8 | 7 | 292 | 277/0/10 | 288 | True/True | True | 99.8 | rules | partial | completed_rules |
| [minimistjs/minimist](https://github.com/minimistjs/minimist) | JavaScript | 6901ee286bc4 | sha256:e3351c86f8cb | 6 | 292 | 277/0/10 | 288 | True/True | True | 130.8 | rules | partial | completed_rules |
| [jonschlinkert/is-number](https://github.com/jonschlinkert/is-number) | JavaScript | 98e8ff1da1a8 | sha256:e17e6f616299 | 0 | 292 | 277/0/4 | 288 | True/True | True | 112.0 | rules | partial | completed_rules |
| [juliangruber/isarray](https://github.com/juliangruber/isarray) | JavaScript | 63ea4ca0a0d6 | sha256:8a4d87dd5859 | 0 | 292 | 277/0/4 | 288 | True/True | True | 100.5 | rules | partial | completed_rules |
| [artifact_graph/python-service](https://bitbucket.org/artifact_graph/python-service) | Python | 973b5e3447f9 | sha256:7b3a96cacdc2 | 0 | 120 | 109/0/6 | 114 | True/True | True | 71.3 | rules | partial; fixture without declared runtime deps | completed_rules |
| [artifact_graph/python-jobs](https://bitbucket.org/artifact_graph/python-jobs) | Python | 776eb037886b | sha256:ed9c816f27d0 | 0 | 120 | 109/0/6 | 114 | True/True | True | 62.7 | rules | partial; fixture without declared runtime deps | completed_rules |
| [artifact_graph/lab-python](https://bitbucket.org/artifact_graph/lab-python) | Python | 93428e3aabeb | sha256:88a82d9a3868 | 0 | 119 | 108/0/6 | 113 | —/— | True | 53.9 | rules | partial; fixture without declared runtime deps | completed_rules |
| [pallets/flask](https://github.com/pallets/flask) | Python | ab8149664182 | sha256:42bff558851c | 35 | 126 | 115/0/41 | 120 | True/True | True | 81.6 | rules | partial | completed_rules |
| [pallets/jinja](https://github.com/pallets/jinja) | Python | 877f6e51be8e | sha256:b9a2ed5100e2 | 10 | 121 | 110/0/16 | 115 | True/True | True | 70.0 | rules | partial | completed_rules |
| [pallets/werkzeug](https://github.com/pallets/werkzeug) | Python | 6389612fd1ee | sha256:6f3b3d35dd5c | 14 | 121 | 110/0/20 | 115 | True/True | True | 76.7 | rules | partial | completed_rules |
| [pallets/itsdangerous](https://github.com/pallets/itsdangerous) | Python | 096c8d42545d | sha256:faffdfe018f0 | 10 | 120 | 109/0/16 | 114 | True/True | True | 67.1 | rules | partial | completed_rules |
| [python-attrs/attrs](https://github.com/python-attrs/attrs) | Python | 598494a61841 | sha256:729e54b83868 | 26 | 120 | 109/0/32 | 114 | True/True | True | 83.9 | rules | partial | completed_rules |
| [pypa/packaging](https://github.com/pypa/packaging) | Python | d8e3b31b7349 | sha256:55b9bc3a43a3 | 11 | 120 | 109/0/17 | 114 | True/True | True | 69.0 | rules | partial | completed_rules |
| [certifi/python-certifi](https://github.com/certifi/python-certifi) | Python | 4ba39005afa1 | sha256:5a060640f6ab | 10 | 120 | 109/0/16 | 114 | True/True | True | 67.4 | rules | partial | completed_rules |
| [BurntSushi/ripgrep](https://github.com/BurntSushi/ripgrep) | Rust | 4649aa970061 | sha256:6240e6eeb7c5 | 65 | 125 | 122/0/35 | 122 | True/True | True | 174.8 | rules | partial; auditable build | completed_rules |
| [sharkdp/fd](https://github.com/sharkdp/fd) | Rust | b19136871310 | sha256:89966e1167bc | 121 | 153 | 150/0/63 | 150 | True/True | True | 108.4 | rules | partial; auditable build | completed_rules |
| [sharkdp/bat](https://github.com/sharkdp/bat) | Rust | 25f4f96ea3af | sha256:b60e53378c6e | 245 | 198 | 195/0/128 | 195 | True/True | True | 126.5 | rules | partial; auditable build | completed_rules |
| [bootandy/dust](https://github.com/bootandy/dust) | Rust | dbd18f90e7b1 | sha256:1047c47e7fa4 | 128 | 151 | 148/0/72 | 148 | True/True | True | 64.5 | rules | partial; auditable build | completed_rules |
| [ClementTsang/bottom](https://github.com/ClementTsang/bottom) | Rust | 2ec1fb56c9db | sha256:286033350077 | 265 | 203 | 200/0/157 | 200 | True/True | True | 186.5 | rules | partial; auditable build | completed_rules |
| [XAMPPRocky/tokei](https://github.com/XAMPPRocky/tokei) | Rust | 7e0b30ff4c1f | sha256:f182dd45038d | 162 | 160 | 157/0/97 | 157 | True/True | True | 73.9 | rules | partial; auditable build | completed_rules |
| [sharkdp/hyperfine](https://github.com/sharkdp/hyperfine) | Rust | 12fec4209864 | sha256:6ac08b3c4517 | 163 | 194 | 191/0/64 | 191 | True/True | True | 59.6 | rules | partial; auditable build | completed_rules |
| [eza-community/eza](https://github.com/eza-community/eza) | Rust | bea5b28591bb | sha256:518448b8a983 | 237 | 209 | 206/0/123 | 206 | True/True | True | 111.3 | rules | partial; auditable build | completed_rules |
| [ajeetdsouza/zoxide](https://github.com/ajeetdsouza/zoxide) | Rust | 3d3267b4fd73 | sha256:4f43a047187f | 142 | 157 | 154/0/80 | 154 | True/True | True | 62.0 | rules | partial; auditable build | completed_rules |
| [dandavison/delta](https://github.com/dandavison/delta) | Rust | a589ff9debae | sha256:b4060d6b0c01 | 232 | 227 | 224/0/100 | 224 | True/True | True | 105.8 | rules | partial; auditable build | completed_rules |
| [rakyll/hey](https://github.com/rakyll/hey) | Go | af177063f85b | sha256:ed0cacd4149e | 2 | 96 | 93/0/3 | 93 | True/True | True | 90.1 | rules | partial; local main module may report (devel) | completed_rules |
| [tomnomnom/assetfinder](https://github.com/tomnomnom/assetfinder) | Go | 4e95d8701aae | sha256:137f611c8e81 | 0 | 94 | 90/0/4 | 90 | False/False | True | 59.6 | rules | partial; GOPATH build without module identity | completed_rules |
| [tomnomnom/httprobe](https://github.com/tomnomnom/httprobe) | Go | 7e8abdb4096a | sha256:dc3f25b6a0aa | 0 | 94 | 91/0/3 | 91 | False/False | True | 61.9 | rules | partial; local main module may report (devel) | completed_rules |
| [tomnomnom/waybackurls](https://github.com/tomnomnom/waybackurls) | Go | 86aeb9785270 | sha256:ff2a77c28aa6 | 0 | 94 | 91/0/3 | 91 | True/True | True | 63.7 | rules | partial; local main module may report (devel) | completed_rules |
| [tomnomnom/unfurl](https://github.com/tomnomnom/unfurl) | Go | 8f10d050f1b0 | sha256:741fb3c8511e | 3 | 95 | 92/0/5 | 92 | True/True | True | 65.4 | rules | partial; local main module may report (devel) | completed_rules |
| [mikefarah/yq](https://github.com/mikefarah/yq) | Go | 4839dbbf8044 | sha256:5284383fdaf2 | 41 | 114 | 111/0/24 | 111 | False/False | True | 119.9 | rules | partial; local main module may report (devel) | completed_rules |
| [jesseduffield/lazygit](https://github.com/jesseduffield/lazygit) | Go | 611fabde11d2 | sha256:0dbb3910e2d1 | 91 | 155 | 152/0/33 | 152 | True/True | True | 167.5 | rules | partial; local main module may report (devel) | completed_rules |
| [charmbracelet/glow](https://github.com/charmbracelet/glow) | Go | 67243bb6fbf6 | sha256:ed875f3750ac | 76 | 153 | 150/0/20 | 150 | False/False | True | 115.8 | rules | partial; local main module may report (devel) | completed_rules |
| [boyter/scc](https://github.com/boyter/scc) | Go | 965213f77b51 | sha256:6201ad162e57 | 31 | 108 | 105/0/20 | 105 | False/False | True | 97.2 | rules | partial; local main module may report (devel) | completed_rules |
| [owenthereal/upterm](https://github.com/owenthereal/upterm) | Go | 9b63f77cf206 | sha256:5c2684176f51 | 118 | 164 | 161/0/51 | 161 | True/True | True | 158.2 | rules | partial; local main module may report (devel) | completed_rules |
| [ruby/rake](https://github.com/ruby/rake) | Ruby | d84f6ef7f354 | sha256:00afff04127b | 15 | 185 | 179/0/21 | 179 | True/True | True | 83.8 | rules | partial | completed_rules |
| [rack/rack](https://github.com/rack/rack) | Ruby | 0eabeb73b3fb | sha256:7cb624285533 | 7 | 185 | 179/0/13 | 179 | True/True | True | 57.9 | rules | partial | completed_rules |
| [ruby/psych](https://github.com/ruby/psych) | Ruby | 746e1ad24dbb | sha256:c10c622c130b | 11 | 185 | 179/0/17 | 179 | True/True | True | 52.6 | rules | partial | completed_rules |
| [ruby/json](https://github.com/ruby/json) | Ruby | f745ec145ef8 | sha256:79e3e5229cb8 | 4 | 185 | 179/0/10 | 179 | True/True | True | 56.9 | rules | partial | completed_rules |
| [ruby/rexml](https://github.com/ruby/rexml) | Ruby | 38eaa86ac7ab | sha256:761cb2c636a8 | 7 | 185 | 179/0/13 | 179 | True/True | True | 54.3 | rules | partial | completed_rules |
| [ruby/csv](https://github.com/ruby/csv) | Ruby | eb20531db251 | sha256:3be0581905de | 9 | 185 | 179/0/15 | 179 | True/True | True | 51.8 | rules | partial | completed_rules |
| [ruby/bigdecimal](https://github.com/ruby/bigdecimal) | Ruby | ae3915ba8831 | sha256:16f0e59a2846 | 6 | 185 | 179/0/12 | 179 | True/True | True | 60.3 | rules | partial | completed_rules |
| [ruby/logger](https://github.com/ruby/logger) | Ruby | 216cedef7ce2 | sha256:fde273e6bdac | 8 | 185 | 179/0/14 | 179 | True/True | True | 46.7 | rules | partial | completed_rules |
| [ruby/uri](https://github.com/ruby/uri) | Ruby | e46960a467f2 | sha256:a41aac33b57d | 13 | 185 | 179/0/19 | 179 | True/True | True | 47.1 | rules | partial | completed_rules |
| [ruby/stringio](https://github.com/ruby/stringio) | Ruby | 7cc9fb1bf54d | sha256:6a342134c457 | 12 | 185 | 179/0/18 | 179 | True/True | True | 48.7 | rules | partial | completed_rules |
