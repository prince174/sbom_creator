# Public Java identity DB cache — R111

Java component presence policyv7 не меняется. Этот этап устраняет partial-cache
poisoning при первой загрузке публичной Trivy Java DB. Это не reference build cache,
не Maven .m2, не vulnerability database и не новый resolver.

`SBOM_TRIVY_CACHE_DIR/java-db` содержит ровно `trivy-java.db` и `metadata.json`.
Cache/workspace принадлежит одному сервису; нельзя делить его с недоверенным writer.
Нормальный warm path не создаёт stage/lock и не обновляет DB: Version1 metadata,
timezone-aware dates, supported SQLite header/page count, exact schema/PK/nonpartial hash
index/query plan и полный физический SHA256 проверяются read-only. Stale NextUpdate
не запускает сеть: факт сохраняется как `database_stale=true`. DownloadedAt необязателен.
SHA1 lookup остаётся index association, не publisher authenticity/global GAV proof.

Только отсутствующий target допускает один download в private sibling stage на том
же filesystem. Download600s,2GiB stage/10,000entries; post-exit stage limits проверяются
ещё раз. Metadata<=16KiB; SHA stream1MiB/file<=2GiB. Metadata duplicate keys, links/
junctions/hardlinks, missing/extra files, bad SQLite layout/schema/index отклоняются.
SQLite schema VM ограничен100callbacks×1000steps и2s, lookup — прежним query budget.
Полный quick_check не используется: на валидной1.55GBDB он не уложился в2s; это
не свидетельство повреждения. Полная SQLite integrity не утверждается.

Публикация меняет видимость всей directory-пары: Windows rename без overwrite,
Linux renameat2(RENAME_NOREPLACE). Даже появившийся пустой чужой target не заменяется.
Unsupported platform/filesystem даёт UNKNOWN. Это atomic visibility, а не fsync/
power-loss durability или защита от hostile concurrent writer. Cold O_EXCL lock
предотвращает повторную загрузку cooperating jobs; производительная параллельная
эксплуатация не сертифицирована. Законченный invalid cache и чужие locks/orphan stages
никогда не удаляются автоматически.

| Fixed provenance code | Поведение и восстановление |
|---|---|
| CACHE_INVALID | Существующая directory сохранена. Остановите активные задания, проверьте bytes/metadata/permissions; при подтверждённой порче сохраните всю directory в отдельном quarantine. Новый bootstrap требует отсутствующего java-db target, не оставшейся пустой directory. |
| BOOTSTRAP_BUSY | Не начинается второй download. Дождитесь активного задания. После crash сначала убедитесь в отсутствии writer; только затем оператор разбирает сохранённый lock. |
| DOWNLOAD_FAILED | Отсутствующий target остаётся отсутствующим, очищен только собственный stage/lock. Проверьте доступ к публичному registry/CA/лимиты; retry отдельным заданием после backoff, без внутреннего бесконечного цикла. |
| DOWNLOAD_INVALID | Неполный/unsupported/over-budget staged snapshot не опубликован. Сохранённый ранее cache не заменяется. |
| PUBLICATION_FAILED | Target не заменён. Проверьте competing writer и поддержку atomic no-replace filesystem; manual unsafe-copy fallback отсутствует. |

Коды — фиксированные enum. Текст SQLite/downloader exception, URL query и путь cache
в диагностическое поле не экспортируются. Java остаётся UNKNOWN, raw inventory и
подтверждённые nonJava сохраняются; неподтверждённые raw packages не становятся final.
Операционные действия с cache — обязанность оператора; эта работа не меняла deployment,
его secret/config или существующий benchmark cache.

## Воспроизводимость

Warm peer regression:2freshTrivy scans REST252/DBCP4 raw instances точно равны R110
по identities/properties/paths/layers/config, без Syft/physical/publisher/oracle;
старая публичная DB и metadata не менялись. Этот v1 snapshot сделан до дополнительного
cache-parent-before-mkdir guard; valid-cache lookup/scan алгоритм тот же. Итоговый
Linux cold/warm pipeline проверяет уже окончательный candidate.

[Official Trivy DB operation](https://trivy.dev/docs/dev/configuration/db/) отделяет
Java identity index от CVE DB; реальные flags закреплённого0.75binary проверены.
Mutable public repository tags не являются immutable provenance; actual bytes/SHA,
metadata и tool versions фиксируются на каждом анализе. При offline переносе используйте
целую проверенную directory и сверяйте SHA; не передавайте source/reference caches.


## Измеренный первый запуск

Installed image `sbom-creator:mvp-r111`, configID
`sha256:4b31c639de2cb444b115dd5ced5bf1fbc9ce98cf3657b6fd2f0923a867f13698`.
На новой native Docker volume без старой DB: один public cold download100.489s,
validation/publication2.213s, actual image-only DBCP pipeline110.125s. Warm container
с той же новой DB и network-none:9.171s, download0.0, validation2.017s.
Все final/os/full4/0/4 равны между cold/warm и прежнему R110 DBCP по coordinates.
Это compatibility3/0/0 known delivered dependencies на одном контроле, не новая
точность всего корпуса. Источники/референсы/секреты/socket не монтировались.
Cold networkbridge использовал публичные default endpoints, не egress allowlist.

Скачанная DB **отличается** от использованного для полной метрики R110 snapshot:

- New:1,554,915,328B,SHA256`491fe2ddb9cfd09bfb1e216d49541e9b64628621ce3538c23ecee5864bfefd59`.
- MetadataSHA256`40b61a18939abfcdbedb76959f5c548100ad245f0a04ca4949b67d90a9078bb2`,
  UpdatedAt2026-10-16T01:00:20.589203513Z,NextUpdate2026-10-19T01:00:20.589203Z.
- Old measured:1,553,915,904B,SHA256`c26ec91db03a11014dfa45909d2b5275c0e34c2dee276363bc0c9693375acc25`.

Прежние Java3862/20/18 и JS307/9/0 не пересчитаны на новой DB. JS вообще не требует
JavaDB. Новый public index пока проверен только DBCP cold/warm; переносить старый
Java aggregate автоматически нельзя. Original measured DB сохранена неизменной.
[Sealed stage summary](../benchmarks/results/mvp-r111-summary-v1/report.json).

Linux native preflight проверил6symlink cases (включая linked ancestor/new child),
empty/nonempty no-replace и positive toy cold/warm без сети/публичнойDB/oracle,0skips.
UID10001/read-only/no capabilities/socket/credentials,3GiB2CPU. Сохранён новый volume
со snapshot;48installed hashes совпадают с frozen executing source. Не утверждается
peakRSS/hardquota/concurrent throughput. Первоначальный v1 CLI preflight не дошёл до
build/network: sanitized host env не находил buildx. v2 восстановил только nonsecret
host plugin-discovery paths. Реальных public download попыток — одна.
