# Public Java identity DB cache

Java component presence policyv7 не меняется. Этот этап устраняет partial-cache
poisoning при первой загрузке публичной Trivy Java DB. Это не reference build cache,
не Maven .m2, не vulnerability database и не новый resolver.

`SBOM_TRIVY_CACHE_DIR/java-db` содержит ровно `trivy-java.db` и `metadata.json`.
Cache/workspace принадлежит одному сервису; нельзя делить его с недоверенным writer.
R112 peer adapter приводит относительный cache path к одному абсолютному пути
без разрешения симлинков и проверяет ancestors до создания дочерних каталогов
или запуска Trivy. Нарушение даёт фиксированный `CACHE_INVALID`; subprocess cwd
не меняет расположение проверенной DB.
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
