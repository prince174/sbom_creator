# R33 — cdxgen pre-build compatibility check

2026-10-14. cdxgen13.4.0, commit b84786dec587a20deb605192087388fc0604b12d.
Node24.19.0 Windows/amd64; pnpm12.10.1, frozen lock, ignore-scripts, prod.
pnpm Windows executable получен из официального npm registry, SHA512 проверен.
Инструмент установлен только во внешнем benchmark cache.

Два exact-commit clean checkout: Gson и Commons Text. Переданы только исходники;
build CDX, effective POM и image не передавались. Режим java/pre-build,
no-install-deps/no-resolve-class/no-recurse, spec1.6. Node permission model
запрещает child processes и запись вне output/temp директории; чтение разрешено.
Это ограничение benchmark, не утверждение о защите от всей сети/чтения.

| Проект | Exit | SBOM | Причина |
|---|---:|---|---|
| Gson |1|нет|ChildProcess denied|
| Commons Text |1|нет|ChildProcess denied|

Повтор с очищенной средой подтвердил тот же отказ. Вызов в
[jvmBom.js:816](https://github.com/cdxgen/cdxgen/blob/b84786dec587a20deb605192087388fc0604b12d/lib/cli/jvmBom.js#L816)
пытается выполнить Maven dependency:tree для определения parent component.
Следовательно, выбранный pre-build режим на этих POM не завершает scan при
запрете процессов. Это mode compatibility failure, не нулевая точность cdxgen.
Результат режима с разрешёнными build tools неизвестен.

Первоначальный ограниченный fs-read отказал при поиске Python в PATH;
после расширения чтения отказала запись временной директории. TEMP/TMP перенесены
в benchmark output. Затем оба scan остановились на запрете child process.
Логи сохранены локально, значения секретов не публикуются.

Ruff passed. Runtime0.7.0 и source checkouts не менялись, deployment не было.
Direct metrics null. Версии, SHA node и lockfile сохранены в отчёте.

```powershell
.venv/Scripts/python.exe -X utf8 benchmarks/check_cdxgen_prebuild.py --node <node24.exe>
```

Предусловия: pinned cdxgen checkout и установленный frozen lock в
benchmarks/.work/cdxgen-r33. Harness отказывается перезаписывать готовый SBOM.
Следующий шаг: отдельный build-enabled прогон в изолированном внешнем стенде
с фиксацией выполненных команд, либо независимый Trivy source baseline.
[Машинный результат](cdxgen-prebuild-v1.json).
