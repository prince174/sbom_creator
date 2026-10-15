FROM sbom-creator-benchmark/no-lock-parent:a929529dd99c73e2d037d0b7226f2075cc1cd0265f12b55a922709709326fa7b
USER root
RUN find /app -type f \( -name .package-lock.json -o -name bun.lock -o -name bun.lockb -o -name npm-shrinkwrap.json -o -name package-lock.json -o -name pnpm-lock.yaml -o -name yarn.lock \) -print -delete
USER node
