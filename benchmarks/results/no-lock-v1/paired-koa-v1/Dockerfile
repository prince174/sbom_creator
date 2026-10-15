FROM sbom-creator-benchmark/no-lock-parent:9f8dd873ee97609ad1a5a9096fb190d22901924be9d932b93679a8e922bbfcf4
USER root
RUN find /app -type f \( -name .package-lock.json -o -name bun.lock -o -name bun.lockb -o -name npm-shrinkwrap.json -o -name package-lock.json -o -name pnpm-lock.yaml -o -name yarn.lock \) -print -delete
USER node
