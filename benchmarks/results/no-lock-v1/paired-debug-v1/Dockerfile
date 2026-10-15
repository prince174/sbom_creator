FROM sbom-creator-benchmark/no-lock-parent:0a609007e6974d34c75c15f52d26fa41df6f7ce27a615a64e2ccd66d8ae9fe86
USER root
RUN find /app -type f \( -name .package-lock.json -o -name bun.lock -o -name bun.lockb -o -name npm-shrinkwrap.json -o -name package-lock.json -o -name pnpm-lock.yaml -o -name yarn.lock \) -print -delete
USER node
