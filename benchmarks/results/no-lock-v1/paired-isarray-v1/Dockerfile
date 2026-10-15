FROM sbom-creator-benchmark/no-lock-parent:bc5aada8fe2a89186bb1fe0b9b4b70f85899f32af827dfb457257822a097f9c1
USER root
RUN find /app -type f \( -name .package-lock.json -o -name bun.lock -o -name bun.lockb -o -name npm-shrinkwrap.json -o -name package-lock.json -o -name pnpm-lock.yaml -o -name yarn.lock \) -print -delete
USER node
