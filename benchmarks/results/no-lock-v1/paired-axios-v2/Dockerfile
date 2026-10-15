FROM sbom-creator-benchmark/no-lock-parent:dadaf680f93f7c9fb886ce087a9cc3f8c1c29258551b46424e93bcc3f8c8f256
USER root
RUN find /app -type f \( -name .package-lock.json -o -name bun.lock -o -name bun.lockb -o -name npm-shrinkwrap.json -o -name package-lock.json -o -name pnpm-lock.yaml -o -name yarn.lock \) -print -delete
USER node
