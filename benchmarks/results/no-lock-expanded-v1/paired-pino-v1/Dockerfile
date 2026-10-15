FROM sbom-creator-benchmark/no-lock-parent:0f957f9c66bbb6c8aa26692be666d5885bc05c9cc3920996dcfc1a1b06aebad3
USER root
RUN find /app -type f \( -name .package-lock.json -o -name bun.lock -o -name bun.lockb -o -name npm-shrinkwrap.json -o -name package-lock.json -o -name pnpm-lock.yaml -o -name yarn.lock \) -print -delete
USER node
