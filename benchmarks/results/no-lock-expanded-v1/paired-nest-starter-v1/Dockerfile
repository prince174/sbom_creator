FROM sbom-creator-benchmark/no-lock-parent:94af58775302e0f722a7ea82e805551584aadaf31976acc16f25c9bc71ddf9c1
USER root
RUN find /app -type f \( -name .package-lock.json -o -name bun.lock -o -name bun.lockb -o -name npm-shrinkwrap.json -o -name package-lock.json -o -name pnpm-lock.yaml -o -name yarn.lock \) -print -delete
USER node
