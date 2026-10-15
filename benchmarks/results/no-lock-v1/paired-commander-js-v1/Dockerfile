FROM sbom-creator-benchmark/no-lock-parent:71ceac155e22701e792355d878ec452d8d37e243128fec74779eaa9c86bf00e1
USER root
RUN find /app -type f \( -name .package-lock.json -o -name bun.lock -o -name bun.lockb -o -name npm-shrinkwrap.json -o -name package-lock.json -o -name pnpm-lock.yaml -o -name yarn.lock \) -print -delete
USER node
