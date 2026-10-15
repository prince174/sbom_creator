FROM sbom-creator-benchmark/no-lock-parent:2558470d5801cdca7d350e3aedb994a6714c015bca52890a31749a9f80e7c0ae
USER root
RUN find /app -type f \( -name .package-lock.json -o -name bun.lock -o -name bun.lockb -o -name npm-shrinkwrap.json -o -name package-lock.json -o -name pnpm-lock.yaml -o -name yarn.lock \) -print -delete
USER node
