FROM sbom-creator-benchmark/no-lock-parent:10ff4cc933082da73b37aaf5883d391e1ea739a4882512f5e18a57688d20dd68
USER root
RUN find /app -type f \( -name .package-lock.json -o -name bun.lock -o -name bun.lockb -o -name npm-shrinkwrap.json -o -name package-lock.json -o -name pnpm-lock.yaml -o -name yarn.lock \) -print -delete
USER node
