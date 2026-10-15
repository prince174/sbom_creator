FROM sbom-creator-benchmark/no-lock-parent:b14745436ea64b61a38f82557f088af35e7d36a13ccbb7ad5bfc59fddb3df5ec
USER root
RUN find /app -type f \( -name .package-lock.json -o -name bun.lock -o -name bun.lockb -o -name npm-shrinkwrap.json -o -name package-lock.json -o -name pnpm-lock.yaml -o -name yarn.lock \) -print -delete
USER node
