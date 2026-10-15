FROM sbom-creator-benchmark/no-lock-parent:5e7a1c2f6851bed2fc2cc11679afd3ce422e46f4a91aee8446a25d7cd09161e7
USER root
RUN find /app -type f \( -name .package-lock.json -o -name bun.lock -o -name bun.lockb -o -name npm-shrinkwrap.json -o -name package-lock.json -o -name pnpm-lock.yaml -o -name yarn.lock \) -print -delete
USER node
