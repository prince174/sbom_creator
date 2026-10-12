FROM node:22-bookworm-slim AS build
RUN npm install --global @cyclonedx/cyclonedx-npm@6.0.1
WORKDIR /src
COPY src/ /src/
RUN npm install --ignore-scripts --no-audit --no-fund && mkdir /reference && npm run build && npm prune --omit=dev --ignore-scripts && cyclonedx-npm --omit dev --spec-version 1.6 --output-file /reference/sbom.json && npm ls --all --omit=dev --json > /reference/resolved.json
FROM scratch AS export
COPY --from=build /reference/ /
