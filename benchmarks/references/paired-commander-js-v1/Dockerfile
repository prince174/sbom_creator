FROM node:22-bookworm-slim@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392 AS build
RUN npm install --global @cyclonedx/cyclonedx-npm@6.0.1
WORKDIR /src
COPY src/ /src/
RUN npm install --package-lock=true --ignore-scripts --no-audit --no-fund && npm run build --if-present && mkdir /reference /packages && node -e "if (!require('./package.json').scripts?.build) require('child_process').execFileSync('npm', ['pack', '--ignore-scripts', '--pack-destination', '/packages'], {stdio: 'inherit'})" && npm prune --omit=dev --ignore-scripts --no-audit --no-fund && cyclonedx-npm --omit dev --spec-version 1.6 --output-file /reference/sbom.json && cp package-lock.json /reference/package-lock.json && node --version > /reference/node-version.txt && npm --version > /reference/npm-version.txt

FROM node:22-bookworm-slim@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392 AS runtime
WORKDIR /app
COPY --from=build /src/ /app/
USER node
CMD ["node", "-e", "console.log('benchmark image; application is not executed')"]
