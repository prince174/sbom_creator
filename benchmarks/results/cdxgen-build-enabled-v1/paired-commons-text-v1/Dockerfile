FROM node:24-bookworm-slim@sha256:a5f4366e834695d5f363b920c104953a535d3a9864d1bdf74566a0ebe01daee5 AS node
FROM maven:3.9-eclipse-temurin-17@sha256:1a352420f7aba21f5ad08df31bab55f74c013fb491f1ae8ab1dd7ff9ed698584
COPY --from=node /usr/local/ /usr/local/
RUN npm install --global --ignore-scripts --no-audit --no-fund @cdxgen/cdxgen@13.4.0 && node --version && mvn --version && cdxgen --version
ENV MAVEN_OPTS=-XX:ActiveProcessorCount=2
WORKDIR /tmp
