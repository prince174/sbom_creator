FROM python:3.12-slim-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/* && python -m venv /generator && /generator/bin/pip install cyclonedx-bom==7.5.0
WORKDIR /src
COPY src/ /src/
RUN mkdir /reference && python -m venv /project && /project/bin/pip install /src && /project/bin/pip inspect > /reference/resolved.json && /generator/bin/cyclonedx-py environment /project/bin/python --pyproject /src/pyproject.toml --spec-version 1.6 --output-file /reference/sbom.json
FROM scratch AS export
COPY --from=build /reference/ /
