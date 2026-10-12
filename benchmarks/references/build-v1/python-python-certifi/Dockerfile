FROM python:3.12-slim-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/* && python -m venv /generator && /generator/bin/pip install cyclonedx-bom==7.5.0
WORKDIR /src
COPY src/ /src/
RUN mkdir /reference && python -m venv /project && /project/bin/pip install /src && /project/bin/pip inspect > /reference/resolved.json && /project/bin/python -c 'import importlib.metadata as m,json; d=m.distribution("certifi"); open("/reference/root.pyproject.toml","w").write("[project]\nname = "+json.dumps(d.metadata["Name"])+"\nversion = "+json.dumps(d.version)+"\ndependencies = "+json.dumps(d.requires or [])+"\n")' && /generator/bin/cyclonedx-py environment /project/bin/python --pyproject /reference/root.pyproject.toml --spec-version 1.6 --output-file /reference/sbom.json
FROM scratch AS export
COPY --from=build /reference/ /
