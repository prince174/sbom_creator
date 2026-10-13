FROM python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258 AS build
RUN python -m pip install flit_core==3.12.0 && python -m venv /generator && /generator/bin/pip install cyclonedx-bom==7.5.0
ARG PROJECT
WORKDIR /src
COPY src/ /src/
RUN mkdir /reference /wheels && python -m pip wheel --no-deps --no-build-isolation --wheel-dir /wheels /src && python -m pip download --only-binary=:all: --dest /wheels /wheels/*.whl && python -m venv /project && /project/bin/pip install --no-index --find-links /wheels ${PROJECT} && /project/bin/pip inspect > /reference/resolved.json && /generator/bin/cyclonedx-py environment /project/bin/python --pyproject /src/pyproject.toml --spec-version 1.6 --output-file /reference/sbom.json && /project/bin/python -VV > /reference/python-version.txt && /generator/bin/pip freeze > /reference/generator-freeze.txt && python -m pip freeze > /reference/builder-freeze.txt && sha256sum /wheels/* > /reference/wheels.sha256 && /generator/bin/python -c "import json; from packaging.markers import default_environment; e=default_environment(); e['extra']=''; print(json.dumps(e))" > /reference/marker-environment.json

FROM python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258 AS runtime
COPY --from=build /project /project
USER 65532
CMD ["/project/bin/python", "-c", "import sys; print(sys.version)"]
