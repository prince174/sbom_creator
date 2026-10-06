FROM anchore/syft:v1.51.1@sha256:95fe0835e5bebc6f8b1f8acef68d47d63d594ef4c0f25c097ff853b23cbac74c AS syft
FROM python:3.12-slim-bookworm@sha256:782412e85d0f0984994c290652577d4018aff08145c85b262bb63dc0c7522254
RUN apt-get update && apt-get install --yes --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=syft /syft /usr/local/bin/syft
WORKDIR /app
COPY pyproject.toml .
COPY src ./src
RUN pip install --no-cache-dir .
RUN mkdir -p /workspace /home/sbom && chown -R 10001:10001 /workspace /home/sbom
USER 10001:10001
ENV HOME=/home/sbom PYTHONDONTWRITEBYTECODE=1 SBOM_WORKSPACE=/workspace
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2)"
CMD ["sbom-creator-service"]
