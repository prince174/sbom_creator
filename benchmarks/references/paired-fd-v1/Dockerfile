FROM rust:1.85.1-bookworm@sha256:e51d0265072d2d9d5d320f6a44dde6b9ef13653b035098febd68cce8fa7c0bc4 AS build
ENV RUSTUP_TOOLCHAIN=1.85.1 CARGO_BUILD_JOBS=2
RUN cargo install cargo-auditable --version 0.6.6 --locked
RUN cargo install cargo-cyclonedx --version 0.5.9 --locked
WORKDIR /src
COPY src/ /src/
ENV CARGO_PROFILE_DEV_DEBUG=0
RUN --mount=type=cache,target=/usr/local/cargo/registry cargo auditable build --locked --bins --target x86_64-unknown-linux-gnu && mkdir /out && find target/x86_64-unknown-linux-gnu/debug -maxdepth 1 -type f -executable -exec cp {} /out/ \; && test -n "$(ls -A /out)"
RUN --mount=type=cache,target=/usr/local/cargo/registry cargo cyclonedx --format json --spec-version 1.5 --override-filename sbom && mkdir /reference && find . -name sbom.json -not -path './target/*' -exec cp --parents {} /reference/ \; && cargo metadata --locked --format-version 1 > /reference/resolved.json
RUN cargo metadata --locked --format-version 1 --filter-platform x86_64-unknown-linux-gnu > /reference/filtered.json && cargo cyclonedx --help > /reference/generator-help.txt && rustc -Vv > /reference/rustc.txt && cargo -V > /reference/cargo.txt && cargo cyclonedx --version > /reference/generator-version.txt
FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587 AS runtime
COPY --from=build /out/ /app/
USER 65532:65532
CMD ["/app/fd", "--help"]
