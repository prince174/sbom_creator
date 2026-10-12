FROM rust:1.85.1-bookworm AS build
ENV RUSTUP_TOOLCHAIN=1.85.1 CARGO_BUILD_JOBS=2
RUN cargo install cargo-auditable --version 0.6.6 --locked
RUN cargo install cargo-cyclonedx --version 0.5.9 --locked
WORKDIR /src
COPY src/ /src/
ENV CARGO_PROFILE_DEV_DEBUG=0
RUN --mount=type=cache,target=/usr/local/cargo/registry cargo auditable build --locked --bins && mkdir /out && find target/debug -maxdepth 1 -type f -executable -exec cp {} /out/ \; && test -n "$(ls -A /out)"
RUN --mount=type=cache,target=/usr/local/cargo/registry cargo cyclonedx --format json --spec-version 1.5 --override-filename sbom && mkdir /reference && find . -name sbom.json -not -path './target/*' -exec cp --parents {} /reference/ \; && cargo metadata --locked --format-version 1 > /reference/resolved.json
FROM scratch AS export
COPY --from=build /reference/ /
