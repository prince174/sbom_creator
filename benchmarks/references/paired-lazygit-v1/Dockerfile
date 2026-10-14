FROM golang:1.24-bookworm@sha256:1a6d4452c65dea36aac2e2d606b01b4a029ec90cc1ae53890540ce6173ea77ac AS build
ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOMAXPROCS=2
WORKDIR /src
COPY src/ /src/
COPY cyclonedx-gomod /usr/local/bin/cyclonedx-gomod
RUN chmod 755 /usr/local/bin/cyclonedx-gomod
RUN git -c core.autocrlf=false reset --hard HEAD && test -z "$(git status --porcelain)"
RUN --mount=type=cache,target=/root/.cache/go-build --mount=type=cache,target=/go/pkg/mod mkdir /application /reference && go build -buildvcs=true -o /application/lazygit . && cyclonedx-gomod app -json -output /reference/sbom.json -main . . && go list -deps -json . > /reference/packages.json && go list -m -json > /reference/modules.json && go version -m /application/lazygit > /reference/build-info.txt && go version > /reference/go-version.txt && sha256sum /application/lazygit > /reference/binary.sha256
FROM scratch AS runtime
COPY --from=build /application /application
USER 65532
CMD ["/application/lazygit", "--help"]

