FROM golang:1.26-bookworm AS generator
RUN GOBIN=/tools go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.12.0
FROM golang:1.24-bookworm AS build
COPY --from=generator /tools/cyclonedx-gomod /usr/local/bin/
WORKDIR /src
COPY src/ /src/
ENV CGO_ENABLED=0
ENV GOMAXPROCS=2
RUN --mount=type=cache,target=/root/.cache/go-build --mount=type=cache,target=/go/pkg/mod git -c core.autocrlf=false reset --hard HEAD && if [ -f go.mod ]; then go build -buildvcs=true -o /out/app .; else GO111MODULE=off go build -o /out/app .; fi && go version -m /out/app > /out/go-build-info.txt
RUN --mount=type=cache,target=/root/.cache/go-build --mount=type=cache,target=/go/pkg/mod mkdir /reference && cyclonedx-gomod app -json -output /reference/sbom.json -main . . && cp /out/go-build-info.txt /reference/ && go list -deps -json . > /reference/resolved.json
FROM scratch AS export
COPY --from=build /reference/ /
